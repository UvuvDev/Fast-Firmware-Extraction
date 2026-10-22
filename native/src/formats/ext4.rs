//! Read-only ext4, ported from formats/ext4.py's verified on-disk layouts.
//! Standard and padless superblocks, 32/64-byte group descriptors, extent
//! trees and classic direct through triple-indirect pointers. Unwritten
//! extents and holes read as zeroes. No journal replay or checksum validation.
use crate::archive::{ArchiveReader, LARGE_CONTAINER_MAX_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use std::collections::HashSet;

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "ext4",
    name: "Ext4",
    description: "ext4 filesystem",
    signatures: &[
        Signature::new(1080, b"\x53\xef"),
        Signature::new(56, b"\x53\xef"),
    ],
    probe: Some(probe),
    open,
    max_input_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
};
fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        get(data, offset, 2)?.try_into().unwrap(),
    ))
}
#[derive(Clone)]
struct Inode {
    mode: u16,
    size: usize,
    flags: u32,
    blocks: [u8; 60],
}
#[derive(Debug)]
struct Extent {
    logical: u64,
    physical: u64,
    count: u64,
    unwritten: bool,
}
struct Ext4 {
    data: Vec<u8>,
    bs: usize,
    pad: usize,
    inodes_per_group: u32,
    inode_size: usize,
    desc_size: usize,
    gdt: u64,
    groups: u64,
    names: Vec<String>,
    files: Vec<Inode>,
}
impl Ext4 {
    fn offset(&self, block: u64) -> Result<usize> {
        let byte = block
            .checked_mul(self.bs as u64)
            .and_then(|n| n.checked_sub(self.pad as u64))
            .ok_or("ext4 block offset overflow")?;
        usize::try_from(byte).map_err(|_| "ext4 address exceeds host range".into())
    }
    fn block(&self, block: u64) -> Result<&[u8]> {
        get(&self.data, self.offset(block)?, self.bs)
    }
    fn inode(&self, ino: u32) -> Result<Inode> {
        let index = ino.checked_sub(1).ok_or("zero ext4 inode number")?;
        let group = index / self.inodes_per_group;
        if group as u64 >= self.groups {
            return Err("ext4 inode group out of bounds".into());
        }
        let offset = self
            .offset(self.gdt)?
            .checked_add(group as usize * self.desc_size)
            .ok_or("ext4 group offset overflow")?;
        let desc = get(&self.data, offset, self.desc_size)?;
        let table = le32(desc, 8)? as u64
            | if self.desc_size >= 64 {
                (le32(desc, 40)? as u64) << 32
            } else {
                0
            };
        let offset = self
            .offset(table)?
            .checked_add((index % self.inodes_per_group) as usize * self.inode_size)
            .ok_or("ext4 inode offset overflow")?;
        let raw = get(&self.data, offset, self.inode_size)?;
        let mode = u16le(raw, 0)?;
        let size = le32(raw, 4)? as u64
            | if mode & 0xf000 == 0x8000 {
                (le32(raw, 108)? as u64) << 32
            } else {
                0
            };
        if size > LARGE_CONTAINER_MAX_SIZE as u64 {
            return Err("ext4 inode exceeds file size limit".into());
        }
        Ok(Inode {
            mode,
            size: size as usize,
            flags: le32(raw, 32)?,
            blocks: get(raw, 40, 60)?.try_into().unwrap(),
        })
    }
    fn extent_tree(
        &self,
        bytes: &[u8],
        expected: Option<u16>,
        output: &mut Vec<Extent>,
        budget: &mut usize,
    ) -> Result<()> {
        *budget = budget
            .checked_sub(1)
            .ok_or("ext4 extent metadata limit exceeded")?;
        let count = u16le(bytes, 2)? as usize;
        let depth = u16le(bytes, 6)?;
        if u16le(bytes, 0)? != 0xf30a
            || depth > 5
            || expected.is_some_and(|d| d != depth)
            || count > u16le(bytes, 4)? as usize
        {
            return Err("invalid ext4 extent tree header/depth".into());
        }
        for entry in get(bytes, 12, count * 12)?.chunks_exact(12) {
            if depth == 0 {
                let raw_length = u16le(entry, 4)?;
                let count = if raw_length > 32768 {
                    raw_length - 32768
                } else {
                    raw_length
                } as u64;
                if count == 0 {
                    return Err("zero length ext4 extent".into());
                }
                if output.len() >= MAX_MEMBERS {
                    return Err("too many ext4 extents".into());
                }
                output.push(Extent {
                    logical: le32(entry, 0)? as u64,
                    physical: le32(entry, 8)? as u64 | ((u16le(entry, 6)? as u64) << 32),
                    count,
                    unwritten: raw_length > 32768,
                });
            } else {
                let child = le32(entry, 4)? as u64 | ((u16le(entry, 8)? as u64) << 32);
                self.extent_tree(self.block(child)?, Some(depth - 1), output, budget)?;
            }
        }
        Ok(())
    }
    fn indirect(
        &self,
        physical: u64,
        logical: u64,
        depth: u32,
        limit: u64,
        output: &mut Vec<Extent>,
        budget: &mut usize,
    ) -> Result<()> {
        if logical >= limit || physical == 0 {
            return Ok(());
        }
        *budget = budget
            .checked_sub(1)
            .ok_or("ext4 indirect metadata limit exceeded")?;
        if depth == 0 {
            if output.len() >= MAX_MEMBERS {
                return Err("too many ext4 block mappings".into());
            }
            output.push(Extent {
                logical,
                physical,
                count: 1,
                unwritten: false,
            });
        } else {
            let stride = (self.bs as u64 / 4).pow(depth - 1);
            for (i, entry) in self.block(physical)?.chunks_exact(4).enumerate() {
                let child_logical = logical + i as u64 * stride;
                if child_logical >= limit {
                    break;
                }
                self.indirect(
                    u32::from_le_bytes(entry.try_into().unwrap()) as u64,
                    child_logical,
                    depth - 1,
                    limit,
                    output,
                    budget,
                )?;
            }
        }
        Ok(())
    }
    fn extents(&self, inode: &Inode) -> Result<Vec<Extent>> {
        let mut result = Vec::new();
        let mut budget = MAX_MEMBERS;
        if inode.flags & 0x80000 != 0 {
            self.extent_tree(&inode.blocks, None, &mut result, &mut budget)?;
        } else {
            let limit = inode.size.div_ceil(self.bs) as u64;
            for i in 0..12 {
                self.indirect(
                    le32(&inode.blocks, i * 4)? as u64,
                    i as u64,
                    0,
                    limit,
                    &mut result,
                    &mut budget,
                )?;
            }
            let mut logical = 12;
            for depth in 1..=3 {
                self.indirect(
                    le32(&inode.blocks, (11 + depth as usize) * 4)? as u64,
                    logical,
                    depth,
                    limit,
                    &mut result,
                    &mut budget,
                )?;
                logical += (self.bs as u64 / 4).pow(depth);
            }
        }
        result.sort_by_key(|e| e.logical);
        let mut end = 0;
        for extent in &result {
            if extent.logical < end {
                return Err("overlapping ext4 extents".into());
            }
            end = extent.logical + extent.count;
        }
        Ok(result)
    }
    fn content(&self, inode: &Inode) -> Result<Vec<u8>> {
        if inode.flags & 0x10000000 != 0 {
            if inode.mode & 0xf000 == 0x4000 || inode.size > 60 {
                return Err("ext4 inline directories/xattr overflow unsupported".into());
            }
            return Ok(inode.blocks[..inode.size].to_vec());
        }
        // Parse metadata before allocating a file-sized buffer.
        let extents = self.extents(inode)?;
        let mut output = vec![0; inode.size];
        for extent in extents {
            let start = extent.logical * self.bs as u64;
            if start >= inode.size as u64 || extent.unwritten {
                continue;
            }
            let length = (extent.count * self.bs as u64).min(inode.size as u64 - start) as usize;
            let source = get(&self.data, self.offset(extent.physical)?, length)?;
            output[start as usize..start as usize + length].copy_from_slice(source);
        }
        Ok(output)
    }
    fn directory(&self, inode: &Inode) -> Result<Vec<(String, u32)>> {
        let bytes = self.content(inode)?;
        let mut entries = Vec::new();
        for block in bytes.chunks(self.bs) {
            let mut pos = 0;
            while pos < block.len() {
                let header = get(block, pos, 8)?;
                let ino = le32(header, 0)?;
                let raw_length = u16le(header, 4)?;
                let length = if self.bs == 65536 && (raw_length == 0 || raw_length == u16::MAX) {
                    65536
                } else {
                    raw_length as usize
                };
                let name_length = header[6] as usize;
                if length < 8 || !length.is_multiple_of(4) || name_length > length - 8 {
                    return Err("invalid ext4 directory record".into());
                }
                let record = get(block, pos, length)?;
                if ino != 0 && name_length != 0 {
                    let name = String::from_utf8_lossy(&record[8..8 + name_length]).into_owned();
                    if name != "." && name != ".." {
                        validate_name(&name)?;
                        if name.contains('/') {
                            return Err("ext4 directory name contains slash".into());
                        }
                        if entries.len() >= MAX_MEMBERS {
                            return Err("too many ext4 directory entries".into());
                        }
                        entries.push((name, ino));
                    }
                }
                pos += length;
            }
        }
        Ok(entries)
    }
    fn index(&mut self) -> Result<()> {
        let mut pending = vec![(String::new(), 2, 0)];
        let mut visited = HashSet::new();
        let mut count = 0;
        while let Some((path, ino, depth)) = pending.pop() {
            count += 1;
            if count > MAX_MEMBERS || depth > 256 {
                return Err("ext4 traversal limit exceeded".into());
            }
            let inode = self.inode(ino)?;
            match inode.mode & 0xf000 {
                0x4000 => {
                    if !visited.insert(ino) {
                        return Err("ext4 directory cycle or repeated directory".into());
                    }
                    for (name, child) in self.directory(&inode)?.into_iter().rev() {
                        let name = if path.is_empty() {
                            name
                        } else {
                            format!("{path}/{name}")
                        };
                        validate_name(&name)?;
                        if pending.len() + count >= MAX_MEMBERS {
                            return Err("too many ext4 directory entries".into());
                        }
                        pending.push((name, child, depth + 1));
                    }
                }
                0x8000 => {
                    self.names.push(path);
                    self.files.push(inode);
                }
                _ => {} // Skip symlinks and special nodes, using the inode's authoritative mode.
            }
        }
        Ok(())
    }
}
impl ArchiveReader for Ext4 {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        self.content(
            self.files
                .get(index)
                .ok_or("ext4 file index out of range")?,
        )
    }
}
// The two-byte magic alone is too broad for recursive firmware detection.
// Keep probing cheap and bounded while checking basic superblock geometry.
fn superblock(data: &[u8]) -> Option<usize> {
    [1024, 0].into_iter().find(|&base| {
        let Ok(sb) = get(data, base, 0x160) else {
            return false;
        };
        u16le(sb, 56).ok() == Some(0xef53)
            && le32(sb, 24).is_ok_and(|n| n <= 6)
            && le32(sb, 32).is_ok_and(|n| n != 0)
            && le32(sb, 40).is_ok_and(|n| n != 0)
    })
}
fn probe(data: &[u8]) -> bool {
    superblock(data).is_some()
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let base = superblock(&data).ok_or("no ext4 superblock")?;
    let sb = get(&data, base, 0x160)?;
    let log = le32(sb, 24)?;
    if log > 6 {
        return Err("unsupported ext4 block size".into());
    }
    let bs = 1024usize << log;
    let first = le32(sb, 20)? as u64;
    let bpg = le32(sb, 32)? as u64;
    let ipg = le32(sb, 40)?;
    if bpg == 0 || ipg == 0 {
        return Err("zero ext4 group geometry".into());
    }
    let dynamic = le32(sb, 76)? >= 1;
    let incompat = if dynamic { le32(sb, 96)? } else { 0 };
    // These features change addressing, contents or directory names. Reject them
    // explicitly rather than presenting bytes with the ordinary ext4 layout.
    if incompat & (0x1 | 0x4 | 0x8 | 0x10 | 0x10000 | 0x20000) != 0 {
        return Err(
            "ext4 compression/recovery/journal-device/meta_bg/encryption/casefold unsupported"
                .into(),
        );
    }
    let wide = incompat & 0x80 != 0;
    let total = le32(sb, 4)? as u64
        | if wide {
            (le32(sb, 0x150)? as u64) << 32
        } else {
            0
        };
    let blocks = total
        .checked_sub(first)
        .filter(|&n| n > 0)
        .ok_or("invalid ext4 block count")?;
    let inode_size = if dynamic {
        u16le(sb, 88)? as usize
    } else {
        128
    };
    let inode_size = if inode_size == 0 { 128 } else { inode_size };
    let desc_size = if wide { u16le(sb, 254)? as usize } else { 32 };
    if inode_size < 128
        || inode_size > bs
        || !inode_size.is_power_of_two()
        || desc_size < if wide { 64 } else { 32 }
        || desc_size > bs
        || !desc_size.is_multiple_of(8)
    {
        return Err("invalid ext4 inode/descriptor size".into());
    }
    let mut fs = Ext4 {
        data,
        bs,
        pad: 1024 - base,
        inodes_per_group: ipg,
        inode_size,
        desc_size,
        gdt: first + 1,
        groups: blocks.div_ceil(bpg),
        names: Vec::new(),
        files: Vec::new(),
    };
    if fs.inode(2)?.mode & 0xf000 != 0x4000 {
        return Err("ext4 root is not a directory".into());
    }
    fs.index()?;
    Ok(Box::new(fs))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/ext4/sample.img").to_vec()
    }
    fn reader() -> Ext4 {
        Ext4 {
            data: vec![0; 8 * 1024],
            bs: 1024,
            pad: 0,
            inodes_per_group: 8,
            inode_size: 128,
            desc_size: 32,
            gdt: 2,
            groups: 1,
            names: vec![],
            files: vec![],
        }
    }
    fn inode(size: usize) -> Inode {
        Inode {
            mode: 0x8000,
            size,
            flags: 0,
            blocks: [0; 60],
        }
    }
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn sparse_and_all_indirect_levels() {
        let mut fs = reader();
        fs.data[7 * 1024..].fill(42);
        for depth in 1u32..=3 {
            let ppb = 256u64;
            let logical = 12 + (1..depth).map(|d| ppb.pow(d)).sum::<u64>();
            let mut node = inode((logical as usize + 1) * 1024);
            put32(&mut node.blocks, (11 + depth as usize) * 4, 3);
            for level in 0..depth {
                put32(
                    &mut fs.data,
                    (3 + level as usize) * 1024,
                    if level + 1 == depth { 7 } else { 4 + level },
                );
            }
            let bytes = fs.content(&node).unwrap();
            assert!(bytes[..logical as usize * 1024].iter().all(|&b| b == 0));
            assert_eq!(&bytes[logical as usize * 1024..], &[42; 1024]);
        }
    }
    #[test]
    fn unwritten_extents_zero_instead_of_exposing_disk_bytes() {
        let mut fs = reader();
        fs.data[7 * 1024..].fill(42);
        let mut node = inode(1024);
        node.flags = 0x80000;
        node.blocks[..8].copy_from_slice(&[0x0a, 0xf3, 1, 0, 4, 0, 0, 0]);
        node.blocks[16..18].copy_from_slice(&0x8001u16.to_le_bytes());
        put32(&mut node.blocks, 20, 7);
        assert_eq!(fs.content(&node).unwrap(), vec![0; 1024]);
        node.blocks[16..18].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(fs.content(&node).unwrap(), vec![42; 1024]);
    }
    #[test]
    fn rejects_extent_cycles_and_overlap() {
        let mut fs = reader();
        let mut node = inode(1024);
        node.flags = 0x80000;
        node.blocks[..8].copy_from_slice(&[0x0a, 0xf3, 1, 0, 4, 0, 1, 0]);
        put32(&mut node.blocks, 16, 3);
        fs.data[3072..3132].copy_from_slice(&node.blocks);
        assert!(fs.content(&node).is_err());
        node.blocks[..8].copy_from_slice(&[0x0a, 0xf3, 2, 0, 4, 0, 0, 0]);
        node.blocks[16..18].copy_from_slice(&1u16.to_le_bytes());
        node.blocks[28..30].copy_from_slice(&1u16.to_le_bytes());
        assert!(fs.content(&node).is_err());
    }
    #[test]
    fn inline_bounds_and_oversized_inode() {
        let fs = reader();
        let mut node = inode(4);
        node.flags = 0x10000000;
        node.blocks[..4].copy_from_slice(b"data");
        assert_eq!(fs.content(&node).unwrap(), b"data");
        node.size = 61;
        assert!(fs.content(&node).is_err());
        let mut data = sample();
        put32(&mut data, 3200 + 4, u32::MAX);
        assert!(open(data).is_err());
    }
    #[test]
    fn rejects_directory_corruption_and_unsupported_features() {
        let mut data = sample();
        data[4096 + 4..4096 + 6].copy_from_slice(&4u16.to_le_bytes());
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 1024 + 96, 0x10000);
        assert!(open(data).is_err());
    }
    #[test]
    fn detection_requires_geometry_beyond_short_magic() {
        let mut data = vec![0; 2048];
        data[1080..1082].copy_from_slice(&[0x53, 0xef]);
        assert!(!probe(&data));
        assert!(probe(&sample()));
        assert!(probe(&sample()[1024..]));
    }
    #[test]
    fn directory_64k_record_encoding() {
        let mut fs = reader();
        fs.bs = 65536;
        fs.data = vec![0; 131072];
        let mut node = inode(65536);
        node.mode = 0x4000;
        put32(&mut node.blocks, 0, 1);
        put32(&mut fs.data, 65536, 3);
        fs.data[65540..65542].copy_from_slice(&u16::MAX.to_le_bytes());
        fs.data[65542] = 1;
        fs.data[65544] = b'a';
        assert_eq!(fs.directory(&node).unwrap(), vec![("a".into(), 3)]);
        fs.data[65540..65542].fill(0);
        assert_eq!(fs.directory(&node).unwrap(), vec![("a".into(), 3)]);
    }
    #[test]
    fn partial_final_group_and_64bit_descriptor_stride() {
        let mut fs = reader();
        fs.groups = 2;
        put32(&mut fs.data, 2048 + 32 + 8, 4);
        fs.data[4096..4098].copy_from_slice(&0x8000u16.to_le_bytes());
        assert_eq!(fs.inode(9).unwrap().mode, 0x8000);
        fs.desc_size = 64;
        put32(&mut fs.data, 2048 + 64 + 8, 4);
        assert_eq!(fs.inode(9).unwrap().mode, 0x8000);
    }
}
