//! Uncompressed EROFS, ported from formats/erofs.py. Its layout/mapping reference
//! is AOSP erofs-utils (GPL-2.0+ OR MIT), under the MIT option. Supports compact
//! and extended inodes, flat/inline data, single-device chunks and sparse data.
//! Compressed inodes, metabox and global 48BIT addressing are unsupported.
use crate::archive::{ArchiveReader, LARGE_CONTAINER_MAX_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use std::collections::HashSet;

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "erofs",
    name: "Erofs",
    description: "EROFS filesystem (uncompressed)",
    signatures: &[Signature::new(1024, b"\xe2\xe1\xf5\xe0")],
    probe: None,
    open,
    max_input_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
};
fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        get(data, offset, 2)?.try_into().unwrap(),
    ))
}
fn u64le(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        get(data, offset, 8)?.try_into().unwrap(),
    ))
}
fn address(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| "EROFS address exceeds host range".into())
}
struct Inode {
    mode: u16,
    size: usize,
    layout: u16,
    block: u64,
    tail: usize,
    chunk_format: u16,
}
struct Segment {
    logical: usize,
    physical: usize,
    length: usize,
}
struct Erofs {
    data: Vec<u8>,
    bs: usize,
    meta: usize,
    root: u64,
    names: Vec<String>,
    files: Vec<Inode>,
}
impl Erofs {
    fn inode(&self, nid: u64) -> Result<Inode> {
        let pos = nid
            .checked_mul(32)
            .and_then(|n| n.checked_add(self.meta as u64))
            .ok_or("EROFS inode address overflow")?;
        let pos = address(pos)?;
        let head = get(&self.data, pos, 32)?;
        let format = u16le(head, 0)?;
        let extended = format & 1 != 0;
        let inode_size = if extended { 64 } else { 32 };
        // A 64-byte inode may span two metadata blocks; read consecutive bytes.
        let raw = get(&self.data, pos, inode_size)?;
        let mode = u16le(raw, 4)?;
        let size = if extended {
            u64le(raw, 8)?
        } else {
            le32(raw, 8)? as u64
        };
        if size > LARGE_CONTAINER_MAX_SIZE as u64 {
            return Err("EROFS inode exceeds file size limit".into());
        }
        let layout = (format >> 1) & 7;
        if mode & 0xf000 == 0x8000 || mode & 0xf000 == 0x4000 {
            match layout {
                0 | 2 | 4 => {}
                1 | 3 => return Err("compressed EROFS inodes unsupported".into()),
                _ => return Err("reserved EROFS data layout".into()),
            }
        }
        let high = if extended || (mode & 0xf000 != 0x4000 && format & 16 != 0) {
            u16le(raw, 6)? as u64
        } else {
            0
        };
        let block = le32(raw, 16)? as u64 | (high << 32);
        let count = u16le(raw, 2)? as usize;
        let xattrs = if count == 0 { 0 } else { 12 + 4 * (count - 1) };
        let tail = pos
            .checked_add(inode_size + xattrs)
            .ok_or("EROFS inline address overflow")?;
        Ok(Inode {
            mode,
            size: size as usize,
            layout,
            block,
            tail,
            chunk_format: u16le(raw, 16)?,
        })
    }
    fn physical(&self, block: u64) -> Result<usize> {
        address(
            block
                .checked_mul(self.bs as u64)
                .ok_or("EROFS block address overflow")?,
        )
    }
    fn segments(&self, inode: &Inode) -> Result<Vec<Segment>> {
        if inode.size == 0 {
            return Ok(Vec::new());
        }
        let mut segments = Vec::new();
        let mut add = |logical, physical, length| -> Result<()> {
            get(&self.data, physical, length)?;
            segments.push(Segment {
                logical,
                physical,
                length,
            });
            Ok(())
        };
        match inode.layout {
            0 | 2 => {
                let inline = inode.layout == 2;
                if !inline && inode.block == u32::MAX as u64 {
                    return Ok(segments);
                }
                let boundary = (inode.size.div_ceil(self.bs) - usize::from(inline)) * self.bs;
                if boundary > 0 {
                    add(0, self.physical(inode.block)?, boundary.min(inode.size))?;
                }
                if inode.size > boundary {
                    let length = inode.size - boundary;
                    if inode.tail % self.bs + length > self.bs {
                        return Err("EROFS inline tail crosses metadata block".into());
                    }
                    add(boundary, inode.tail, length)?;
                }
            }
            4 => {
                let format = inode.chunk_format;
                if format & !0x7f != 0 {
                    return Err("reserved EROFS chunk format".into());
                }
                let indexed = format & 0x20 != 0;
                let unit = if indexed { 8 } else { 4 };
                let chunk = (self.bs as u64)
                    .checked_shl((format & 31) as u32)
                    .ok_or("EROFS chunk size overflow")?;
                let count = (inode.size as u64).div_ceil(chunk);
                if count > MAX_MEMBERS as u64 {
                    return Err("too many EROFS chunks".into());
                }
                let base = inode
                    .tail
                    .checked_add(unit - 1)
                    .ok_or("EROFS chunk table overflow")?
                    & !(unit - 1);
                let table = get(&self.data, base, count as usize * unit)?;
                for (i, entry) in table.chunks_exact(unit).enumerate() {
                    let mut block = if indexed {
                        if u16le(entry, 2)? != 0 {
                            return Err("multi-device EROFS chunks unsupported".into());
                        }
                        le32(entry, 4)? as u64 | ((u16le(entry, 0)? as u64) << 32)
                    } else {
                        le32(entry, 0)? as u64
                    };
                    if format & 0x40 == 0 {
                        block &= u32::MAX as u64;
                    }
                    if block == u32::MAX as u64 {
                        continue;
                    }
                    let logical = address(i as u64 * chunk)?;
                    let length = chunk.min((inode.size - logical) as u64) as usize;
                    add(logical, self.physical(block)?, length)?;
                }
            }
            _ => return Err("unsupported EROFS layout".into()),
        }
        Ok(segments)
    }
    fn content(&self, inode: &Inode) -> Result<Vec<u8>> {
        let segments = self.segments(inode)?;
        let mut output = vec![0; inode.size];
        for seg in segments {
            output[seg.logical..seg.logical + seg.length]
                .copy_from_slice(&self.data[seg.physical..seg.physical + seg.length]);
        }
        Ok(output)
    }
    fn directory(&self, inode: &Inode) -> Result<Vec<(String, u64)>> {
        let bytes = self.content(inode)?;
        let mut entries = Vec::new();
        for block in bytes.chunks(self.bs) {
            let first = u16le(block, 8)? as usize;
            if first < 12 || first > block.len() || !first.is_multiple_of(12) {
                return Err("invalid EROFS directory name offset".into());
            }
            let count = first / 12;
            for i in 0..count {
                let start = u16le(block, i * 12 + 8)? as usize;
                let end = if i + 1 < count {
                    u16le(block, (i + 1) * 12 + 8)? as usize
                } else {
                    block.len()
                };
                if start < first || start >= end || end > block.len() {
                    return Err("invalid EROFS directory name range".into());
                }
                let name = &block[start..end];
                let name = if i + 1 == count {
                    name.split(|&b| b == 0).next().unwrap()
                } else {
                    name
                };
                let name = String::from_utf8_lossy(name).into_owned();
                if name == "." || name == ".." {
                    continue;
                }
                validate_name(&name)?;
                if name.contains('/') {
                    return Err("EROFS directory name contains slash".into());
                }
                if entries.len() >= MAX_MEMBERS {
                    return Err("too many EROFS directory entries".into());
                }
                entries.push((name, u64le(block, i * 12)?));
            }
        }
        Ok(entries)
    }
    fn index(&mut self) -> Result<()> {
        let mut pending = vec![(String::new(), self.root, 0)];
        let mut visited = HashSet::new();
        let mut count = 0;
        while let Some((path, nid, depth)) = pending.pop() {
            count += 1;
            if count > MAX_MEMBERS || depth > 256 {
                return Err("EROFS traversal limit exceeded".into());
            }
            let inode = self.inode(nid)?;
            match inode.mode & 0xf000 {
                0x4000 => {
                    if !visited.insert(nid) {
                        return Err("EROFS directory cycle or repeated directory".into());
                    }
                    for (name, child) in self.directory(&inode)?.into_iter().rev() {
                        let name = if path.is_empty() {
                            name
                        } else {
                            format!("{path}/{name}")
                        };
                        validate_name(&name)?;
                        if pending.len() + count >= MAX_MEMBERS {
                            return Err("too many EROFS directory entries".into());
                        }
                        pending.push((name, child, depth + 1));
                    }
                }
                0x8000 => {
                    self.names.push(path);
                    self.files.push(inode);
                }
                _ => {} // inode mode takes precedence over untrusted directory type hints.
            }
        }
        Ok(())
    }
}
impl ArchiveReader for Erofs {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        self.content(
            self.files
                .get(index)
                .ok_or("EROFS file index out of range")?,
        )
    }
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let sb = get(&data, 1024, 96)?;
    if le32(sb, 0)? != 0xe0f5e1e2 {
        return Err("bad EROFS superblock magic".into());
    }
    let bits = sb[12];
    if !(9..=20).contains(&bits) {
        return Err("unsupported EROFS block size".into());
    }
    if le32(sb, 80)? & 0x180 != 0 {
        return Err("EROFS metabox/global 48BIT addressing unsupported".into());
    }
    let bs = 1usize << bits;
    let meta = address(le32(sb, 40)? as u64 * bs as u64)?;
    let root = u16le(sb, 14)? as u64;
    let mut fs = Erofs {
        data,
        bs,
        meta,
        root,
        names: vec![],
        files: vec![],
    };
    if fs.inode(root)?.mode & 0xf000 != 0x4000 {
        return Err("EROFS root is not a directory".into());
    }
    fs.index()?;
    Ok(Box::new(fs))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/erofs_flat_plain/sample.img").to_vec()
    }
    fn fs(data: Vec<u8>) -> Erofs {
        Erofs {
            data,
            bs: 512,
            meta: 1536,
            root: 0,
            names: vec![],
            files: vec![],
        }
    }
    fn put16(data: &mut [u8], off: usize, value: u16) {
        data[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn sparse_plain_and_chunk_holes_are_zero_filled() {
        let mut reader = fs(sample());
        put32(&mut reader.data, 1568 + 16, u32::MAX);
        assert_eq!(
            reader.content(&reader.inode(1).unwrap()).unwrap(),
            vec![0; 700]
        );
        let mut reader =
            fs(include_bytes!("../../../tests/fixtures/erofs_chunk_based/sample.img").to_vec());
        put32(&mut reader.data, 1604, u32::MAX);
        let bytes = reader.content(&reader.inode(1).unwrap()).unwrap();
        assert!(bytes[512..1024].iter().all(|&b| b == 0));
    }
    #[test]
    fn indexed_chunks_and_device_rejection() {
        let mut reader =
            fs(include_bytes!("../../../tests/fixtures/erofs_chunk_based/sample.img").to_vec());
        put16(&mut reader.data, 1584, 0x20);
        for (i, block) in [10, 20, 15].iter().enumerate() {
            put16(&mut reader.data, 1600 + i * 8, 0);
            put16(&mut reader.data, 1602 + i * 8, 0);
            put32(&mut reader.data, 1604 + i * 8, *block);
        }
        let node = reader.inode(1).unwrap();
        assert_eq!(reader.content(&node).unwrap().len(), 1124);
        put16(&mut reader.data, 1602, 1);
        assert!(reader.content(&node).is_err());
    }
    #[test]
    fn extended_inode_crosses_metadata_block_boundary() {
        let mut reader = fs(sample());
        let pos = 1536 + 15 * 32;
        put16(&mut reader.data, pos, 1);
        put16(&mut reader.data, pos + 4, 0x8000);
        reader.data[pos + 8..pos + 16].copy_from_slice(&700u64.to_le_bytes());
        put32(&mut reader.data, pos + 16, 6);
        let node = reader.inode(15).unwrap();
        assert_eq!(node.tail, 2080);
        assert_eq!(reader.content(&node).unwrap(), reader.data[3072..3772]);
    }
    #[test]
    fn rejects_directory_ranges_and_cycles() {
        let mut data = sample();
        put16(&mut data, 2560 + 8, 13);
        assert!(open(data).is_err());
        let mut data = sample();
        put16(&mut data, 2560 + 20, 13);
        assert!(open(data).is_err());
        let mut data = sample();
        data[2560 + 24..2560 + 32].fill(0);
        assert!(open(data).is_err());
    }
    #[test]
    fn rejects_unsupported_layouts_and_oversized_inodes() {
        let mut data = sample();
        put16(&mut data, 1568, 2);
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 1104, 0x100);
        assert!(open(data).is_err());
        // A compact inode's 32-bit size field tops out under 4 GiB, which
        // the raised LARGE_CONTAINER_MAX_SIZE limit now accepts; exceeding
        // that limit needs an extended inode's 64-bit size field instead.
        let mut data = sample();
        put16(&mut data, 1568, 1); // extended inode
        data[1568 + 8..1568 + 16].copy_from_slice(&(20_u64 * 1024 * 1024 * 1024).to_le_bytes());
        assert!(open(data).is_err());
    }
    #[test]
    fn zero_length_inline_and_tail_bounds() {
        let mut reader = fs(sample());
        put16(&mut reader.data, 1568, 4);
        put32(&mut reader.data, 1576, 0);
        assert!(
            reader
                .content(&reader.inode(1).unwrap())
                .unwrap()
                .is_empty()
        );
        put32(&mut reader.data, 1576, 500);
        assert!(reader.content(&reader.inode(1).unwrap()).is_err());
    }
}
