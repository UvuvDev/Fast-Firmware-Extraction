//! Static-NAT F2FS extraction, ported from formats/f2fs.py's on-disk facts.
//! Facts rechecked against Linux v6.12 f2fs_fs.h/f2fs.h/dir.c (GPL; no kernel
//! implementation code copied): directory bitmaps are LSB-first, NAT MSB-first.
//! 4 KiB blocks, inline data/dentries, extra attributes and all node-pointer
//! tiers. No inline xattrs, compression, encryption, checkpoint-payload overflow,
//! NAT journal/roll-forward replay, or checksum verification. Synthetic coverage
//! only; see tests/fixture_sources/f2fs/README.md for the supported scope.
use crate::archive::{ArchiveReader, MAX_FILE_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use std::{collections::HashSet, ops::Range};

const BS: usize = 4096;
const ADDRS: usize = (BS - 360 - 20 - 24) / 4;
const PTRS: usize = (BS - 24) / 4;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "f2fs",
    name: "F2fs",
    description: "F2FS filesystem (static NAT, 4 KiB)",
    signatures: &[
        Signature::new(1024, b"\x10\x20\xf5\xf2"),
        Signature::new(5120, b"\x10\x20\xf5\xf2"),
    ],
    probe: Some(|data| superblock(data).is_some()),
    open,
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
fn superblock(data: &[u8]) -> Option<usize> {
    [1024, 5120].into_iter().find(|&base| {
        let Ok(sb) = get(data, base, 1668) else {
            return false;
        };
        le32(sb, 0).ok() == Some(0xf2f52010)
            && le32(sb, 16).ok() == Some(12)
            && le32(sb, 20).is_ok_and(|n| n <= 20)
            && le32(sb, 52).is_ok_and(|n| n != 0)
    })
}
struct Inode {
    nid: u32,
    mode: u16,
    size: usize,
    direct: Range<usize>,
    nodes: [u32; 5],
    inline: Option<Range<usize>>,
}
struct Mapping {
    logical: u64,
    physical: u32,
}
struct Walk {
    limit: u64,
    owner: u32,
    visited: HashSet<u32>,
    mappings: Vec<Mapping>,
}
struct F2fs {
    data: Vec<u8>,
    bps: u64,
    nat: u64,
    bitmap: Vec<u8>,
    root: u32,
    names: Vec<String>,
    files: Vec<Inode>,
}
impl F2fs {
    fn block(&self, number: u64) -> Result<&[u8]> {
        let start = number
            .checked_mul(BS as u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("F2FS block offset overflow")?;
        get(&self.data, start, BS)
    }
    fn checkpoint(&mut self, cp: u64, segments: u64) -> Result<()> {
        let pack = segments
            .checked_mul(self.bps)
            .ok_or("F2FS checkpoint size overflow")?
            / 2;
        if pack == 0 {
            return Err("empty F2FS checkpoint area".into());
        }
        let mut best = None;
        for i in 0..2 {
            let start = cp + i * pack;
            let Ok(header) = self.block(start) else {
                continue;
            };
            let count = le32(header, 136)? as u64;
            if count == 0 || count > pack {
                continue;
            }
            let Ok(footer) = self.block(start + count - 1) else {
                continue;
            };
            let version = u64le(header, 0)?;
            if u64le(footer, 0)? == version && best.is_none_or(|(old, _)| version >= old) {
                best = Some((version, start));
            }
        }
        let (_, start) = best.ok_or("no matching F2FS checkpoint header/footer")?;
        let header = self.block(start)?;
        let flags = le32(header, 132)?;
        if flags & (0x400 | 0x1000 | 0x2000 | 0x8) != 0 {
            return Err("F2FS large NAT bitmap/disabled/error checkpoint unsupported".into());
        }
        let sit = le32(header, 156)? as usize;
        let nat = le32(header, 160)? as usize;
        let offset = 192usize
            .checked_add(sit)
            .ok_or("F2FS bitmap offset overflow")?;
        if nat == 0 {
            return Err("empty F2FS NAT version bitmap".into());
        }
        self.bitmap = get(header, offset, nat)?.to_vec();
        Ok(())
    }
    fn node(&self, nid: u32, owner: u32) -> Result<Range<usize>> {
        if nid == 0 {
            return Err("zero F2FS node ID".into());
        }
        let per = BS / 9;
        let logical = nid as usize / per;
        let byte = *self
            .bitmap
            .get(logical / 8)
            .ok_or("F2FS NAT bitmap does not cover node ID")?;
        let current = byte & (1 << (7 - logical % 8)) != 0;
        let offset = logical as u64;
        let physical =
            self.nat + offset * 2 - (offset & (self.bps - 1)) + if current { self.bps } else { 0 };
        let record = get(self.block(physical)?, (nid as usize % per) * 9, 9)?;
        let nat_owner = le32(record, 1)?;
        let address = le32(record, 5)?;
        if matches!(address, 0 | u32::MAX) {
            return Err("unallocated F2FS node".into());
        }
        let bytes = self.block(address as u64)?;
        if le32(bytes, BS - 24)? != nid || le32(bytes, BS - 20)? != nat_owner || nat_owner != owner
        {
            return Err("F2FS NAT/node footer owner or ID mismatch".into());
        }
        let start = address as usize * BS;
        Ok(start..start + BS)
    }
    fn inode(&self, nid: u32) -> Result<Inode> {
        let range = self.node(nid, nid)?;
        let raw = &self.data[range.clone()];
        let size = u64le(raw, 16)?;
        if size > MAX_FILE_SIZE as u64 {
            return Err("F2FS inode exceeds file size limit".into());
        }
        if le32(raw, 80)? & 4 != 0 {
            return Err("compressed F2FS inode unsupported".into());
        }
        if raw[2] & 4 != 0 {
            return Err("encrypted F2FS inode unsupported".into());
        }
        let flags = raw[3];
        if flags & 1 != 0 {
            return Err("F2FS inline xattrs unsupported".into());
        }
        let extra = if flags & 0x20 != 0 {
            u16le(raw, 360)? as usize
        } else {
            0
        };
        if !extra.is_multiple_of(4) || extra > ADDRS * 4 {
            return Err("invalid F2FS extra attribute size".into());
        }
        let count = ADDRS - extra / 4;
        let start = range.start + 360 + extra;
        let end = range.start + 360 + ADDRS * 4;
        let mut nodes = [0; 5];
        for (i, pointer) in nodes.iter_mut().enumerate() {
            *pointer = le32(raw, 360 + ADDRS * 4 + i * 4)?;
        }
        let inline = if flags & 6 != 0 {
            if count < 1 {
                return Err("no F2FS inline capacity".into());
            }
            if flags & 6 == 6 {
                return Err("conflicting F2FS inline flags".into());
            }
            Some(start + 4..end)
        } else {
            None
        };
        Ok(Inode {
            nid,
            mode: u16le(raw, 0)?,
            size: size as usize,
            direct: start..end,
            nodes,
            inline,
        })
    }
    fn emit(&self, address: u32, logical: u64, walk: &mut Walk) -> Result<()> {
        if logical >= walk.limit || matches!(address, 0 | u32::MAX) {
            return Ok(());
        }
        if address == u32::MAX - 1 {
            return Err("F2FS compressed block marker unsupported".into());
        }
        if walk.mappings.len() >= MAX_MEMBERS {
            return Err("too many F2FS data mappings".into());
        }
        self.block(address as u64)?;
        walk.mappings.push(Mapping {
            logical,
            physical: address,
        });
        Ok(())
    }
    fn subtree(&self, nid: u32, depth: u32, logical: u64, walk: &mut Walk) -> Result<()> {
        if logical >= walk.limit || nid == 0 {
            return Ok(());
        }
        if depth > 2 || walk.visited.len() >= MAX_MEMBERS || !walk.visited.insert(nid) {
            return Err("F2FS node cycle/duplicate reference or depth limit".into());
        }
        let range = self.node(nid, walk.owner)?;
        let raw = &self.data[range];
        let stride = (PTRS as u64).pow(depth);
        for (i, entry) in raw[..PTRS * 4].chunks_exact(4).enumerate() {
            let target = logical + i as u64 * stride;
            if target >= walk.limit {
                break;
            }
            let pointer = u32::from_le_bytes(entry.try_into().unwrap());
            if depth == 0 {
                self.emit(pointer, target, walk)?;
            } else {
                self.subtree(pointer, depth - 1, target, walk)?;
            }
        }
        Ok(())
    }
    fn mappings(&self, inode: &Inode) -> Result<Vec<Mapping>> {
        let mut walk = Walk {
            limit: inode.size.div_ceil(BS) as u64,
            owner: inode.nid,
            visited: HashSet::from([inode.nid]),
            mappings: vec![],
        };
        let entries = &self.data[inode.direct.clone()];
        for (i, entry) in entries.chunks_exact(4).enumerate() {
            if i as u64 >= walk.limit {
                break;
            }
            self.emit(
                u32::from_le_bytes(entry.try_into().unwrap()),
                i as u64,
                &mut walk,
            )?;
        }
        let mut logical = (entries.len() / 4) as u64;
        for (i, nid) in inode.nodes.iter().enumerate() {
            let depth = match i {
                0 | 1 => 0,
                2 | 3 => 1,
                _ => 2,
            };
            self.subtree(*nid, depth, logical, &mut walk)?;
            logical += (PTRS as u64).pow(depth + 1);
        }
        Ok(walk.mappings)
    }
    fn content(&self, inode: &Inode) -> Result<Vec<u8>> {
        if let Some(range) = &inode.inline {
            if inode.size > range.len() {
                return Err("F2FS inline file exceeds capacity".into());
            }
            return Ok(self.data[range.start..range.start + inode.size].to_vec());
        }
        let mappings = self.mappings(inode)?;
        let mut output = vec![0; inode.size];
        for mapping in mappings {
            let start = mapping.logical as usize * BS;
            let length = BS.min(inode.size - start);
            output[start..start + length]
                .copy_from_slice(&self.block(mapping.physical as u64)?[..length]);
        }
        Ok(output)
    }
    fn directory(&self, inode: &Inode) -> Result<Vec<(String, u32, u8)>> {
        if let Some(range) = &inode.inline {
            return dentries(&self.data[range.clone()]);
        }
        let mut entries = Vec::new();
        for mapping in self.mappings(inode)? {
            let block = dentries(self.block(mapping.physical as u64)?)?;
            if entries.len() + block.len() > MAX_MEMBERS {
                return Err("too many F2FS directory entries".into());
            }
            entries.extend(block);
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
                return Err("F2FS directory traversal limit".into());
            }
            let inode = self.inode(nid)?;
            match inode.mode & 0xf000 {
                0x4000 => {
                    if !visited.insert(nid) {
                        return Err("F2FS directory cycle/repeated directory".into());
                    }
                    for (name, child, kind) in self.directory(&inode)?.into_iter().rev() {
                        if !matches!(kind, 0..=2) {
                            continue;
                        }
                        let name = if path.is_empty() {
                            name
                        } else {
                            format!("{path}/{name}")
                        };
                        validate_name(&name)?;
                        if pending.len() + count >= MAX_MEMBERS {
                            return Err("too many F2FS paths".into());
                        }
                        pending.push((name, child, depth + 1));
                    }
                }
                0x8000 => {
                    self.names.push(path);
                    self.files.push(inode);
                }
                _ => {}
            }
        }
        Ok(())
    }
}
fn dentries(bytes: &[u8]) -> Result<Vec<(String, u32, u8)>> {
    let count = bytes.len() * 8 / 153;
    if count == 0 {
        return Err("F2FS directory region too small".into());
    }
    let bitmap_size = count.div_ceil(8);
    let names = bytes.len() - count * 8;
    let records = names - count * 11;
    if records < bitmap_size {
        return Err("invalid F2FS directory geometry".into());
    }
    let bit = |index: usize| bytes[index / 8] & (1 << (index % 8)) != 0;
    let mut entries = Vec::new();
    let mut slot = 0;
    while slot < count {
        if !bit(slot) {
            slot += 1;
            continue;
        }
        let entry = get(bytes, records + slot * 11, 11)?;
        let length = u16le(entry, 8)? as usize;
        let slots = length.div_ceil(8);
        if length == 0
            || length > 255
            || slot + slots > count
            || (slot..slot + slots).any(|i| !bit(i))
        {
            return Err("invalid F2FS directory name/slot bitmap".into());
        }
        let name = String::from_utf8_lossy(get(bytes, names + slot * 8, length)?).into_owned();
        if name != "." && name != ".." {
            validate_name(&name)?;
            if name.contains('/') {
                return Err("F2FS directory name contains slash".into());
            }
            entries.push((name, le32(entry, 4)?, entry[10]));
        }
        slot += slots;
    }
    Ok(entries)
}
impl ArchiveReader for F2fs {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        self.content(
            self.files
                .get(index)
                .ok_or("F2FS file index out of range")?,
        )
    }
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let base = superblock(&data).ok_or("no supported 4 KiB F2FS superblock")?;
    let sb = get(&data, base, 1668)?;
    if le32(sb, 1664)? != 0 {
        return Err("F2FS checkpoint payload overflow unsupported".into());
    }
    let bps = 1u64 << le32(sb, 20)?;
    let cp = le32(sb, 76)? as u64;
    let segments = le32(sb, 52)? as u64;
    let nat = le32(sb, 84)? as u64;
    let root = le32(sb, 96)?;
    let mut fs = F2fs {
        data,
        bps,
        nat,
        root,
        bitmap: vec![],
        names: vec![],
        files: vec![],
    };
    fs.checkpoint(cp, segments)?;
    if fs.inode(root)?.mode & 0xf000 != 0x4000 {
        return Err("F2FS root is not a directory".into());
    }
    fs.index()?;
    Ok(Box::new(fs))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/f2fs/sample.img").to_vec()
    }
    fn put32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn reader() -> F2fs {
        let mut fs = F2fs {
            data: sample(),
            bps: 8,
            nat: 24,
            root: 3,
            bitmap: vec![],
            names: vec![],
            files: vec![],
        };
        fs.checkpoint(8, 2).unwrap();
        fs
    }
    #[test]
    fn secondary_superblock_and_checkpoint_fallback() {
        let mut data = sample();
        data[1024..1028].fill(0);
        open(data).unwrap();
        let mut data = sample();
        data[23 * BS] ^= 1;
        open(data).unwrap();
        let mut data = sample();
        data[15 * BS] ^= 1;
        data[23 * BS] ^= 1;
        assert!(open(data).is_err());
    }
    #[test]
    fn bitmap_orders_differ() {
        let fs = reader();
        assert_eq!(fs.node(3, 3).unwrap().start, 40 * BS);
        let mut fs = reader();
        fs.bitmap[0] = 0x80;
        fs.data.copy_within(24 * BS..25 * BS, 32 * BS);
        assert_eq!(fs.node(3, 3).unwrap().start, 40 * BS);
        fs.data[24 * BS + 3 * 9 + 5..24 * BS + 3 * 9 + 9].fill(0);
        assert!(fs.node(3, 3).is_ok());
        let mut fs = reader();
        let root = fs.inode(3).unwrap();
        let range = root.inline.unwrap();
        fs.data[range.start] = 0x80; // bit 7 set, not bit 0
        assert!(dentries(&fs.data[range]).is_err());
    }
    #[test]
    fn rejects_unsupported_inodes_and_checkpoint_layouts() {
        for (offset, value) in [
            (40 * BS + 3, 1),
            (40 * BS + 80, 4),
            (1024 + 1664, 1),
            (16 * BS + 132, 0x400),
        ] {
            let mut data = sample();
            put32(&mut data, offset, value);
            assert!(open(data).is_err());
        }
        let mut data = sample();
        data[40 * BS + 2] |= 4;
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 41 * BS + 16, u32::MAX);
        assert!(open(data).is_err());
    }
    #[test]
    fn validates_nat_and_node_footer() {
        let mut data = sample();
        put32(&mut data, 24 * BS + 3 * 9 + 5, u32::MAX);
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 40 * BS + BS - 24, 99);
        assert!(open(data).is_err());
        let mut fs = reader();
        fs.bitmap.clear();
        assert!(fs.node(3, 3).is_err());
    }
    #[test]
    fn rejects_extra_attribute_and_inline_bounds() {
        let mut data = sample();
        data[42 * BS + 360..42 * BS + 362].copy_from_slice(&3u16.to_le_bytes());
        assert!(open(data).is_err());
        let fs = reader();
        let mut inode = fs.inode(4).unwrap();
        inode.size = BS;
        assert!(fs.content(&inode).is_err());
    }
    #[test]
    fn bounds_dentry_names_and_continuation_slots() {
        let fs = reader();
        let root = fs.inode(3).unwrap();
        let range = root.inline.unwrap();
        let mut bytes = fs.data[range].to_vec();
        let count = bytes.len() * 8 / 153;
        let records = bytes.len() - 19 * count;
        bytes[records + 8..records + 10].copy_from_slice(&256u16.to_le_bytes());
        assert!(dentries(&bytes).is_err());
        let mut bytes = vec![0; BS];
        let count = bytes.len() * 8 / 153;
        let records = bytes.len() - 19 * count;
        let names = bytes.len() - 8 * count;
        bytes[0] = 1;
        bytes[records + 8..records + 10].copy_from_slice(&9u16.to_le_bytes());
        bytes[names..names + 9].copy_from_slice(b"long_name");
        assert!(dentries(&bytes).is_err());
        bytes[0] = 3;
        assert_eq!(dentries(&bytes).unwrap()[0].0, "long_name");
    }
    #[test]
    fn all_node_tiers_and_cycles_without_large_file_allocations() {
        let mut fs = reader();
        fs.data.resize(55 * BS, 0);
        for (nid, physical) in [(8, 50), (9, 51), (10, 52)] {
            let nat = 24 * BS + nid * 9;
            put32(&mut fs.data, nat + 1, 5);
            put32(&mut fs.data, nat + 5, physical as u32);
            put32(&mut fs.data, physical * BS + BS - 24, nid as u32);
            put32(&mut fs.data, physical * BS + BS - 20, 5);
        }
        for depth in 0..=2 {
            put32(&mut fs.data, 50 * BS, if depth == 0 { 36 } else { 9 });
            put32(&mut fs.data, 51 * BS, if depth == 1 { 36 } else { 10 });
            put32(&mut fs.data, 52 * BS, 36);
            let mut walk = Walk {
                limit: 1,
                owner: 5,
                visited: HashSet::new(),
                mappings: vec![],
            };
            fs.subtree(8, depth, 0, &mut walk).unwrap();
            assert_eq!(walk.mappings.len(), 1);
            assert_eq!(walk.mappings[0].physical, 36);
        }
        put32(&mut fs.data, 50 * BS, 8);
        let mut walk = Walk {
            limit: 1,
            owner: 5,
            visited: HashSet::new(),
            mappings: vec![],
        };
        assert!(fs.subtree(8, 1, 0, &mut walk).is_err());
    }
    #[test]
    fn new_and_null_data_addresses_leave_holes() {
        let mut fs = reader();
        let inode = fs.inode(5).unwrap();
        fs.data[inode.direct.start..inode.direct.end].fill(0);
        put32(&mut fs.data, inode.direct.start, u32::MAX);
        assert_eq!(fs.content(&inode).unwrap(), vec![0; 9000]);
    }
}
