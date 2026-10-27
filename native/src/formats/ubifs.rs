//! Committed, unauthenticated UBIFS, ported from formats/ubifs.py's documented
//! on-disk facts. No Linux/mtd-utils implementation code is copied. Validate
//! node CRCs and B-tree references; none/raw-DEFLATE data only. No journal
//! replay, diverging-master recovery, authentication, LZO or ZSTD support.
use crate::archive::{ArchiveReader, LARGE_CONTAINER_MAX_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{DecompressorOxide, decompress, inflate_flags},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Range,
};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "ubifs",
    name: "Ubifs",
    description: "UBIFS filesystem (none/raw DEFLATE)",
    signatures: &[Signature::new(0, b"\x31\x18\x10\x06")],
    probe: Some(|data| data.get(20) == Some(&6)),
    open,
    max_input_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
};
fn u16le(data: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(get(data, off, 2)?.try_into().unwrap()))
}
fn u64le(data: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(get(data, off, 8)?.try_into().unwrap()))
}
fn node(data: &[u8], offset: usize, limit: usize) -> Result<&[u8]> {
    let header = get(data, offset, 24)?;
    if le32(header, 0)? != 0x06101831 {
        return Err("bad UBIFS node magic".into());
    }
    let length = le32(header, 16)? as usize;
    if length < 24 || length > limit {
        return Err("invalid UBIFS node length/LEB boundary".into());
    }
    let bytes = get(data, offset, length)?;
    if !crc32fast::hash(&bytes[8..]) != le32(header, 4)? {
        return Err("UBIFS node CRC mismatch".into());
    }
    Ok(bytes)
}
fn master(data: &[u8], leb: usize, number: usize) -> Result<Option<Range<usize>>> {
    let base = number
        .checked_mul(leb)
        .ok_or("UBIFS master address overflow")?;
    let mut offset = 0;
    let mut last = None;
    while offset + 24 <= leb {
        let Ok(bytes) = node(data, base + offset, leb - offset) else {
            break;
        };
        if bytes[20] == 7 {
            if bytes.len() != 512 {
                return Err("invalid UBIFS master length".into());
            }
            last = Some(base + offset..base + offset + bytes.len());
        }
        offset += (bytes.len() + 7) & !7;
    }
    Ok(last)
}
struct Inode {
    size: usize,
    mode: u32,
}
struct Dent {
    name: String,
    inode: u64,
    kind: u8,
}
struct Block {
    payload: Range<usize>,
    size: usize,
    compression: u16,
}
struct Ubifs {
    data: Vec<u8>,
    leb: usize,
    inodes: HashMap<u64, Inode>,
    children: HashMap<u64, Vec<Dent>>,
    blocks: HashMap<u64, BTreeMap<u32, Block>>,
    names: Vec<String>,
    files: Vec<u64>,
}
impl Ubifs {
    fn location(&self, lnum: u32, offset: u32, length: u32) -> Result<Range<usize>> {
        let offset = offset as usize;
        let length = length as usize;
        if !offset.is_multiple_of(8)
            || length < 24
            || offset.checked_add(length).is_none_or(|n| n > self.leb)
        {
            return Err("invalid UBIFS branch range/alignment".into());
        }
        let start = (lnum as usize)
            .checked_mul(self.leb)
            .and_then(|n| n.checked_add(offset))
            .ok_or("UBIFS branch offset overflow")?;
        get(&self.data, start, length)?;
        Ok(start..start + length)
    }
    fn leaf(&mut self, range: Range<usize>, key: &[u8]) -> Result<()> {
        let bytes = &self.data[range.clone()];
        let kind = bytes[20];
        if !matches!(kind, 0..=3) || get(bytes, 24, 8)? != key || le32(key, 4)? >> 29 != kind as u32
        {
            return Err("UBIFS leaf type/key disagrees with index".into());
        }
        let inode = le32(bytes, 24)? as u64;
        match kind {
            0 => {
                get(bytes, 0, 160)?;
                let size = u64le(bytes, 48)?;
                if size > LARGE_CONTAINER_MAX_SIZE as u64 {
                    return Err("UBIFS inode exceeds file size limit".into());
                }
                let record = Inode {
                    size: size as usize,
                    mode: le32(bytes, 104)?,
                };
                if self.inodes.insert(inode, record).is_some() {
                    return Err("duplicate UBIFS inode key".into());
                }
            }
            2 => {
                let length = u16le(bytes, 50)? as usize;
                let name = String::from_utf8_lossy(get(bytes, 56, length)?).into_owned();
                if name == "." || name == ".." {
                    return Ok(());
                }
                validate_name(&name)?;
                if name.contains('/') {
                    return Err("UBIFS directory name contains slash".into());
                }
                self.children.entry(inode).or_default().push(Dent {
                    name,
                    inode: u64le(bytes, 40)?,
                    kind: bytes[49],
                });
            }
            1 => {
                let block = le32(bytes, 28)? & 0x1fff_ffff;
                let size = le32(bytes, 40)? as usize;
                let compression = u16le(bytes, 44)?;
                if size > 4096 {
                    return Err("UBIFS data block exceeds 4 KiB".into());
                }
                if !matches!(compression, 0 | 2) {
                    return Err("UBIFS LZO/ZSTD or unknown compression unsupported".into());
                }
                let payload = range.start + 48..range.end;
                if payload.start > payload.end || (compression == 0 && payload.len() != size) {
                    return Err("UBIFS data size mismatch".into());
                }
                let record = Block {
                    payload,
                    size,
                    compression,
                };
                if self
                    .blocks
                    .entry(inode)
                    .or_default()
                    .insert(block, record)
                    .is_some()
                {
                    return Err("duplicate UBIFS data key".into());
                }
            }
            _ => {} // Extended attributes are outside the regular file namespace.
        }
        Ok(())
    }
    fn index(&mut self, root: Range<usize>) -> Result<()> {
        let mut pending = vec![(root, None::<u16>, None::<[u8; 8]>)];
        let mut visited = HashSet::new();
        while let Some((range, level, key)) = pending.pop() {
            if visited.len() >= MAX_MEMBERS || !visited.insert(range.start) {
                return Err("UBIFS B-tree cycle/duplicate reference or node limit".into());
            }
            let bytes = node(&self.data, range.start, self.leb - range.start % self.leb)?;
            if bytes.len() != range.len() {
                return Err("UBIFS branch length disagrees with node".into());
            }
            if let Some(key) = key {
                self.leaf(range, &key)?;
                continue;
            }
            if bytes[20] != 9 {
                return Err("UBIFS index branch is not an index node".into());
            }
            let count = u16le(bytes, 24)? as usize;
            let actual_level = u16le(bytes, 26)?;
            if actual_level > 512 || level.is_some_and(|v| v != actual_level) {
                return Err("UBIFS index level mismatch/limit".into());
            }
            let table = get(bytes, 28, count * 20)?;
            if pending.len() + visited.len() + count > MAX_MEMBERS {
                return Err("UBIFS index exceeds node limit".into());
            }
            for branch in table.chunks_exact(20).rev() {
                let child = self.location(le32(branch, 0)?, le32(branch, 4)?, le32(branch, 8)?)?;
                let key: [u8; 8] = branch[12..20].try_into().unwrap();
                pending.push((
                    child,
                    actual_level.checked_sub(1),
                    if actual_level == 0 { Some(key) } else { None },
                ));
            }
        }
        Ok(())
    }
    fn paths(&mut self) -> Result<()> {
        let mut pending = vec![(String::new(), 1u64, 0)];
        let mut visited = HashSet::new();
        let mut count = 0;
        while let Some((path, ino, depth)) = pending.pop() {
            count += 1;
            if count > MAX_MEMBERS || depth > 256 {
                return Err("UBIFS directory traversal limit".into());
            }
            let inode = self
                .inodes
                .get(&ino)
                .ok_or("UBIFS directory references missing inode")?;
            match inode.mode & 0xf000 {
                0x4000 => {
                    if !visited.insert(ino) {
                        return Err("UBIFS directory cycle/repeated directory".into());
                    }
                    for dent in self.children.get(&ino).into_iter().flatten().rev() {
                        if dent.kind > 1 {
                            continue;
                        }
                        let child = self
                            .inodes
                            .get(&dent.inode)
                            .ok_or("UBIFS dent references missing inode")?;
                        if child.mode & 0xf000 != if dent.kind == 1 { 0x4000 } else { 0x8000 } {
                            return Err("UBIFS dent type disagrees with inode".into());
                        }
                        let name = if path.is_empty() {
                            dent.name.clone()
                        } else {
                            format!("{path}/{}", dent.name)
                        };
                        validate_name(&name)?;
                        if pending.len() + count >= MAX_MEMBERS {
                            return Err("too many UBIFS paths".into());
                        }
                        pending.push((name, dent.inode, depth + 1));
                    }
                }
                0x8000 => {
                    self.names.push(path);
                    self.files.push(ino);
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn decode(&self, block: &Block) -> Result<Vec<u8>> {
        let payload = &self.data[block.payload.clone()];
        if block.compression == 0 {
            return Ok(payload.to_vec());
        }
        // One bounded output buffer, including a sentinel byte to detect excess
        // output. Require stream completion and exact input/output consumption.
        let mut output = vec![0; block.size + 1];
        let mut state = Box::<DecompressorOxide>::default();
        let (status, consumed, written) = decompress(
            &mut state,
            payload,
            &mut output,
            0,
            inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        if status != TINFLStatus::Done || consumed != payload.len() || written != block.size {
            return Err("invalid/truncated UBIFS raw DEFLATE or output size mismatch".into());
        }
        output.truncate(written);
        Ok(output)
    }
}
impl ArchiveReader for Ubifs {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        let ino = self
            .files
            .get(index)
            .ok_or("UBIFS file index out of range")?;
        let size = self.inodes[ino].size;
        let mut output = vec![0; size];
        for (block, record) in self.blocks.get(ino).into_iter().flatten() {
            let start = *block as u64 * 4096;
            if start >= size as u64 {
                continue;
            }
            let plain = self.decode(record)?;
            let length = plain.len().min(size - start as usize);
            output[start as usize..start as usize + length].copy_from_slice(&plain[..length]);
        }
        Ok(output)
    }
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let sb = node(&data, 0, data.len())?;
    if sb[20] != 6 || sb.len() != 4096 {
        return Err("expected UBIFS superblock node".into());
    }
    if sb[27] != 0 || le32(sb, 28)? & 0x20 != 0 {
        return Err("UBIFS non-simple keys/authentication unsupported".into());
    }
    let leb = le32(sb, 36)? as usize;
    if leb < 4096 || leb > data.len() || !leb.is_multiple_of(8) {
        return Err("invalid UBIFS LEB size".into());
    }
    let first = master(&data, leb, 1)?;
    let second = master(&data, leb, 2)?;
    if let (Some(a), Some(b)) = (&first, &second)
        && data[a.start + 24..a.end] != data[b.start + 24..b.end]
    {
        return Err("diverging UBIFS master copies require recovery".into());
    }
    let range = first.or(second).ok_or("no valid UBIFS master copy")?;
    let selected = &data[range];
    if le32(selected, 40)? & 1 != 0 {
        return Err("dirty UBIFS master requires journal replay".into());
    }
    let location = (
        le32(selected, 48)?,
        le32(selected, 52)?,
        le32(selected, 56)?,
    );
    let mut fs = Ubifs {
        data,
        leb,
        inodes: HashMap::new(),
        children: HashMap::new(),
        blocks: HashMap::new(),
        names: vec![],
        files: vec![],
    };
    let root = fs.location(location.0, location.1, location.2)?;
    fs.index(root)?;
    if fs
        .inodes
        .get(&1)
        .is_none_or(|inode| inode.mode & 0xf000 != 0x4000)
    {
        return Err("missing UBIFS root directory inode".into());
    }
    fs.paths()?;
    Ok(Box::new(fs))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/ubifs/sample.ubifs").to_vec()
    }
    fn put32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fix(data: &mut [u8], off: usize) {
        let len = le32(data, off + 16).unwrap() as usize;
        let crc = !crc32fast::hash(&data[off + 8..off + len]);
        put32(data, off + 4, crc);
    }
    #[test]
    fn rejects_crc_and_bad_node_lengths() {
        let mut data = sample();
        data[100] ^= 1;
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 12288 + 16, 24);
        fix(&mut data, 12288);
        assert!(open(data).is_err());
    }
    #[test]
    fn master_recovery_and_unsupported_state() {
        let mut data = sample();
        data[4096 + 100] ^= 1;
        open(data).unwrap();
        let mut data = sample();
        data[4096 + 100] ^= 1;
        data[8192 + 100] ^= 1;
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 4096 + 48, 99);
        fix(&mut data, 4096);
        assert!(open(data).is_err());
        let mut data = sample();
        for off in [4096, 8192] {
            put32(&mut data, off + 40, 1);
            fix(&mut data, off);
        }
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 28, 0x20);
        fix(&mut data, 0);
        assert!(open(data).is_err());
    }
    #[test]
    fn rejects_branch_length_key_and_leb_boundary_mismatch() {
        for (offset, value) in [(12288 + 36, 159), (12288 + 44, 5), (12288 + 32, 4088)] {
            let mut data = sample();
            put32(&mut data, offset, value);
            fix(&mut data, 12288);
            assert!(open(data).is_err());
        }
    }
    #[test]
    fn rejects_index_cycles_and_inconsistent_levels() {
        let mut data = sample();
        data[12288 + 26..12288 + 28].copy_from_slice(&1u16.to_le_bytes());
        put32(&mut data, 12288 + 28, 3);
        put32(&mut data, 12288 + 32, 0);
        put32(&mut data, 12288 + 36, 268);
        fix(&mut data, 12288);
        assert!(open(data).is_err());
        let mut data =
            include_bytes!("../../../tests/fixtures/ubifs_multiblock/sample.ubifs").to_vec();
        data[3 * 16384 + 26..3 * 16384 + 28].copy_from_slice(&2u16.to_le_bytes());
        fix(&mut data, 3 * 16384);
        assert!(open(data).is_err());
    }
    #[test]
    fn rejects_duplicate_keys_and_oversized_files() {
        let mut data = sample();
        data.copy_within(12288 + 28..12288 + 48, 12288 + 48);
        fix(&mut data, 12288);
        assert!(open(data).is_err());
        // size is a full 64-bit field; only setting its low 32 bits (as
        // u32::MAX) stays under the raised LARGE_CONTAINER_MAX_SIZE limit.
        let mut data = sample();
        data[16752 + 48..16752 + 56].copy_from_slice(&(20_u64 * 1024 * 1024 * 1024).to_le_bytes());
        fix(&mut data, 16752);
        assert!(open(data).is_err());
    }
    #[test]
    fn compressed_stream_must_end_exactly_at_declared_size() {
        for mutation in 0..3 {
            let mut data = sample();
            match mutation {
                0 => put32(&mut data, 17624 + 40, 1),
                1 => data[17624 + 75] = 0xff,
                _ => put32(&mut data, 17624 + 16, 75),
            };
            fix(&mut data, 17624);
            if mutation == 2 {
                put32(&mut data, 12288 + 28 + 11 * 20 + 8, 75);
                fix(&mut data, 12288);
            }
            let result = open(data).and_then(|fs| {
                let i = fs
                    .names()
                    .iter()
                    .position(|n| n == "compressed.txt")
                    .unwrap();
                fs.read(i)
            });
            assert!(result.is_err());
        }
    }
    #[test]
    fn rejects_unsupported_compression_and_node_types() {
        let mut data = sample();
        data[17624 + 44] = 1;
        fix(&mut data, 17624);
        assert!(open(data).is_err());
        let mut data = sample();
        data[16384 + 20] = 9;
        fix(&mut data, 16384);
        assert!(open(data).is_err());
    }
}
