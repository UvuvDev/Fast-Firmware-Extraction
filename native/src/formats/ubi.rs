//! UBI volume reconstruction, ported from formats/ubi.py's real-sample-verified
//! EC/VID/table layout. No kernel or mtd-utils implementation was copied.
//! Reorders LEBs and honors static lengths/dynamic capacity and data padding.
//! Uses the first layout LEB 0; update recovery and header CRCs are not supported.
use crate::archive::{ArchiveReader, LARGE_CONTAINER_MAX_SIZE, Result};
use crate::bytes::{be32, get};
use crate::registry::{FormatDescriptor, Signature};
use std::{collections::BTreeMap, ops::Range};

const LAYOUT: u32 = 0x7fff_efff;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "ubi",
    name: "Ubi",
    description: "UBI flash image",
    signatures: &[Signature::new(0, b"UBI#")],
    probe: None,
    open,
    max_input_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
};
struct Ubi {
    data: Vec<u8>,
    names: Vec<String>,
    volumes: Vec<Vec<Range<usize>>>,
}
impl ArchiveReader for Ubi {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        let segments = self.volumes.get(index).ok_or("volume index out of range")?;
        let length = segments.iter().map(|r| r.len()).sum();
        let mut output = Vec::with_capacity(length);
        for range in segments {
            output.extend_from_slice(&self.data[range.clone()]);
        }
        Ok(output)
    }
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if get(&data, 0, 4)? != b"UBI#" {
        return Err("bad UBI EC magic".into());
    }
    let vid = be32(&data, 16)? as usize;
    let start = be32(&data, 20)? as usize;
    // Match EC geometry too, avoiding a literal UBI# within data as a boundary.
    let peb = (64..data.len().min(1 << 22))
        .find(|&offset| {
            data.get(offset..offset + 4) == Some(b"UBI#")
                && be32(&data, offset + 16).ok() == Some(vid as u32)
                && be32(&data, offset + 20).ok() == Some(start as u32)
        })
        .ok_or("could not measure UBI eraseblock size")?;
    if vid < 64 || vid.checked_add(64).is_none_or(|end| end > start) || start >= peb {
        return Err("invalid UBI EC/VID/data offsets".into());
    }
    if !data.len().is_multiple_of(peb) {
        return Err("truncated UBI eraseblock".into());
    }
    let mut volumes: BTreeMap<u32, Vec<(u32, Range<usize>)>> = BTreeMap::new();
    let mut layout = None;
    for base in (0..data.len()).step_by(peb) {
        if &data[base..base + 4] != b"UBI#" {
            continue;
        }
        if be32(&data, base + 16)? as usize != vid || be32(&data, base + 20)? as usize != start {
            return Err("inconsistent UBI eraseblock geometry".into());
        }
        let header = get(&data, base + vid, 64)?;
        if &header[..4] != b"UBI!" {
            continue;
        }
        let kind = header[5];
        if kind != 1 && kind != 2 {
            return Err("unsupported UBI volume type".into());
        }
        let id = be32(header, 8)?;
        let lnum = be32(header, 12)?;
        let pad = be32(header, 28)? as usize;
        let capacity = (peb - start)
            .checked_sub(pad)
            .filter(|&n| n > 0)
            .ok_or("invalid UBI data padding")?;
        let stored = be32(header, 20)? as usize;
        let length = if kind == 2 && stored != 0 {
            stored
        } else {
            capacity
        };
        if length > capacity {
            return Err("UBI LEB exceeds capacity".into());
        }
        let range = base + start..base + start + length;
        if id == LAYOUT && lnum == 0 && layout.is_none() {
            layout = Some(base + start..base + start + capacity);
        }
        volumes.entry(id).or_default().push((lnum, range));
    }
    let table = &data[layout.ok_or("UBI layout volume missing")?];
    let mut names = Vec::new();
    let mut members = Vec::new();
    for (id, record) in table.chunks_exact(172).enumerate() {
        let length = u16::from_be_bytes(record[14..16].try_into().unwrap()) as usize;
        if length == 0 || length > 127 {
            continue;
        }
        let Some(mut segments) = volumes.remove(&(id as u32)) else {
            continue;
        };
        segments.sort_by_key(|(lnum, _)| *lnum);
        let mut size = 0usize;
        for (expected, (lnum, range)) in segments.iter().enumerate() {
            if *lnum as usize != expected {
                return Err("UBI volume has missing or duplicate logical blocks; update recovery unsupported".into());
            }
            size = size
                .checked_add(range.len())
                .filter(|&n| n <= LARGE_CONTAINER_MAX_SIZE)
                .ok_or("UBI volume exceeds file limit")?;
        }
        names.push(String::from_utf8_lossy(&record[16..16 + length]).into_owned());
        members.push(segments.into_iter().map(|(_, range)| range).collect());
    }
    Ok(Box::new(Ubi {
        data,
        names,
        volumes: members,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Archive;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/ubi/sample.bin").to_vec()
    }
    #[test]
    fn rejects_truncated_blocks_and_bad_lengths() {
        let mut data = sample();
        data.pop();
        assert!(open(data).is_err());
        let mut data = sample();
        data[512 + 64 + 20..512 + 64 + 24].copy_from_slice(&400u32.to_be_bytes());
        assert!(open(data).is_err());
    }
    #[test]
    fn rejects_gaps_and_duplicate_lebs_but_skips_unsafe_names() {
        let mut data = sample();
        data[512 + 64 + 12..512 + 64 + 16].copy_from_slice(&1u32.to_be_bytes());
        assert!(open(data).is_err());
        let mut data = sample();
        data.extend_from_within(512..1024);
        assert!(open(data).is_err());
        let mut data = sample();
        data[144..148].copy_from_slice(b"../x");
        let archive = Archive::open("ubi", data).unwrap();
        assert!(!archive.names().iter().any(|name| name == "../x"));
    }
    #[test]
    fn reorders_static_lebs_and_reads_dynamic_padding() {
        let mut data = sample();
        data.extend_from_within(512..1024);
        data[512 + 64 + 12..512 + 64 + 16].copy_from_slice(&1u32.to_be_bytes());
        data[1024 + 128..1024 + 128 + 108].fill(42);
        let archive = open(data).unwrap();
        let output = archive.read(0).unwrap();
        assert_eq!(output.len(), 216);
        assert_eq!(&output[..108], &[42; 108]);
        let mut data = sample();
        data[512 + 64 + 5] = 1;
        data[512 + 64 + 28..512 + 64 + 32].copy_from_slice(&16u32.to_be_bytes());
        assert_eq!(open(data).unwrap().read(0).unwrap().len(), 368);
    }
    #[test]
    fn measures_geometry_despite_magic_in_first_payload() {
        let mut data = sample();
        data[320..324].copy_from_slice(b"UBI#");
        assert_eq!(open(data).unwrap().read(0).unwrap().len(), 108);
    }
}
