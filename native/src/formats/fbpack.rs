//! Pixel/Tensor fastboot packages, FBPK v1 (linked entries) and v2 (table).
//! Port of formats/fbpack.py; v2 structs cross-checked against Google's
//! source.android.com/devices/bootloader/tools/pixel/fw_unpack/fbpack.py,
//! v1 traversal follows the existing Python port, whose documented reference
//! is CalyxOS/scripts fbpacktool.py (Apache-2.0).
//! CRC fields remain advisory, matching the Python implementation.
use std::collections::HashSet;
use crate::archive::{ArchiveReader, Member, RangeArchive, Result, MAX_MEMBERS};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "fbpack", name: "FBPack", description: "Fastboot Package (FBPK v1/v2)",
    signatures: &[Signature::new(0, b"FBPK")], probe: None, open,
};

fn word64(data: &[u8], offset: usize) -> Result<usize> {
    let value = u64::from_le_bytes(get(data, offset, 8)?.try_into().unwrap());
    usize::try_from(value).map_err(|_| "FBPK value exceeds address space".into())
}
fn split64(data: &[u8], offset: usize) -> Result<usize> {
    let value = ((le32(data, offset)? as u64) << 32) | le32(data, offset + 4)? as u64;
    usize::try_from(value).map_err(|_| "FBPK value exceeds address space".into())
}
fn name(data: &[u8]) -> String {
    String::from_utf8_lossy(data.split(|&byte| byte == 0).next().unwrap()).into_owned()
}
fn count(data: &[u8], offset: usize, record_size: usize) -> Result<usize> {
    let count = le32(data, offset)? as usize;
    if count > MAX_MEMBERS || count > data.len() / record_size {
        return Err("FBPK entry count exceeds input or member limit".into());
    }
    Ok(count)
}
fn v1(data: &[u8]) -> Result<Vec<Member>> {
    get(data, 0, 84)?;
    let count = count(data, 76, 56)?;
    let mut members = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 84;
    for _ in 0..count {
        if offset < 84 || !seen.insert(offset) {
            return Err("FBPK v1 invalid or cyclic entry link".into());
        }
        let entry = get(data, offset, 56)?;
        let start = offset.checked_add(56).ok_or("FBPK offset overflow")?;
        offset = split64(entry, 44)?;
        // Table markers carry a link, not a payload.
        if le32(entry, 0)? == 0 { continue; }
        let end = start.checked_add(split64(entry, 36)?).ok_or("FBPK payload overflow")?;
        members.push(Member { name: name(&entry[4..36]), range: start..end });
    }
    Ok(members)
}
fn v2(data: &[u8]) -> Result<Vec<Member>> {
    get(data, 0, 112)?;
    let header_size = le32(data, 8)? as usize;
    let entry_size = le32(data, 12)? as usize;
    if header_size != 112 || entry_size != 104 {
        return Err("unsupported FBPK v2 header/entry layout".into());
    }
    let count = count(data, 104, entry_size)?;
    let table_size = count.checked_mul(entry_size).ok_or("FBPK table size overflow")?;
    let table = get(data, header_size, table_size)?;
    let mut members = Vec::new();
    for entry in table.chunks_exact(entry_size) {
        let start = word64(entry, 80)?;
        let end = start.checked_add(word64(entry, 88)?).ok_or("FBPK payload overflow")?;
        members.push(Member { name: name(&entry[4..40]), range: start..end });
    }
    Ok(members)
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if get(&data, 0, 4)? != b"FBPK" { return Err("bad FBPK magic".into()); }
    let members = match le32(&data, 4)? {
        1 => v1(&data)?, 2 => v2(&data)?,
        _ => return Err("unsupported FBPK version".into()),
    };
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const V1: &[u8] = include_bytes!("../../../tests/fixtures/fbpack_v1/sample.bin");
    const V2: &[u8] = include_bytes!("../../../tests/fixtures/fbpack_v2/sample.bin");
    fn reject(data: Vec<u8>) { assert!(Archive::open("fbpack", data).is_err()); }
    fn set32(data: &mut [u8], offset: usize, value: u32) { data[offset..offset+4].copy_from_slice(&value.to_le_bytes()); }
    #[test]
    fn every_truncated_prefix_is_rejected() {
        for data in [V1, V2] { for length in 0..data.len() { reject(data[..length].to_vec()); } }
    }
    #[test]
    fn rejects_cyclic_links_and_64_bit_link_sizes() {
        for (offset, value) in [(132, 84), (128, 1), (176, 1), (132, 0)] {
            let mut data = V1.to_vec(); set32(&mut data, offset, value); reject(data);
        }
    }
    #[test]
    fn rejects_64_bit_payload_overflow_and_table_limits() {
        for (offset, value) in [(8, 0), (12, 0), (104, u32::MAX), (196, u32::MAX), (204, u32::MAX)] {
            let mut data = V2.to_vec(); set32(&mut data, offset, value); reject(data);
        }
    }
    #[test]
    fn unsafe_and_duplicate_names_fail_before_extraction() {
        let mut data = V2.to_vec();
        data[116..152].fill(0); data[116..125].copy_from_slice(b"../escape"); reject(data);
        let mut data = V2.to_vec();
        data[220..256].fill(0); data[220..225].copy_from_slice(b"alpha"); reject(data);
    }
    #[test]
    fn skips_v1_table_markers_and_preserves_payloads() {
        let archive = Archive::open_auto(V1.to_vec()).unwrap();
        assert_eq!(archive.names(), ["gamma", "delta"]);
        assert_eq!(archive.read_named("gamma").unwrap(), b"GAMMA_DATA_1234");
        assert_eq!(archive.read_named("delta").unwrap(), b"DELTA");
    }
}
