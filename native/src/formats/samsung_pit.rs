//! Samsung PIT descriptors, ported from formats/samsung_pit.py's verified
//! Heimdall libpit layout (MIT). A standalone PIT contains metadata only:
//! emit each named raw record, never interpret device offsets as file offsets.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "samsung_pit",
    name: "SamsungPit",
    description: "Samsung PIT partition descriptors",
    signatures: &[Signature::new(0, b"\x76\x98\x34\x12")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let header = get(&data, 0, 28)?;
    if le32(header, 0)? != 0x12349876 {
        return Err("bad PIT identifier".into());
    }
    let count = le32(header, 4)? as usize;
    if count > 4096 {
        return Err("PIT entry count exceeds limit".into());
    }
    let records = get(&data, 28, count * 132)?;
    let mut members = Vec::new();
    for (index, record) in records.chunks_exact(132).enumerate() {
        let name = &record[36..68];
        let name = name.split(|&byte| byte == 0).next().unwrap();
        if name.is_empty() {
            continue;
        }
        let name = String::from_utf8_lossy(name).into_owned();
        let start = 28 + index * 132;
        members.push(Member {
            name,
            range: start..start + 132,
        });
    }
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Archive;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/samsung_pit/sample.pit").to_vec()
    }
    fn put32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn rejects_truncation_and_excessive_count() {
        let mut data = sample();
        data.pop();
        assert!(open(data).is_err());
        let mut data = sample();
        put32(&mut data, 4, 4097);
        assert!(open(data).is_err());
    }
    #[test]
    fn empty_names_skipped_and_obsolete_offsets_ignored() {
        let mut data = sample();
        data[64..96].fill(0);
        put32(&mut data, 28 + 132 + 28, u32::MAX);
        put32(&mut data, 28 + 132 + 32, u32::MAX);
        let archive = open(data).unwrap();
        assert_eq!(archive.names(), ["SYSTEM"]);
        assert_eq!(archive.read(0).unwrap().len(), 132);
    }
    #[test]
    fn full_width_names_and_empty_tables() {
        let mut data = sample();
        data[64..96].fill(b'X');
        assert_eq!(open(data).unwrap().names()[0], "X".repeat(32));
        let mut data = sample();
        put32(&mut data, 4, 0);
        assert!(open(data).unwrap().names().is_empty());
    }
    #[test]
    fn skips_unsafe_and_duplicate_names_rather_than_failing_outright() {
        let mut data = sample();
        data[64..96].fill(0);
        data[64..68].copy_from_slice(b"../x");
        let archive = Archive::open("samsung_pit", data).unwrap();
        assert_eq!(archive.names(), ["SYSTEM"]);
        let mut data = sample();
        data.copy_within(64..96, 196);
        let archive = Archive::open("samsung_pit", data).unwrap();
        assert_eq!(archive.names().len(), 1);
    }
}
