//! Qualcomm QCDT v1/v2/v3 device-tree tables. Port of formats/qcdt.py,
//! whose layouts were verified against Qualcomm dtbtool.c and EFIDroid's
//! BSD-3-Clause QCDT headers. Identifier fields are advisory; stored payload
//! bytes are returned without interpreting the embedded device trees.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "qcdt",
    name: "Qcdt",
    description: "Qualcomm Device Tree Table (QCDT v1/v2/v3)",
    signatures: &[Signature::new(0, b"QCDT")],
    probe: None,
    open,
};

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if get(&data, 0, 4)? != b"QCDT" {
        return Err("bad QCDT magic".into());
    }
    let stride = match le32(&data, 4)? {
        1 => 20,
        2 => 24,
        3 => 40,
        _ => return Err("unsupported QCDT version".into()),
    };
    let count = le32(&data, 8)? as usize;
    if count > MAX_MEMBERS {
        return Err("QCDT entry count exceeds member limit".into());
    }
    let size = count
        .checked_mul(stride)
        .ok_or("QCDT table size overflow")?;
    let table = get(&data, 12, size)?;
    let mut members = Vec::new();
    for (index, entry) in table.chunks_exact(stride).enumerate() {
        let start = le32(entry, stride - 8)? as usize;
        let size = le32(entry, stride - 4)? as usize;
        let end = start
            .checked_add(size)
            .ok_or("QCDT payload range overflow")?;
        members.push(Member {
            name: format!("dt{index:02}"),
            range: start..end,
        });
    }
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const V1: &[u8] = include_bytes!("../../../tests/fixtures/qcdt_v1/sample.img");
    const V2: &[u8] = include_bytes!("../../../tests/fixtures/qcdt_v2/sample.img");
    const V3: &[u8] = include_bytes!("../../../tests/fixtures/qcdt_v3/sample.img");
    fn set32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn all_versions_reject_every_truncated_prefix() {
        for data in [V1, V2, V3] {
            for length in 0..data.len() {
                assert!(
                    Archive::open("qcdt", data[..length].to_vec()).is_err(),
                    "version {}, prefix {length}",
                    data[4]
                );
            }
        }
    }
    #[test]
    fn rejects_bad_magic_versions_counts_and_each_entry_range() {
        for (offset, value) in [
            (0, 0),
            (4, 0),
            (4, 4),
            (8, u32::MAX),
            (28, u32::MAX),
            (32, u32::MAX),
            (52, u32::MAX),
            (56, u32::MAX),
        ] {
            let mut data = V2.to_vec();
            set32(&mut data, offset, value);
            assert!(Archive::open("qcdt", data).is_err(), "offset {offset}");
        }
    }
    #[test]
    fn accepts_empty_tables_and_empty_payload_at_eof() {
        let mut empty = V1[..12].to_vec();
        set32(&mut empty, 8, 0);
        assert!(Archive::open("qcdt", empty).unwrap().names().is_empty());
        let mut data = V1.to_vec();
        let eof = data.len() as u32;
        set32(&mut data, 8, 1);
        set32(&mut data, 24, eof);
        set32(&mut data, 28, 0);
        let archive = Archive::open("qcdt", data).unwrap();
        assert_eq!(archive.names(), ["dt00"]);
        assert!(archive.read(0).unwrap().is_empty());
    }
    #[test]
    fn v1_contains_the_original_dtc_overlays() {
        let archive = Archive::open_auto(V1.to_vec()).unwrap();
        assert_eq!(
            archive.read(0).unwrap(),
            include_bytes!("../../../tests/fixture_sources/dtbo/overlay0.dtbo")
        );
        assert_eq!(
            archive.read(1).unwrap(),
            include_bytes!("../../../tests/fixture_sources/dtbo/overlay1.dtbo")
        );
    }
}
