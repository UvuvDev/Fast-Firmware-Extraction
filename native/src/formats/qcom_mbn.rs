//! Qualcomm legacy non-ELF 80-byte SBL MBN headers. Port of
//! formats/qcom_mbn.py, verified there against Qualcomm's Sbl_Hdr in
//! coreboot util/qualcomm/mbn_tools.py (BSD-3-Clause).
//! Code, signature and certificate data are concatenated after the header.
//! Load addresses and image_src/image_size metadata are not file offsets.
//! Signatures/certificates are exposed verbatim, not authenticated.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

const MAGIC: &[u8] = b"\xd1\xdc\x4b\x84\x34\x10\xd7\x73";
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "qcom_mbn",
    name: "QcomMbn",
    description: "Qualcomm Legacy MBN Firmware Header",
    signatures: &[Signature::new(0, MAGIC)],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let header = get(&data, 0, 80)?;
    if &header[..8] != MAGIC {
        return Err("bad MBN codeword/magic pair".into());
    }
    let mut start = 80_usize;
    let mut members = Vec::new();
    for (name, offset) in [("code", 32), ("signature", 40), ("cert_chain", 48)] {
        let end = start
            .checked_add(le32(header, offset)? as usize)
            .ok_or("MBN region size overflow")?;
        members.push(Member {
            name: name.into(),
            range: start..end,
        });
        start = end;
    }
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/qcom_mbn/sample.mbn");
    fn set32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn every_truncated_prefix_is_rejected() {
        for length in 0..SAMPLE.len() {
            assert!(Archive::open("qcom_mbn", SAMPLE[..length].to_vec()).is_err());
        }
    }
    #[test]
    fn rejects_each_oversized_region_and_both_magic_words() {
        for offset in [0, 4, 32, 40, 48] {
            let mut data = SAMPLE.to_vec();
            set32(&mut data, offset, u32::MAX);
            assert!(Archive::open("qcom_mbn", data).is_err(), "offset {offset}");
        }
    }
    #[test]
    fn ram_addresses_and_advisory_metadata_do_not_change_file_ranges() {
        let original = Archive::open("qcom_mbn", SAMPLE.to_vec()).unwrap();
        let mut data = SAMPLE.to_vec();
        for offset in [20, 24, 28, 36, 44] {
            set32(&mut data, offset, u32::MAX);
        }
        let changed = Archive::open_auto(data).unwrap();
        for name in original.names() {
            assert_eq!(
                changed.read_named(name).unwrap(),
                original.read_named(name).unwrap()
            );
        }
    }
    #[test]
    fn absent_signature_and_certificates_remain_empty_members() {
        let mut data = SAMPLE[..80].to_vec();
        for offset in [32, 40, 48] {
            set32(&mut data, offset, 0);
        }
        let archive = Archive::open("qcom_mbn", data).unwrap();
        assert_eq!(archive.names(), ["code", "signature", "cert_chain"]);
        for index in 0..3 {
            assert!(archive.read(index).unwrap().is_empty());
        }
    }
}
