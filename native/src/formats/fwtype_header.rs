//! Vendor fw-type wrapper, as observed in the single router sample described
//! by formats/fwtype_header.py. No public specification is known. Detection
//! requires the literal tag in the first 256 bytes and UBI# within 64 KiB.
//! Vendor hash bytes/tag values are not interpreted or authenticated.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::registry::{FormatDescriptor, Signature};

const TAG: &[u8] = b"fw-type:";
const TAG_LIMIT: usize = 256;
const SCAN_LIMIT: usize = 1 << 16;
// Enumerating the bounded tag positions uses the existing signature index;
// unrelated inputs never require an unconditional format-specific probe.
const fn signatures() -> [Signature; TAG_LIMIT - TAG.len() + 1] {
    let mut result = [const { Signature::new(0, TAG) }; TAG_LIMIT - TAG.len() + 1];
    let mut offset = 0;
    while offset < result.len() {
        result[offset] = Signature::new(offset, TAG);
        offset += 1;
    }
    result
}
const SIGNATURES: [Signature; TAG_LIMIT - TAG.len() + 1] = signatures();
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "fwtype_header",
    name: "FwTypeHeader",
    description: "Vendor fw-type Header",
    signatures: &SIGNATURES,
    probe: Some(probe),
    open,
    max_input_size: None,
    max_file_size: None,
};
fn payload_offset(data: &[u8]) -> Result<usize> {
    let prefix = &data[..data.len().min(SCAN_LIMIT)];
    if prefix.starts_with(b"UBI#") {
        return Err("bare UBI image is not a fw-type wrapper".into());
    }
    let tag_prefix = &prefix[..prefix.len().min(TAG_LIMIT)];
    let tag = tag_prefix
        .windows(TAG.len())
        .position(|bytes| bytes == TAG)
        .ok_or("fw-type tag not found in bounded prefix")?;
    let after_tag = tag + TAG.len();
    prefix[after_tag..]
        .windows(4)
        .position(|bytes| bytes == b"UBI#")
        .map(|offset| after_tag + offset)
        .ok_or("UBI payload not found after fw-type tag in bounded prefix".into())
}
fn probe(data: &[u8]) -> bool {
    payload_offset(data).is_ok()
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let start = payload_offset(&data)?;
    let end = data.len();
    Ok(Box::new(RangeArchive::new(
        data,
        vec![Member {
            name: "payload.bin".into(),
            range: start..end,
        }],
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive::Archive, registry};
    #[test]
    fn preserves_the_entire_appended_payload() {
        let data = include_bytes!("../../../tests/fixtures/fwtype_header/sample.bin");
        let archive = Archive::open_auto(data.to_vec()).unwrap();
        assert_eq!(archive.names(), ["payload.bin"]);
        assert_eq!(archive.read(0).unwrap(), data[64..]);
    }
    #[test]
    fn enforces_tag_and_payload_search_boundaries() {
        let mut data = vec![0; SCAN_LIMIT + 16];
        data[248..256].copy_from_slice(TAG);
        data[SCAN_LIMIT - 4..SCAN_LIMIT].copy_from_slice(b"UBI#");
        assert_eq!(registry::detect(&data).unwrap().id, "fwtype_header");
        assert_eq!(
            Archive::open_auto(data.clone()).unwrap().read(0).unwrap(),
            data[SCAN_LIMIT - 4..]
        );
        data[SCAN_LIMIT - 4..SCAN_LIMIT].fill(0);
        data[SCAN_LIMIT - 3..SCAN_LIMIT + 1].copy_from_slice(b"UBI#");
        assert!(!probe(&data));
        assert!(registry::detect(&data).is_none());
        let mut data = vec![0; 512];
        data[249..257].copy_from_slice(TAG);
        data[400..404].copy_from_slice(b"UBI#");
        assert!(!probe(&data));
        assert!(registry::detect(&data).is_none());
    }
    #[test]
    fn rejects_missing_markers_and_bare_ubi_images() {
        for data in [
            b"fw-type:Cloud\nno payload".as_slice(),
            b"no tag\0UBI#payload".as_slice(),
            b"UBI#fw-type:Cloud\nUBI#payload".as_slice(),
        ] {
            assert!(Archive::open("fwtype_header", data.to_vec()).is_err());
            assert!(!probe(data));
        }
    }
    #[test]
    fn ignores_false_payload_magic_before_the_tag() {
        let data = b"hash-UBI#-bytes\0fw-type:Cloud\0UBI#real payload";
        let archive = Archive::open_auto(data.to_vec()).unwrap();
        assert_eq!(archive.read(0).unwrap(), b"UBI#real payload");
    }
}
