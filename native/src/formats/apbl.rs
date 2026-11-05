//! Google APBL v2, observed in the real Cubs spacecraft ABL image via Binary
//! Ninja MCP: outer version at 0, APBL at 0x463c, payload size at 0x4648,
//! SHA-384 at 0x4674 and executable payload at 0x5000. The digest matched
//! independently before implementation. No signature/authentication scheme is
//! assumed: opaque signing metadata is skipped, not authenticated. Only this
//! observed fixed-prefix v2 layout is supported. No reference code copied.
use crate::archive::{ArchiveReader, MAX_FILE_SIZE, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use sha2::{Digest, Sha384};
const TAG: usize = 0x463c;
const PAYLOAD: usize = 0x5000;
const HASH: usize = 0x4674;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "apbl",
    name: "Apbl",
    description: "Google APBL v2 signed bootloader image",
    signatures: &[Signature::new(TAG, b"APBL")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    get(&data, 0, PAYLOAD)?;
    if le32(&data, 0)? != 2 || get(&data, TAG, 4)? != b"APBL" || le32(&data, TAG + 4)? != 2 {
        return Err("unsupported APBL authentication/header version".into());
    }
    let size = le32(&data, TAG + 12)? as usize;
    if size == 0 || size > MAX_FILE_SIZE {
        return Err("invalid APBL payload size".into());
    }
    let payload = get(&data, PAYLOAD, size)?;
    if PAYLOAD + size != data.len() {
        return Err("APBL payload length disagrees with image size".into());
    }
    if Sha384::digest(payload).as_slice() != get(&data, HASH, 48)? {
        return Err("APBL SHA-384 payload digest mismatch".into());
    }
    let archive = RangeArchive::new(
        data,
        vec![Member {
            name: "payload.bin".into(),
            range: PAYLOAD..PAYLOAD + size,
        }],
    )?;
    Ok(Box::new(archive.with_diagnostics(format!("APBL v2: payload at {PAYLOAD:#x}, {size:#x} bytes; SHA-384 matches. Signing metadata is not authenticated."))))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/apbl/sample.bin").to_vec()
    }
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn payload_and_digest_corruption_rejected() {
        for offset in [PAYLOAD, HASH] {
            let mut data = sample();
            data[offset] ^= 1;
            assert!(open(data).is_err());
        }
    }
    #[test]
    fn versions_and_lengths_checked() {
        for (offset, value) in [(0, 1), (TAG + 4, 3), (TAG + 12, 0), (TAG + 12, u32::MAX)] {
            let mut data = sample();
            put32(&mut data, offset, value);
            assert!(open(data).is_err());
        }
        let mut data = sample();
        data.pop();
        assert!(open(data).is_err());
        let mut data = sample();
        data.push(0);
        assert!(open(data).is_err());
        assert!(open(sample()[..TAG + 4].to_vec()).is_err());
    }
    #[test]
    fn opaque_signing_bytes_are_not_treated_as_authenticated() {
        let mut data = sample();
        data[0x1000] ^= 1;
        let fs = open(data).unwrap();
        assert_eq!(fs.read(0).unwrap(), sample()[PAYLOAD..]);
        assert!(fs.diagnostics().contains("not authenticated"));
    }
}
