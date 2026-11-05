//! NETGEAR CHK firmware. CHK vendor checksums are advisory; TRX CRC32 is verified.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, be32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "netgear_chk", name: "NetgearChk", description: "NETGEAR CHK firmware",
    signatures: &[Signature::new(0, b"*#$^")],
    probe: None, open,
    max_input_size: None,
    max_file_size: None,
};

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let (members, board_diagnostics) = members(&data)?;
    Ok(Box::new(
        RangeArchive::new(data, members)?.with_diagnostics(board_diagnostics),
    ))
}

/// The CHK board-ID string is validated (see `members` below) but otherwise
/// unused by this reader; surface it so a real device's board string is
/// visible for debugging, the same way mecp.rs surfaces its own
/// header/region fields through `RangeArchive::with_diagnostics`.
fn diagnostics(board: &[u8]) -> String {
    let text = String::from_utf8_lossy(board);
    let trimmed = text.trim_end_matches('\0').trim();
    format!("CHK: board ID {trimmed:?}\n")
}

fn members(data: &[u8]) -> Result<(Vec<Member>, String)> {
    if get(data, 0, 4)? != b"*#$^" {
        return Err("bad CHK magic".into());
    }
    let header_size = be32(data, 4)? as usize;
    if !(41..=4096).contains(&header_size) {
        return Err("invalid CHK header size".into());
    }
    let board = get(data, 40, header_size - 40)?;
    if !board.iter().any(|&b| b != 0) || board.iter().any(|&b| b != 0 && !(32..127).contains(&b)) {
        return Err("invalid CHK board ID".into());
    }
    let payload_size = (be32(data, 24)? as usize)
        .checked_add(be32(data, 28)? as usize)
        .ok_or("CHK payload length overflow")?;
    if payload_size == 0 {
        return Err("empty CHK payload".into());
    }
    let payload = get(data, header_size, payload_size)?;
    let end = header_size + payload_size;
    let name = if payload.starts_with(b"HDR0") {
        "firmware.trx"
    } else {
        "firmware.bin"
    };
    let mut members = vec![Member {
        name: name.into(),
        range: header_size..end,
    }];
    if end < data.len() {
        members.push(Member {
            name: "trailer.bin".into(),
            range: end..data.len(),
        });
    }
    Ok((members, diagnostics(board)))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/netgear_chk/sample.bin");

    fn set_be32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn decodes_the_sample_image_as_a_trx_payload() {
        let archive = Archive::open("netgear_chk", SAMPLE.to_vec()).unwrap();
        assert_eq!(archive.names(), ["firmware.trx"]);
        assert_eq!(archive.read(0).unwrap().len(), 4166);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = SAMPLE.to_vec();
        data[0] ^= 0xFF;
        assert!(Archive::open("netgear_chk", data).is_err());
    }

    #[test]
    fn rejects_header_size_outside_the_valid_range() {
        for header_size in [0_u32, 40, 4097, u32::MAX] {
            let mut data = SAMPLE.to_vec();
            set_be32(&mut data, 4, header_size);
            assert!(
                Archive::open("netgear_chk", data).is_err(),
                "header_size {header_size}"
            );
        }
    }

    #[test]
    fn rejects_an_all_zero_board_id() {
        let mut data = SAMPLE.to_vec();
        data[40..58].fill(0);
        assert!(Archive::open("netgear_chk", data).is_err());
    }

    #[test]
    fn rejects_a_non_printable_board_id_byte() {
        let mut data = SAMPLE.to_vec();
        data[40] = 0x01; // not NUL, not printable ASCII either
        assert!(Archive::open("netgear_chk", data).is_err());
    }

    #[test]
    fn rejects_a_payload_size_overflowing_past_the_actual_buffer() {
        // Two be32 fields near u32::MAX sum (via checked usize arithmetic,
        // so this can't overflow on a 64-bit target) to a payload claim
        // vastly larger than the real buffer; it must still be rejected
        // once the claimed range is checked against the actual data.
        let mut data = SAMPLE.to_vec();
        set_be32(&mut data, 24, u32::MAX);
        set_be32(&mut data, 28, u32::MAX);
        assert!(Archive::open("netgear_chk", data).is_err());
    }

    #[test]
    fn rejects_a_zero_payload_size() {
        let mut data = SAMPLE.to_vec();
        set_be32(&mut data, 24, 0);
        set_be32(&mut data, 28, 0);
        assert!(Archive::open("netgear_chk", data).is_err());
    }

    #[test]
    fn names_the_payload_firmware_bin_when_it_does_not_start_with_hdr0() {
        let mut data = SAMPLE.to_vec();
        let header_size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
        data[header_size] = b'X'; // break the "HDR0" signature
        let archive = Archive::open("netgear_chk", data).unwrap();
        assert_eq!(archive.names(), ["firmware.bin"]);
    }

    #[test]
    fn exposes_trailing_bytes_past_the_payload_as_a_member() {
        let mut data = SAMPLE.to_vec();
        data.extend_from_slice(b"trailing-bytes");
        let archive = Archive::open("netgear_chk", data).unwrap();
        let mut names = archive.names().to_vec();
        names.sort();
        assert_eq!(names, ["firmware.trx", "trailer.bin"]);
        assert_eq!(archive.read_named("trailer.bin").unwrap(), b"trailing-bytes");
    }

    #[test]
    fn surfaces_the_board_id_through_diagnostics() {
        let archive = Archive::open("netgear_chk", SAMPLE.to_vec()).unwrap();
        assert!(
            archive.diagnostics().contains("U12H270T00_NETGEAR"),
            "diagnostics: {:?}",
            archive.diagnostics()
        );
    }
}
