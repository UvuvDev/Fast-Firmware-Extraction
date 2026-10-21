//! NETGEAR CHK firmware. CHK vendor checksums are advisory; TRX CRC32 is verified.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, be32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "netgear_chk", name: "NetgearChk", description: "NETGEAR CHK firmware",
    signatures: &[Signature::new(0, b"*#$^")],
    probe: None, open,
};

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let members = members(&data)?;
    Ok(Box::new(RangeArchive::new(data, members)?))
}

fn members(data: &[u8]) -> Result<Vec<Member>> {
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
    Ok(members)
}
