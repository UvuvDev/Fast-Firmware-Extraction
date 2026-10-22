//! Broadcom TRX firmware. CHK vendor checksums are advisory; TRX CRC32 is verified.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "trx", name: "Trx", description: "Broadcom TRX firmware",
    signatures: &[Signature::new(0, b"HDR0")],
    probe: None, open,
    max_input_size: None,
    max_file_size: None,
};

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let members = members(&data)?;
    Ok(Box::new(RangeArchive::new(data, members)?))
}

fn members(data: &[u8]) -> Result<Vec<Member>> {
    if get(data, 0, 4)? != b"HDR0" {
        return Err("bad TRX magic".into());
    }
    let total = le32(data, 4)? as usize;
    let flags_version = le32(data, 12)?;
    let version = flags_version >> 16;
    let slots = match version {
        1 => 3,
        2 => 4,
        _ => return Err("unsupported TRX version".into()),
    };
    let header_size = 16 + slots * 4;
    if total < header_size {
        return Err("invalid TRX length".into());
    }
    let image = get(data, 0, total)?;
    get(image, 0, header_size)?;
    if crc32fast::hash(&image[12..]) ^ u32::MAX != le32(image, 8)? {
        return Err("TRX CRC32 mismatch".into());
    }
    let mut offsets = Vec::new();
    let mut saw_empty = false;
    for i in 0..slots {
        let offset = le32(image, 16 + i * 4)? as usize;
        if offset == 0 {
            saw_empty = true;
            continue;
        }
        if saw_empty
            || offset < header_size
            || offset >= total
            || offsets.last().is_some_and(|last| offset <= *last)
        {
            return Err("invalid or unordered TRX partition offsets".into());
        }
        offsets.push(offset);
    }
    if offsets.is_empty() {
        return Err("empty TRX partition table".into());
    }
    let mut members = Vec::new();
    let mut saw_rootfs = false;
    // Preserve any gap between header and first partition as an opaque child.
    if offsets[0] > header_size {
        members.push(Member {
            name: "prefix.bin".into(),
            range: header_size..offsets[0],
        });
    }
    for (index, &start) in offsets.iter().enumerate() {
        let end = offsets.get(index + 1).copied().unwrap_or(total);
        let payload = &image[start..end];
        let name = if index == 0
            && crate::registry::detect(payload).is_some_and(|format| format.id == "lzma_alone")
        {
            "kernel.lzma".into()
        } else if payload.starts_with(b"hsqs") {
            let name = if saw_rootfs {
                format!("rootfs_{index}.squashfs")
            } else {
                "rootfs.squashfs".into()
            };
            saw_rootfs = true;
            name
        } else {
            format!("partition_{index}.bin")
        };
        members.push(Member {
            name,
            range: start..end,
        });
    }
    if total < data.len() {
        members.push(Member {
            name: "trailer.bin".into(),
            range: total..data.len(),
        });
    }
    Ok(members)
}
