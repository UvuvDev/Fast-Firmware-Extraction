//! U-Boot legacy image ("uImage"), a 64-byte big-endian header mkimage/dumpimage
//! still produce and read today. Layout and both CRC32 algorithms (plain zlib
//! CRC32 over the header with ih_hcrc zeroed, and over the data) were verified
//! against real `mkimage`/`dumpimage` 2026.10 output, including the multi-file
//! sub-image size table and its 4-byte padding between (not after) entries.
//! ih_type values used below were confirmed the same way, one per -T option.
//! Compressed payloads (ih_comp != none) are exposed as stored, undecompressed
//! bytes; nested detection decodes any payload this crate otherwise recognizes.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::{be32, get};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "uboot_legacy",
    name: "UBootLegacyImage",
    description: "U-Boot legacy image (uImage)",
    signatures: &[Signature::new(0, b"\x27\x05\x19\x56")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};

const HEADER_SIZE: usize = 64;
const IH_TYPE_MULTI: u8 = 4;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("uImage offset overflow".into())
}

fn type_name(value: u8) -> &'static str {
    match value {
        1 => "standalone",
        2 => "kernel",
        3 => "ramdisk",
        4 => "multi",
        5 => "firmware",
        6 => "script",
        7 => "filesystem",
        8 => "flat_dt",
        14 => "kernel_noload",
        _ => "unknown",
    }
}
fn comp_name(value: u8) -> &'static str {
    match value {
        0 => "none",
        1 => "gzip",
        2 => "bzip2",
        3 => "lzma",
        4 => "lzo",
        5 => "lz4",
        6 => "zstd",
        _ => "unknown",
    }
}
fn member_name(image_type: u8) -> &'static str {
    match image_type {
        1 => "standalone.bin",
        2 | 14 => "kernel.bin",
        3 => "ramdisk.bin",
        5 => "firmware.bin",
        6 => "script.bin",
        7 => "filesystem.bin",
        8 => "fdt.bin",
        _ => "data.bin",
    }
}

/// The size-table/sub-image layout dumpimage round-trips: big-endian u32
/// lengths terminated by a zero, then the sub-images themselves, each one
/// padded up to the next 4-byte boundary (never trailing after the last).
fn multi_members(payload: &[u8], payload_start: usize) -> Result<Vec<Member>> {
    let mut sizes = Vec::new();
    let mut offset = 0usize;
    loop {
        let length = be32(payload, offset)? as usize;
        offset = add(offset, 4)?;
        if length == 0 {
            break;
        }
        if sizes.len() >= MAX_MEMBERS {
            return Err("too many uImage multi-file sub-images".into());
        }
        sizes.push(length);
    }
    let mut members = Vec::new();
    for (index, &length) in sizes.iter().enumerate() {
        get(payload, offset, length)?;
        members.push(Member {
            name: format!("data{index:02}.bin"),
            range: add(payload_start, offset)?..add(payload_start, add(offset, length)?)?,
        });
        offset = add(offset, length)?;
        let padding = (4 - (offset % 4)) % 4;
        offset = add(offset, padding)?;
    }
    Ok(members)
}

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let header = get(&data, 0, HEADER_SIZE)?;
    if header[..4] != *b"\x27\x05\x19\x56" {
        return Err("bad uImage magic".into());
    }
    let header_crc = be32(header, 4)?;
    let mut zeroed = [0_u8; HEADER_SIZE];
    zeroed.copy_from_slice(header);
    zeroed[4..8].fill(0);
    if crc32fast::hash(&zeroed) != header_crc {
        return Err("uImage header CRC32 mismatch".into());
    }
    let size = be32(header, 12)? as usize;
    let load = be32(header, 16)?;
    let entry = be32(header, 20)?;
    let data_crc = be32(header, 24)?;
    let os = header[28];
    let arch = header[29];
    let image_type = header[30];
    let compression = header[31];
    let name_end = header[32..64].iter().position(|&b| b == 0).unwrap_or(32);
    let name = String::from_utf8_lossy(&header[32..32 + name_end]).into_owned();

    let payload = get(&data, HEADER_SIZE, size)?;
    if crc32fast::hash(payload) != data_crc {
        return Err("uImage data CRC32 mismatch".into());
    }

    let members = if image_type == IH_TYPE_MULTI {
        multi_members(payload, HEADER_SIZE)?
    } else {
        vec![Member {
            name: member_name(image_type).into(),
            range: HEADER_SIZE..add(HEADER_SIZE, size)?,
        }]
    };
    let diagnostics = format!(
        "name={name} type={} os={os} arch={arch} compression={} load=0x{load:08x} entry=0x{entry:08x}",
        type_name(image_type),
        comp_name(compression),
    );
    Ok(Box::new(
        RangeArchive::new(data, members)?.with_diagnostics(diagnostics),
    ))
}

#[cfg(test)]
mod tests {
    use super::HEADER_SIZE;
    use crate::archive::Archive;
    const LEGACY: &[u8] = include_bytes!("../../../tests/fixtures/uboot_legacy/sample.img");
    const MULTI: &[u8] = include_bytes!("../../../tests/fixtures/uboot_legacy_multi/sample.img");

    /// Recompute ih_hcrc for a header edited in place, since the header CRC
    /// covers the whole 64-byte header (with ih_hcrc itself zeroed).
    fn fix_header_crc(data: &mut [u8]) {
        let mut zeroed: [u8; HEADER_SIZE] = data[..HEADER_SIZE].try_into().unwrap();
        zeroed[4..8].fill(0);
        data[4..8].copy_from_slice(&crc32fast::hash(&zeroed).to_be_bytes());
    }

    #[test]
    fn rejects_every_truncated_prefix() {
        for data in [LEGACY, MULTI] {
            for length in 0..data.len() {
                assert!(
                    Archive::open("uboot_legacy", data[..length].to_vec()).is_err(),
                    "prefix {length}"
                );
            }
        }
    }

    #[test]
    fn rejects_bad_magic_and_either_crc() {
        for offset in [0, 1, 2, 3, 4, 5, 6, 7, 64, 65] {
            let mut data = LEGACY.to_vec();
            data[offset] ^= 0xFF;
            assert!(
                Archive::open("uboot_legacy", data).is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn rejects_declared_size_past_the_buffer() {
        let mut data = LEGACY.to_vec();
        data[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        fix_header_crc(&mut data);
        assert!(Archive::open("uboot_legacy", data).is_err());
    }

    #[test]
    fn multi_file_entries_match_the_independent_dumpimage_split() {
        let archive = Archive::open("uboot_legacy", MULTI.to_vec()).unwrap();
        assert_eq!(archive.names(), ["data00.bin", "data01.bin", "data02.bin"]);
    }

    #[test]
    fn rejects_multi_table_missing_its_zero_terminator() {
        let mut data = MULTI.to_vec();
        // Overwrite the terminating zero (right after the three table entries)
        // so the scan runs past the declared payload without ever finding 0.
        data[64 + 12..64 + 16].copy_from_slice(&1_u32.to_be_bytes());
        let size = u32::from_be_bytes(data[12..16].try_into().unwrap()) as usize;
        let data_crc = crc32fast::hash(&data[64..64 + size]);
        data[24..28].copy_from_slice(&data_crc.to_be_bytes());
        fix_header_crc(&mut data);
        assert!(Archive::open("uboot_legacy", data).is_err());
    }

    #[test]
    fn single_image_member_name_follows_the_verified_type_byte() {
        let mut data = LEGACY.to_vec();
        data[30] = 3; // ramdisk
        fix_header_crc(&mut data);
        let archive = Archive::open("uboot_legacy", data).unwrap();
        assert_eq!(archive.names(), ["ramdisk.bin"]);
    }
}
