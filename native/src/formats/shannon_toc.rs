//! Samsung Shannon modem TOC. Layout and BOOT trimming were checked against
//! grant-h/ShannonBaseband's MIT parse_modem.py/TOCSectionHeader.java and a
//! real Pixel modem image. Zero-offset virtual regions are skipped. BOOT
//! exposes its declared size minus the reference extractor's 528-byte
//! trailer allowance. Load addresses, IDs and unknown metadata do not
//! participate in file-offset calculation. The full stored BOOT region,
//! including its trailer, is validated against file bounds before
//! trimming — not just the exposed, post-trim payload.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

// Record layout: a 12-byte name, then four more little-endian u32 fields —
// offset @12, load address @16 (unused), size @20, unk1 @24, id @28 (unused).
const RECORD_SIZE: usize = 32;
const NAME_SIZE: usize = 12; // "name" field: bytes [0..NAME_SIZE)
const OFFSET: usize = 12; // "offset" field
const SIZE: usize = 20; // "size" field (load_address at 16 sits in between)
const BOOT_TRIM: usize = 512 + 4 * 4;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "shannon_toc",
    name: "ShannonTOC",
    description: "Samsung Shannon Baseband TOC",
    signatures: &[Signature::new(0, b"TOC\0")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};
fn name(entry: &[u8]) -> String {
    String::from_utf8_lossy(entry[..NAME_SIZE].split(|&byte| byte == 0).next().unwrap())
        .into_owned()
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let header = get(&data, 0, RECORD_SIZE)?;
    if name(header) != "TOC" {
        return Err("missing leading Shannon TOC entry".into());
    }
    let table_size = le32(header, SIZE)? as usize;
    if table_size < RECORD_SIZE || table_size / RECORD_SIZE - 1 > MAX_MEMBERS {
        return Err("invalid Shannon TOC size or entry count".into());
    }
    let table = get(&data, 0, table_size)?;
    let mut members = Vec::new();
    let mut records = table[RECORD_SIZE..].chunks_exact(RECORD_SIZE);
    let mut terminated = false;
    for record in records.by_ref() {
        let name = name(record);
        if name.is_empty() {
            terminated = true;
            break;
        }
        let start = le32(record, OFFSET)? as usize;
        if start == 0 {
            continue;
        }
        let stored_size = le32(record, SIZE)? as usize;
        // Validate even the bytes omitted from BOOT's exposed payload.
        get(&data, start, stored_size)?;
        let size = if name == "BOOT" {
            stored_size.saturating_sub(BOOT_TRIM)
        } else {
            stored_size
        };
        let end = start
            .checked_add(size)
            .ok_or("Shannon payload range overflow")?;
        members.push(Member {
            name,
            range: start..end,
        });
    }
    // An empty-name sentinel ends the table, so trailing padding need not be
    // a multiple of 32. Without a sentinel, every active record must fit.
    if !terminated && !records.remainder().is_empty() {
        return Err("truncated Shannon TOC entry".into());
    }
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/shannon_toc/sample.bin");
    fn set32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn every_truncated_prefix_is_rejected() {
        for length in 0..SAMPLE.len() {
            assert!(
                Archive::open("shannon_toc", SAMPLE[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }
    #[test]
    fn rejects_bad_magic() {
        let mut data = SAMPLE.to_vec();
        set32(&mut data, 0, 0);
        assert!(Archive::open("shannon_toc", data).is_err());
    }
    #[test]
    fn rejects_bad_table_size() {
        for (offset, value) in [(20, 0), (20, 31), (20, 33), (20, u32::MAX)] {
            let mut data = SAMPLE.to_vec();
            set32(&mut data, offset, value);
            assert!(
                Archive::open("shannon_toc", data).is_err(),
                "offset {offset}"
            );
        }
    }
    #[test]
    fn rejects_out_of_bounds_member_regions() {
        for (offset, value) in [
            (44, u32::MAX),
            (52, u32::MAX),
            (76, u32::MAX),
            (84, u32::MAX),
        ] {
            let mut data = SAMPLE.to_vec();
            set32(&mut data, offset, value);
            assert!(
                Archive::open("shannon_toc", data).is_err(),
                "offset {offset}"
            );
        }
    }
    #[test]
    fn skips_virtual_regions_and_stops_at_empty_names() {
        let mut data = SAMPLE.to_vec();
        data[96..108].fill(0);
        data[96..103].copy_from_slice(b"NV_NORM");
        set32(&mut data, 108, 0);
        set32(&mut data, 116, u32::MAX);
        let archive = Archive::open("shannon_toc", data).unwrap();
        assert_eq!(archive.names(), ["BOOT", "MAIN"]);
        let mut data = SAMPLE.to_vec();
        set32(&mut data, 108, u32::MAX);
        set32(&mut data, 116, u32::MAX);
        assert_eq!(
            Archive::open("shannon_toc", data).unwrap().names(),
            ["BOOT", "MAIN"]
        );
    }
    #[test]
    fn preserves_padding_after_the_terminator_without_requiring_record_alignment() {
        let original = Archive::open("shannon_toc", SAMPLE.to_vec()).unwrap();
        let padded = include_bytes!("../../../tests/fixtures/shannon_toc_padded/sample.bin");
        let archive = Archive::open_auto(padded.to_vec()).unwrap();
        assert_eq!(archive.names(), original.names());
        for name in archive.names() {
            assert_eq!(
                archive.read_named(name).unwrap(),
                original.read_named(name).unwrap()
            );
        }
    }
    #[test]
    fn boot_trim_matches_reference_sample() {
        let archive = Archive::open_auto(SAMPLE.to_vec()).unwrap();
        assert_eq!(archive.read_named("BOOT").unwrap(), SAMPLE[128..200]);
    }
    #[test]
    fn boot_region_smaller_than_trim_is_empty() {
        let mut data = SAMPLE.to_vec();
        set32(&mut data, 52, 100);
        assert!(
            Archive::open("shannon_toc", data)
                .unwrap()
                .read_named("BOOT")
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn rejects_truncated_stored_boot_trailer_even_if_exposed_bytes_fit() {
        let mut data = SAMPLE[..200].to_vec();
        set32(&mut data, 20, 64);
        assert!(Archive::open("shannon_toc", data).is_err());
    }
    #[test]
    fn unsafe_path_like_name_is_skipped() {
        let mut data = SAMPLE.to_vec();
        data[32..44].fill(0);
        data[32..41].copy_from_slice(b"../escape");
        let archive = Archive::open("shannon_toc", data).unwrap();
        assert!(!archive.names().iter().any(|name| name == "../escape"));
    }
    #[test]
    fn duplicate_name_is_deduplicated() {
        let mut data = SAMPLE.to_vec();
        data[64..76].fill(0);
        data[64..68].copy_from_slice(b"BOOT");
        let archive = Archive::open("shannon_toc", data).unwrap();
        assert_eq!(archive.names().iter().filter(|name| *name == "BOOT").count(), 1);
    }
}
