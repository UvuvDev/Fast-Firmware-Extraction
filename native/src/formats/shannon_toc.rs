//! Samsung Shannon modem TOC. Port of formats/shannon_toc.py, whose layout
//! and BOOT trimming were checked against grant-h/ShannonBaseband's MIT
//! parse_modem.py/TOCSectionHeader.java and a real Pixel modem image.
//! Zero-offset virtual regions are skipped. BOOT exposes its declared size
//! minus the reference extractor's 528-byte trailer allowance. Load addresses,
//! IDs and unknown metadata do not participate in file-offset calculation.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

const RECORD_SIZE: usize = 32;
const BOOT_TRIM: usize = 528;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "shannon_toc",
    name: "ShannonTOC",
    description: "Samsung Shannon Baseband TOC",
    signatures: &[Signature::new(0, b"TOC\0")],
    probe: None,
    open,
};
fn name(entry: &[u8]) -> String {
    String::from_utf8_lossy(entry[..12].split(|&byte| byte == 0).next().unwrap()).into_owned()
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let header = get(&data, 0, RECORD_SIZE)?;
    if name(header) != "TOC" {
        return Err("missing leading Shannon TOC entry".into());
    }
    let table_size = le32(header, 20)? as usize;
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
        let start = le32(record, 12)? as usize;
        if start == 0 {
            continue;
        }
        let stored_size = le32(record, 20)? as usize;
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
    fn rejects_bad_magic_table_lengths_and_all_region_bounds() {
        for (offset, value) in [
            (0, 0),
            (20, 0),
            (20, 31),
            (20, 33),
            (20, u32::MAX),
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
    fn boot_trim_matches_reference_and_small_regions_are_empty() {
        let archive = Archive::open_auto(SAMPLE.to_vec()).unwrap();
        assert_eq!(archive.read_named("BOOT").unwrap(), SAMPLE[128..200]);
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
    fn unsafe_and_duplicate_names_are_rejected() {
        let mut data = SAMPLE.to_vec();
        data[32..44].fill(0);
        data[32..41].copy_from_slice(b"../escape");
        assert!(Archive::open("shannon_toc", data).is_err());
        let mut data = SAMPLE.to_vec();
        data[64..76].fill(0);
        data[64..68].copy_from_slice(b"BOOT");
        assert!(Archive::open("shannon_toc", data).is_err());
    }
}
