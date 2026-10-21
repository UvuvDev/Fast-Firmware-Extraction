//! Unisoc CP memory-decoupling modem images, fixed 8-region/50-word layout.
//! Port of formats/mecp.py, whose C alignment and load semantics were checked
//! against Unisoc u-boot15 cp_mem_decoupling.h/process_cp_coupling_info.c and
//! a Redmi A5 modem image. Only the modem partition and embedded bootstrap
//! live here; sibling DDR regions are diagnostics, not extractable files.
//! Optional AVB footer layout follows AOSP libavb/avb_footer.h (Apache-2.0).
//! vbmeta bytes are extracted without authenticating their signatures.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{be32, get, le32};
use crate::registry::{FormatDescriptor, Signature};
use std::ops::Range;

const MIN_HEADER: usize = 0x470;
const MAX_HEADER: usize = 0x600;
const REGIONS: usize = 0x1a0;
const BOOT_COUNT: usize = 0xd0;
const BOOT_CODE: usize = 0xd4;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "mecp",
    name: "UnisocMECP",
    description: "Unisoc CP memory-decoupling modem image",
    signatures: &[Signature::new(0, b"MECP")],
    probe: None,
    open,
};
fn name(data: &[u8]) -> String {
    String::from_utf8_lossy(data.split(|&byte| byte == 0).next().unwrap()).into_owned()
}
fn le64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        get(data, offset, 8)?.try_into().unwrap(),
    ))
}
fn be64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        get(data, offset, 8)?.try_into().unwrap(),
    ))
}
struct Footer {
    original_size: usize,
    vbmeta: Range<usize>,
}
fn footer(data: &[u8]) -> Result<Option<Footer>> {
    if data.len() < 64 {
        return Ok(None);
    }
    let start = data.len() - 64;
    let record = &data[start..];
    if &record[..4] != b"AVBf" {
        return Ok(None);
    }
    if be32(record, 4)? != 1 {
        return Err("unsupported AVB footer major version".into());
    }
    let original = be64(record, 12)?;
    if original == 0 || original > start as u64 {
        return Err("invalid AVB original image size".into());
    }
    let offset = be64(record, 20)?;
    let size = be64(record, 28)?;
    let vbmeta = if size == 0 {
        0..0
    } else {
        let end = offset
            .checked_add(size)
            .ok_or("AVB vbmeta range overflow")?;
        if offset < original || end > start as u64 {
            return Err("AVB vbmeta range overlaps image/footer or exceeds input".into());
        }
        offset as usize..end as usize
    };
    Ok(Some(Footer {
        original_size: original as usize,
        vbmeta,
    }))
}
fn flag(value: u32) -> &'static str {
    match value {
        0 => "ignore",
        1 => "load",
        2 => "clear",
        3 => "dump",
        4 => "reg",
        _ => "unknown",
    }
}
fn diagnostics(
    data: &[u8],
    modem: &[u8],
    header: usize,
    image_end: usize,
    avb: Option<&Footer>,
) -> Result<String> {
    let base = le64(modem, 24)?;
    let load = base
        .checked_add(header as u64)
        .ok_or("MECP payload load address overflow")?;
    let version = if data[..8].iter().all(|&byte| (32..127).contains(&byte)) {
        String::from_utf8_lossy(&data[..8]).into_owned()
    } else {
        format!("MECP({:#010x})", le32(data, 4)?)
    };
    let mut text = format!(
        "MECP: {version} header {header:#x} bytes, payload {header:#x}..{image_end:#x}\nMECP: modem child loads at {load:#x} (region base {base:#x})\n"
    );
    for (label, offset, count, stride) in [
        ("reserved", 0x10, 4, 48),
        ("region", REGIONS, 8, 48),
        ("boot res", 0x320, 4, 40),
        ("comm res", 0x3c8, 4, 40),
    ] {
        for record in get(data, offset, count * stride)?.chunks_exact(stride) {
            let name = name(&record[..20]);
            if name.is_empty() {
                continue;
            }
            text.push_str(&format!(
                "MECP: {label} {name:?} base {:#x} size {:#x}",
                le64(record, 24)?,
                le32(record, 32)?
            ));
            if stride == 48 {
                let value = le32(record, 40)?;
                text.push_str(&format!(" {} ({value})", flag(value)));
            }
            text.push('\n');
        }
    }
    if let Some(avb) = avb {
        text.push_str(&format!(
            "MECP: AVB original size {:#x}, vbmeta {:#x}..{:#x}\n",
            avb.original_size, avb.vbmeta.start, avb.vbmeta.end
        ));
    }
    Ok(text)
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if get(&data, 0, 4)? != b"MECP" {
        return Err("bad MECP magic".into());
    }
    let header = le32(&data, 8)? as usize;
    if !(MIN_HEADER..=MAX_HEADER).contains(&header) {
        return Err("invalid MECP header length/layout".into());
    }
    get(&data, 0, header)?;
    let count = le32(&data, BOOT_COUNT)? as usize;
    if count > 50 {
        return Err("MECP bootstrap count exceeds supported layout".into());
    }
    let regions = get(&data, REGIONS, 8 * 48)?;
    let modem = regions
        .chunks_exact(48)
        .find(|record| name(&record[..20]) == "modem")
        .ok_or("MECP modem region not found")?;
    if le32(modem, 40)? != 1 {
        return Err("MECP modem region is not load_t".into());
    }
    let avb = footer(&data)?;
    // Without AVB, this size is a DDR reservation/read limit, not an exact
    // on-disk length. Preserve the legacy bounded-to-input fallback.
    let image_end = avb
        .as_ref()
        .map_or((le32(modem, 32)? as usize).min(data.len()), |footer| {
            footer.original_size
        });
    if image_end <= header {
        return Err("MECP image contains no modem payload after the header".into());
    }
    let mut members = vec![Member {
        name: "modem".into(),
        range: header..image_end,
    }];
    if count > 0 {
        members.push(Member {
            name: "cp_bootcode".into(),
            range: BOOT_CODE..BOOT_CODE + count * 4,
        });
    }
    if let Some(footer) = &avb
        && !footer.vbmeta.is_empty()
    {
        members.push(Member {
            name: "vbmeta".into(),
            range: footer.vbmeta.clone(),
        });
    }
    let message = diagnostics(&data, modem, header, image_end, avb.as_ref())?;
    Ok(Box::new(
        RangeArchive::new(data, members)?.with_diagnostics(message),
    ))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/mecp/sample.img");
    const RAW: &[u8] = include_bytes!("../../../tests/fixtures/mecp_no_avb/sample.img");
    fn set32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn rejects_truncated_headers_bad_layouts_and_missing_payload() {
        for length in 0..=1536 {
            assert!(Archive::open("mecp", SAMPLE[..length].to_vec()).is_err());
        }
        for (offset, value) in [
            (0, 0),
            (8, 0),
            (8, 0x46f),
            (8, 0x601),
            (0xd0, 51),
            (0x1c8, 2),
        ] {
            let mut data = RAW.to_vec();
            set32(&mut data, offset, value);
            assert!(Archive::open("mecp", data).is_err());
        }
        let mut data = RAW.to_vec();
        data[0x1a0..0x1b4].fill(0);
        assert!(Archive::open("mecp", data).is_err());
    }
    #[test]
    fn rejects_invalid_avb_sizes_versions_and_vbmeta_ranges() {
        let start = SAMPLE.len() - 64;
        for (offset, value) in [
            (4, 2_u64),
            (12, 0),
            (12, u64::MAX),
            (20, u64::MAX),
            (20, 1),
            (28, u64::MAX),
        ] {
            let mut data = SAMPLE.to_vec();
            if offset == 4 {
                data[start + offset..start + offset + 4]
                    .copy_from_slice(&(value as u32).to_be_bytes());
            } else {
                data[start + offset..start + offset + 8].copy_from_slice(&value.to_be_bytes());
            }
            assert!(
                Archive::open("mecp", data).is_err(),
                "footer offset {offset}"
            );
        }
    }
    #[test]
    fn preserves_large_reserved_size_fallback_and_optional_bootstrap() {
        let mut data = RAW.to_vec();
        set32(&mut data, 0x1c0, u32::MAX);
        set32(&mut data, 0xd0, 0);
        let archive = Archive::open_auto(data).unwrap();
        assert_eq!(archive.names(), ["modem"]);
        assert_eq!(archive.read(0).unwrap(), RAW[1536..]);
    }
    #[test]
    fn exposes_only_embedded_regions_and_reports_the_adjusted_load_address() {
        let archive = Archive::open_auto(SAMPLE.to_vec()).unwrap();
        assert_eq!(archive.names(), ["modem", "cp_bootcode", "vbmeta"]);
        assert_eq!(archive.read(0).unwrap(), SAMPLE[1536..2560]);
        assert_eq!(archive.read(1).unwrap(), SAMPLE[0xd4..0xe4]);
        assert_eq!(archive.read(2).unwrap(), SAMPLE[4096..4160]);
        assert!(
            archive
                .diagnostics()
                .contains("modem child loads at 0x8b000600")
        );
        assert!(archive.diagnostics().contains("gdsp"));
        assert!(archive.diagnostics().contains("comm res"));
    }
    #[test]
    fn rejects_overflowing_modem_load_address() {
        let mut data = RAW.to_vec();
        data[0x1b8..0x1c0].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Archive::open("mecp", data).is_err());
    }
}
