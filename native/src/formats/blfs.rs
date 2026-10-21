//! BLFS v1 resource tables, layout measured in the real Cubs spacecraft ABL
//! through Binary Ninja MCP and independently extracted using record offsets.
//! Only the observed 32-byte header / 64-byte entry layout is supported; both
//! count fields must agree and reserved fields must be zero. No reference
//! implementation was copied. Recognizes standalone or bounded embedded tables.
use crate::archive::{ArchiveReader, MAX_FILE_SIZE, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, PROBE_LIMIT, Signature};
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "blfs",
    name: "Blfs",
    description: "BLFS v1 bootloader resources",
    signatures: &[Signature::new(0, b"sFlB"), Signature::embedded(b"sFlB")],
    probe: Some(|data| locate(data).is_some()),
    open,
};
fn geometry(data: &[u8], base: usize) -> Result<(usize, usize, usize)> {
    let header = get(data, base, 32)?;
    if &header[..4] != b"sFlB" || le32(header, 4)? != 1 {
        return Err("unsupported BLFS magic/version".into());
    }
    let count = le32(header, 8)? as usize;
    let total = le32(header, 16)? as usize;
    if count > MAX_MEMBERS
        || le32(header, 12)? as usize != count
        || header[20..].iter().any(|&b| b != 0)
    {
        return Err("unsupported BLFS count/reserved fields".into());
    }
    let table = count
        .checked_mul(64)
        .and_then(|n| n.checked_add(32))
        .ok_or("BLFS table overflow")?;
    if total < table || total > MAX_FILE_SIZE {
        return Err("invalid BLFS total/table size".into());
    }
    Ok((count, total, table))
}
fn locate(data: &[u8]) -> Option<usize> {
    if data.starts_with(b"sFlB") {
        return Some(0);
    }
    let prefix = &data[..data.len().min(PROBE_LIMIT)];
    prefix.windows(4).enumerate().find_map(|(offset, magic)| {
        if magic != b"sFlB" {
            return None;
        }
        let (_, _, table) = geometry(prefix, offset).ok()?;
        get(prefix, offset, table).ok()?;
        Some(offset)
    })
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let base = locate(&data).ok_or("no BLFS table within embedded scan limit")?;
    let (count, total, table) = geometry(&data, base)?;
    let archive = get(&data, base, total)?;
    let mut members = Vec::with_capacity(count);
    for record in get(archive, 32, count * 64)?.chunks_exact(64) {
        if record[56..].iter().any(|&b| b != 0) {
            return Err("unsupported BLFS entry flags/reserved fields".into());
        }
        let name =
            String::from_utf8_lossy(record[..48].split(|&b| b == 0).next().unwrap()).into_owned();
        let size = le32(record, 48)? as usize;
        let offset = le32(record, 52)? as usize;
        if offset < table {
            return Err("BLFS member overlaps metadata".into());
        }
        get(archive, offset, size)?;
        members.push(Member {
            name,
            range: base + offset..base + offset + size,
        });
    }
    let diagnostic = if base == 0 {
        String::new()
    } else {
        format!("BLFS: embedded resource table at {base:#x}, {total:#x} bytes")
    };
    let embedded = base != 0 || total != data.len();
    let mut reader = RangeArchive::new(data, members)?.with_diagnostics(diagnostic);
    if embedded {
        reader = reader.with_embedded_range(base..base + total);
    }
    Ok(Box::new(reader))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive::Archive, registry};
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/blfs/sample.blfs").to_vec()
    }
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn embedded_beyond_old_probe_limit_and_false_constants() {
        let mut data = vec![0xa5; 0x180000];
        data[20..24].copy_from_slice(b"sFlB");
        data.extend(sample());
        assert_eq!(registry::detect(&data).unwrap().id, "blfs");
        let archive = Archive::open_auto(data).unwrap();
        assert_eq!(archive.names().len(), 2);
        assert_eq!(
            archive.embedded_range(),
            Some(0x180000..0x180000 + sample().len())
        );
        assert!(archive.diagnostics().contains("0x180000"));
    }
    #[test]
    fn standalone_and_trailing_host_data() {
        let data = sample();
        let size = data.len();
        assert_eq!(
            Archive::open_auto(data.clone()).unwrap().embedded_range(),
            None
        );
        let mut host = data;
        host.extend(b"host image suffix");
        let archive = Archive::open_auto(host).unwrap();
        assert_eq!(archive.embedded_range(), Some(0..size));
    }
    #[test]
    fn rejects_versions_counts_and_reserved_fields() {
        for (offset, value) in [(4, 2), (8, u32::MAX), (12, 3), (20, 1), (32 + 56, 1)] {
            let mut data = sample();
            put32(&mut data, offset, value);
            assert!(open(data).is_err());
        }
    }
    #[test]
    fn rejects_metadata_overlap_truncation_and_member_overflow() {
        let mut data = sample();
        data.pop();
        assert!(open(data).is_err());
        for (offset, value) in [
            (16, 31),
            (32 + 52, 0),
            (32 + 48, u32::MAX),
            (32 + 52, u32::MAX),
        ] {
            let mut data = sample();
            put32(&mut data, offset, value);
            assert!(open(data).is_err());
        }
    }
    #[test]
    fn rejects_duplicate_and_unsafe_names() {
        let mut data = sample();
        data.copy_within(32..80, 96);
        assert!(Archive::open("blfs", data).is_err());
        let mut data = sample();
        data[32..80].fill(0);
        data[32..36].copy_from_slice(b"../x");
        assert!(Archive::open("blfs", data).is_err());
    }
    #[test]
    fn embedded_search_is_bounded() {
        let mut data = vec![0xa5; PROBE_LIMIT];
        data.extend(sample());
        assert!(locate(&data).is_none());
    }
}
