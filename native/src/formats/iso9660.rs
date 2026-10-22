//! ISO 9660 (ECMA-119) optical disc images, with Joliet and Rock Ridge name
//! extensions. Volume descriptor/directory record field offsets (including
//! ECMA-119's "both-endian" 32/16-bit fields) and the Joliet escape sequence
//! and Rock Ridge SUSP entry layout (SP/PX/TF/NM) were verified against real
//! images built with Homebrew's `xorriso` 1.5.8 (`-as mkisofs`), independent
//! GPL-3.0 software not vendored here; only the generated fixture bytes are
//! committed, the same policy already used for every other producer tool in
//! this project. ECMA-119 and the Rock Ridge/SUSP specifications are public,
//! royalty-free standards.
//!
//! Only a 2048-byte logical block size is supported (the universal case for
//! CD/DVD media). A regular file's directory record must not have the
//! multi-extent flag set (files split across several records, generally
//! only seen well past 4 GiB, are unsupported). Rock Ridge continuation
//! areas ("CE" entries, used when a record's own system-use area is too
//! small) are not followed, so a name split into a CE is read truncated.
//!
//! Name resolution picks one tree, in priority order: a Supplementary
//! Volume Descriptor carrying the Joliet escape sequence (simple UTF-16BE
//! names, no Rock Ridge needed), else the Primary Volume Descriptor's tree,
//! reading each record's Rock Ridge "NM" name if present, else its plain
//! ISO 9660 name with the ";version" suffix stripped. El Torito boot
//! images and multiple sessions are not inspected.
use crate::archive::{
    ArchiveReader, LARGE_CONTAINER_MAX_SIZE, MAX_MEMBERS, Member, RangeArchive, Result,
    validate_name,
};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use std::collections::HashSet;

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "iso9660",
    name: "Iso9660",
    description: "ISO 9660 optical disc image (Joliet/Rock Ridge)",
    signatures: &[Signature::new(16 * SECTOR_SIZE + 1, b"CD001")],
    probe: None,
    open,
    max_input_size: Some(LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(LARGE_CONTAINER_MAX_SIZE),
};

const SECTOR_SIZE: usize = 2048;
const VOLUME_DESCRIPTORS_START: usize = 16 * SECTOR_SIZE;
const STANDARD_IDENTIFIER: &[u8] = b"CD001";
const TYPE_PRIMARY: u8 = 1;
const TYPE_SUPPLEMENTARY: u8 = 2;
const TYPE_TERMINATOR: u8 = 255;
const ROOT_RECORD_OFFSET: usize = 156;
const MIN_RECORD_SIZE: usize = 34;
const FLAG_DIRECTORY: u8 = 0x02;
const FLAG_MULTI_EXTENT: u8 = 0x80;
const JOLIET_ESCAPES: [[u8; 3]; 3] = [
    [0x25, 0x2f, 0x40], // UCS-2 level 1
    [0x25, 0x2f, 0x43], // UCS-2 level 2
    [0x25, 0x2f, 0x45], // UCS-2 level 3
];

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("ISO 9660 offset overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or("ISO 9660 size overflow".into())
}
fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(get(data, offset, 2)?.try_into().unwrap()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NameSource {
    Joliet,
    Primary,
}

fn decode_utf16be(bytes: &[u8]) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err("odd-length Joliet name".into());
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}
fn strip_version(name: &str) -> String {
    name.rfind(';').map_or(name, |i| &name[..i]).to_string()
}
/// Concatenates every Rock Ridge "NM" (POSIX name) entry's payload found in
/// a record's system-use area; `None` if there is none.
fn rock_ridge_name(system_use: &[u8]) -> Option<String> {
    let mut pos = 0;
    let mut name = Vec::new();
    let mut found = false;
    while pos + 4 <= system_use.len() {
        let length = system_use[pos + 2] as usize;
        if length < 4 || pos + length > system_use.len() {
            break;
        }
        if &system_use[pos..pos + 2] == b"NM" && length >= 5 {
            name.extend_from_slice(&system_use[pos + 5..pos + length]);
            found = true;
        }
        pos += length;
    }
    found.then(|| String::from_utf8_lossy(&name).into_owned())
}

struct Entry {
    name: String,
    extent: usize,
    size: usize,
    is_directory: bool,
}
/// Parses one directory record, returning `None` for "." and "..".
fn parse_record(record: &[u8], source: NameSource) -> Result<Option<Entry>> {
    let name_len = *record.get(32).ok_or("truncated ISO 9660 directory record")? as usize;
    let name_bytes = get(record, 33, name_len)?;
    if matches!(name_bytes, [0] | [1]) {
        return Ok(None);
    }
    let flags = record[25];
    if flags & FLAG_MULTI_EXTENT != 0 {
        return Err("multi-extent ISO 9660 records are not supported".into());
    }
    let mut system_use_start = add(33, name_len)?;
    if !system_use_start.is_multiple_of(2) {
        system_use_start = add(system_use_start, 1)?;
    }
    let name = match source {
        NameSource::Joliet => decode_utf16be(name_bytes)?,
        NameSource::Primary => record
            .get(system_use_start..)
            .and_then(rock_ridge_name)
            .unwrap_or_else(|| strip_version(&String::from_utf8_lossy(name_bytes))),
    };
    Ok(Some(Entry {
        name,
        extent: le32(record, 2)? as usize,
        size: le32(record, 10)? as usize,
        is_directory: flags & FLAG_DIRECTORY != 0,
    }))
}
fn read_directory(data: &[u8], extent: usize, size: usize, source: NameSource) -> Result<Vec<Entry>> {
    let bytes = get(data, mul(extent, SECTOR_SIZE)?, size).map_err(|_| {
        "ISO 9660 directory extent exceeds the buffer (bad or damaged volume descriptor)"
    })?;
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let length = bytes[pos] as usize;
        if length == 0 {
            // No more records in this logical block; resume at the next one.
            pos = add(pos / SECTOR_SIZE, 1)?.checked_mul(SECTOR_SIZE).ok_or("ISO 9660 offset overflow")?;
            continue;
        }
        if length < MIN_RECORD_SIZE {
            return Err("ISO 9660 directory record shorter than its minimum size".into());
        }
        let record = get(bytes, pos, length)?;
        if let Some(entry) = parse_record(record, source)? {
            entries.push(entry);
        }
        pos = add(pos, length)?;
    }
    Ok(entries)
}

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let mut pos = VOLUME_DESCRIPTORS_START;
    let mut primary_root = None;
    let mut joliet_root = None;
    loop {
        let descriptor = get(&data, pos, SECTOR_SIZE)?;
        if &descriptor[1..6] != STANDARD_IDENTIFIER {
            return Err("bad ISO 9660 standard identifier".into());
        }
        let volume_type = descriptor[0];
        if volume_type == TYPE_TERMINATOR {
            break;
        }
        if volume_type == TYPE_PRIMARY || volume_type == TYPE_SUPPLEMENTARY {
            if descriptor[6] != 1 {
                return Err("unsupported ISO 9660 volume descriptor version".into());
            }
            if u16le(descriptor, 128)? != SECTOR_SIZE as u16 {
                return Err("unsupported ISO 9660 logical block size".into());
            }
            let volume_space_size = le32(descriptor, 80)? as usize;
            if mul(volume_space_size, SECTOR_SIZE)? > data.len() {
                return Err("ISO 9660 volume space size exceeds the buffer".into());
            }
            let root = get(descriptor, ROOT_RECORD_OFFSET, MIN_RECORD_SIZE)?;
            let root = (le32(root, 2)? as usize, le32(root, 10)? as usize);
            if volume_type == TYPE_PRIMARY {
                if primary_root.is_some() {
                    return Err("multiple ISO 9660 primary volume descriptors".into());
                }
                primary_root = Some(root);
            } else if joliet_root.is_none()
                && JOLIET_ESCAPES.iter().any(|escape| descriptor[88..91] == *escape)
            {
                joliet_root = Some(root);
            }
        }
        pos = add(pos, SECTOR_SIZE)?;
    }
    let (source, (root_extent, root_size)) = match joliet_root {
        Some(root) => (NameSource::Joliet, root),
        None => (
            NameSource::Primary,
            primary_root.ok_or("no ISO 9660 primary volume descriptor found")?,
        ),
    };

    let mut members = Vec::new();
    let mut pending = vec![(String::new(), root_extent, root_size, 0_u32)];
    let mut visited = HashSet::new();
    let mut count = 0;
    while let Some((path, extent, size, depth)) = pending.pop() {
        count += 1;
        if count > MAX_MEMBERS || depth > 256 {
            return Err("ISO 9660 traversal limit exceeded".into());
        }
        if !visited.insert(extent) {
            return Err("ISO 9660 directory cycle or repeated directory".into());
        }
        for entry in read_directory(&data, extent, size, source)?.into_iter().rev() {
            if entry.name.is_empty() || entry.name.contains('/') {
                return Err("invalid ISO 9660 entry name".into());
            }
            let full = if path.is_empty() {
                entry.name
            } else {
                format!("{path}/{}", entry.name)
            };
            validate_name(&full)?;
            if pending.len() + count >= MAX_MEMBERS {
                return Err("too many ISO 9660 entries".into());
            }
            if entry.is_directory {
                pending.push((full, entry.extent, entry.size, depth + 1));
            } else {
                let start = mul(entry.extent, SECTOR_SIZE)?;
                let end = add(start, entry.size)?;
                get(&data, start, entry.size)?;
                members.push(Member { name: full, range: start..end });
            }
        }
    }
    Ok(Box::new(RangeArchive::new_with_file_size_limit(
        data,
        members,
        LARGE_CONTAINER_MAX_SIZE,
    )?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const ISO: &[u8] = include_bytes!("../../../tests/fixtures/iso9660/sample.iso");
    const ROCK_RIDGE_ONLY: &[u8] =
        include_bytes!("../../../tests/fixtures/iso9660_rockridge_only/sample.iso");

    #[test]
    fn rejects_every_truncated_prefix() {
        for length in (0..ISO.len()).step_by(2048).chain([ISO.len() - 1]) {
            assert!(
                Archive::open("iso9660", ISO[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_bad_standard_identifier_and_version() {
        for offset in [16 * 2048 + 1, 16 * 2048 + 6] {
            let mut data = ISO.to_vec();
            data[offset] ^= 0xFF;
            assert!(Archive::open("iso9660", data).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn prefers_joliet_names_when_present() {
        let archive = Archive::open("iso9660", ISO.to_vec()).unwrap();
        let mut names = archive.names().to_vec();
        names.sort();
        assert_eq!(names, ["big.bin", "small.txt", "subdir/nested.txt"]);
    }

    #[test]
    fn falls_back_to_rock_ridge_names_without_joliet() {
        let archive = Archive::open("iso9660", ROCK_RIDGE_ONLY.to_vec()).unwrap();
        let mut names = archive.names().to_vec();
        names.sort();
        assert_eq!(names, ["big.bin", "small.txt", "subdir/nested.txt"]);
    }

    #[test]
    fn falls_back_to_the_plain_stripped_name_without_rock_ridge_either() {
        // Corrupt the "NM" (POSIX name) SUSP entry's own signature for
        // small.txt, so rock_ridge_name() no longer recognizes it; the
        // plain ISO 9660 name (uppercase, ";version" suffix stripped)
        // must be used instead.
        let mut data = ROCK_RIDGE_ONLY.to_vec();
        let needle = [0x4e, 0x4d, 0x0e, 0x01, 0x00]
            .into_iter()
            .chain(*b"small.txt")
            .collect::<Vec<u8>>();
        let position = data
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("fixture must have an NM entry for small.txt");
        data[position] = b'X'; // breaks the "NM" signature match
        let archive = Archive::open("iso9660", data).unwrap();
        assert!(archive.names().contains(&"SMALL.TXT".to_string()));
    }

    #[test]
    fn rejects_a_directory_cycle() {
        // Point "subdir"'s own extent at the root's extent instead of its
        // real one, forming a cycle once the traversal revisits root.
        let mut data = ROCK_RIDGE_ONLY.to_vec();
        let pvd = &data[16 * 2048..17 * 2048];
        let root_extent = u32::from_le_bytes(pvd[156 + 2..156 + 6].try_into().unwrap());
        let root_dir = data[root_extent as usize * 2048..root_extent as usize * 2048 + 2048].to_vec();
        // Find the "SUBDIR" record (plain name, no Rock Ridge dependency
        // needed to locate it: scan for the raw bytes).
        let needle = b"SUBDIR";
        let pos = root_dir
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        let record_start = pos - 33; // name begins at offset 33 within its record
        let extent_field = root_extent as usize * 2048 + record_start + 2;
        data[extent_field..extent_field + 4].copy_from_slice(&root_extent.to_le_bytes());
        data[extent_field + 6..extent_field + 10].copy_from_slice(&root_extent.to_be_bytes());
        assert!(Archive::open("iso9660", data).is_err());
    }
}
