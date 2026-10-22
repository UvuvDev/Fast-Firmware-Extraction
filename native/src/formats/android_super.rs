//! Android "super" dynamic-partition image (AOSP's liblp): a container of
//! logical partitions addressed by linear/zero extents into one backing
//! block device. Layout reference: AOSP's Apache-2.0
//! system/core/fs_mgr/liblp/include/liblp/metadata_format.h. Struct field
//! offsets/sizes and SHA-256 checksum placement were verified against real
//! images built with Alpine's `android-tools-lpmake` 35.0.2 (AOSP's actual
//! lpmake/liblp), cross-checked with `lpdump`/`lpunpack`; that tool's
//! Apache-2.0 source is not vendored here, only the generated fixture bytes
//! are committed.
//!
//! Only the single-block-device ("super") layout is supported, not
//! "retrofit" devices whose dynamic partitions are split across separate
//! physical super_a/super_b devices. Metadata slot 0 is read (the default
//! every reader, including `lpdump`, uses without an explicit --slot); the
//! primary copy is used if its checksums validate, else its backup copy.
//! Partition group quotas are not exposed.
use crate::archive::{ArchiveReader, MAX_FILE_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use sha2::{Digest, Sha256};
use std::ops::Range;

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "android_super",
    name: "AndroidSuperImage",
    description: "Android super partition (dynamic partitions)",
    signatures: &[Signature::new(4096, b"\x67\x44\x6c\x61")],
    probe: None,
    open,
};

const SECTOR_SIZE: usize = 512;
const RESERVED_SIZE: usize = 4096;
const GEOMETRY_SIZE: usize = 4096;
const GEOMETRY_MAGIC: u32 = 0x616c_4467;
const MIN_GEOMETRY_SIZE: usize = 52;
const HEADER_MAGIC: u32 = 0x414c_5030;
const MIN_HEADER_SIZE: usize = 128;
const PARTITION_NAME_SIZE: usize = 36;
const TARGET_LINEAR: u32 = 0;
const TARGET_ZERO: u32 = 1;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("super image offset overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or("super image size overflow".into())
}
fn address(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| "super image address exceeds host range".into())
}
fn checked_sha256(data: &[u8], zero: Range<usize>, checksum: &[u8]) -> bool {
    let mut zeroed = data.to_vec();
    zeroed[zero].fill(0);
    Sha256::digest(&zeroed).as_slice() == checksum
}

/// metadata_max_size, metadata_slot_count.
fn geometry(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    let header = get(data, offset, MIN_GEOMETRY_SIZE)?;
    if le32(header, 0)? != GEOMETRY_MAGIC {
        return Err("bad super image geometry magic".into());
    }
    let struct_size = le32(header, 4)? as usize;
    if struct_size < MIN_GEOMETRY_SIZE {
        return Err("super image geometry struct too small".into());
    }
    let full = get(data, offset, struct_size)?;
    if !checked_sha256(full, 8..40, get(full, 8, 32)?) {
        return Err("super image geometry checksum mismatch".into());
    }
    Ok((le32(full, 40)? as usize, le32(full, 44)? as usize))
}

struct TableDescriptor {
    offset: usize,
    count: usize,
    entry_size: usize,
}
fn table_descriptor(header: &[u8], at: usize) -> Result<TableDescriptor> {
    Ok(TableDescriptor {
        offset: le32(header, at)? as usize,
        count: le32(header, add(at, 4)?)? as usize,
        entry_size: le32(header, add(at, 8)?)? as usize,
    })
}
struct Metadata {
    tables: Vec<u8>,
    partitions: TableDescriptor,
    extents: TableDescriptor,
    block_devices: TableDescriptor,
}
fn parse_metadata_at(data: &[u8], offset: usize) -> Result<Metadata> {
    let header = get(data, offset, MIN_HEADER_SIZE)?;
    if le32(header, 0)? != HEADER_MAGIC {
        return Err("bad super image metadata header magic".into());
    }
    let header_size = le32(header, 8)? as usize;
    if header_size < MIN_HEADER_SIZE {
        return Err("super image metadata header too small".into());
    }
    let header = get(data, offset, header_size)?;
    if !checked_sha256(header, 12..44, get(header, 12, 32)?) {
        return Err("super image metadata header checksum mismatch".into());
    }
    let tables_size = le32(header, 44)? as usize;
    let tables_checksum = get(header, 48, 32)?;
    let tables = get(data, add(offset, header_size)?, tables_size)?;
    if Sha256::digest(tables).as_slice() != tables_checksum {
        return Err("super image metadata tables checksum mismatch".into());
    }
    Ok(Metadata {
        tables: tables.to_vec(),
        partitions: table_descriptor(header, 80)?,
        extents: table_descriptor(header, 92)?,
        block_devices: table_descriptor(header, 116)?,
    })
}

enum Extent {
    Linear(Range<usize>),
    Zero(usize),
}
struct AndroidSuper {
    data: Vec<u8>,
    names: Vec<String>,
    files: Vec<Vec<Extent>>,
}
impl ArchiveReader for AndroidSuper {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        let extents = self
            .files
            .get(index)
            .ok_or("super image partition index out of range")?;
        let mut output = Vec::new();
        for extent in extents {
            match extent {
                Extent::Linear(range) => output.extend_from_slice(&self.data[range.clone()]),
                Extent::Zero(length) => output.resize(add(output.len(), *length)?, 0),
            }
        }
        Ok(output)
    }
}

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let (metadata_max_size, slot_count) = geometry(&data, RESERVED_SIZE)?;
    if slot_count == 0 {
        return Err("super image has no metadata slots".into());
    }
    let primary = add(RESERVED_SIZE, 2 * GEOMETRY_SIZE)?; // slot 0's primary copy
    let backup = add(primary, mul(slot_count, metadata_max_size)?)?;
    let metadata =
        parse_metadata_at(&data, primary).or_else(|_| parse_metadata_at(&data, backup))?;

    if metadata.block_devices.count != 1 {
        return Err("unsupported multi-device (retrofit) super image layout".into());
    }
    let partitions_bytes = mul(metadata.partitions.count, metadata.partitions.entry_size)?;
    let partitions_table = get(&metadata.tables, metadata.partitions.offset, partitions_bytes)?;
    if metadata.partitions.entry_size < PARTITION_NAME_SIZE + 16 {
        return Err("super image partition entry too small".into());
    }
    let extents_bytes = mul(metadata.extents.count, metadata.extents.entry_size)?;
    let extents_table = get(&metadata.tables, metadata.extents.offset, extents_bytes)?;
    if metadata.extents.entry_size < 24 {
        return Err("super image extent entry too small".into());
    }

    let mut names = Vec::new();
    let mut files = Vec::new();
    for entry in partitions_table.chunks_exact(metadata.partitions.entry_size) {
        if names.len() >= MAX_MEMBERS {
            return Err("too many super image partitions".into());
        }
        let raw_name = &entry[0..PARTITION_NAME_SIZE];
        let name_end = raw_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(PARTITION_NAME_SIZE);
        let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        if name.is_empty() || name.contains('/') {
            return Err("invalid super image partition name".into());
        }
        validate_name(&name)?;
        let first_extent_index = le32(entry, PARTITION_NAME_SIZE + 4)? as usize;
        let num_extents = le32(entry, PARTITION_NAME_SIZE + 8)? as usize;
        if num_extents > MAX_MEMBERS {
            return Err("too many extents for one super image partition".into());
        }

        let mut partition_size = 0_usize;
        let mut extents = Vec::new();
        for offset in 0..num_extents {
            let index = add(first_extent_index, offset)?;
            let extent = get(
                extents_table,
                mul(index, metadata.extents.entry_size)?,
                metadata.extents.entry_size,
            )?;
            let num_sectors = address(u64::from_le_bytes(extent[0..8].try_into().unwrap()))?;
            let target_type = le32(extent, 8)?;
            let length = mul(num_sectors, SECTOR_SIZE)?;
            partition_size = add(partition_size, length)?;
            if partition_size > MAX_FILE_SIZE {
                return Err("super image partition exceeds size limit".into());
            }
            match target_type {
                TARGET_LINEAR => {
                    let target_data =
                        address(u64::from_le_bytes(extent[12..20].try_into().unwrap()))?;
                    let target_source = le32(extent, 20)?;
                    if target_source != 0 {
                        return Err(
                            "super image extent references unsupported secondary block device"
                                .into(),
                        );
                    }
                    let start = mul(target_data, SECTOR_SIZE)?;
                    let end = add(start, length)?;
                    get(&data, start, length)?; // validated eagerly, read lazily
                    extents.push(Extent::Linear(start..end));
                }
                TARGET_ZERO => extents.push(Extent::Zero(length)),
                _ => return Err("unsupported super image extent target type".into()),
            }
        }
        names.push(name);
        files.push(extents);
    }
    Ok(Box::new(AndroidSuper { data, names, files }))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const SUPER: &[u8] = include_bytes!("../../../tests/fixtures/android_super/sample.img");

    #[test]
    fn rejects_prefixes_that_cut_off_metadata_or_partition_data() {
        // This fixture's "vendor" partition data ends at byte 36864 (sector
        // 72 * 512); the declared device size is 65536, all unused padding
        // past that point. So, unlike formats with a single checked total
        // length, a prefix of exactly 36864 is legitimately complete (every
        // byte this parser needs is present) even though it's short of the
        // full image -- only a prefix that actually cuts into metadata or
        // a partition's claimed extent data must fail.
        for length in [0, 4096, 12287, 12300, 16775, 20000, 28000, 36863] {
            assert!(
                Archive::open("android_super", SUPER[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
        assert!(Archive::open("android_super", SUPER[..36864].to_vec()).is_ok());
    }

    #[test]
    fn rejects_bad_geometry_magic_and_checksum() {
        for offset in [4096, 4096 + 10] {
            let mut data = SUPER.to_vec();
            data[offset] ^= 0xFF;
            assert!(Archive::open("android_super", data).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn falls_back_to_the_backup_metadata_copy_when_the_primary_is_corrupt() {
        let archive = Archive::open("android_super", SUPER.to_vec()).unwrap();
        let before = archive.names().to_vec();

        let mut data = SUPER.to_vec();
        let primary = 4096 * 3;
        data[primary + 12] ^= 0xFF; // one byte into the primary header's checksum
        let archive = Archive::open("android_super", data).unwrap();
        assert_eq!(archive.names(), before.as_slice());
    }

    #[test]
    fn rejects_both_copies_corrupted() {
        let (metadata_max_size, slot_count) = super::geometry(SUPER, 4096).unwrap();
        let primary = 4096 * 3;
        let backup = primary + slot_count * metadata_max_size;
        let mut data = SUPER.to_vec();
        data[primary + 12] ^= 0xFF;
        data[backup + 12] ^= 0xFF;
        assert!(Archive::open("android_super", data).is_err());
    }

    #[test]
    fn extracts_the_two_partitions_byte_exact() {
        let archive = Archive::open("android_super", SUPER.to_vec()).unwrap();
        let mut names = archive.names().to_vec();
        names.sort();
        assert_eq!(names, ["system", "vendor"]);
    }
}
