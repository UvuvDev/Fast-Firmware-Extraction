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

#[cfg(test)]
mod tests {
    use crate::archive::Archive;

    fn slot_count(version: u32) -> usize {
        match version {
            1 => 3,
            2 => 4,
            other => panic!("unsupported test version {other}"),
        }
    }

    /// Build a valid TRX image: `version` selects the v1 (3-slot) or v2
    /// (4-slot) offset table, and each entry in `partitions` becomes one
    /// back-to-back partition packed right after the header, with a
    /// correct length/CRC32 so the buffer round-trips through `open`.
    fn build(version: u32, partitions: &[&[u8]]) -> Vec<u8> {
        let slots = slot_count(version);
        assert!(partitions.len() <= slots);
        let header_size = 16 + slots * 4;
        let mut offsets = vec![0u32; slots];
        let mut body = Vec::new();
        let mut offset = header_size;
        for (index, partition) in partitions.iter().enumerate() {
            offsets[index] = offset as u32;
            body.extend_from_slice(partition);
            offset += partition.len();
        }
        let total = offset as u32;
        let mut data = vec![0u8; header_size];
        data[0..4].copy_from_slice(b"HDR0");
        data[4..8].copy_from_slice(&total.to_le_bytes());
        data[12..16].copy_from_slice(&(version << 16).to_le_bytes());
        for (index, &value) in offsets.iter().enumerate() {
            data[16 + index * 4..20 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(&body);
        fix_crc(&mut data);
        data
    }

    /// Recompute the TRX CRC32, which covers everything from byte 12 to
    /// `total` (i.e. flags_version, the offset table and every partition).
    fn fix_crc(data: &mut [u8]) {
        let crc = crc32fast::hash(&data[12..]) ^ u32::MAX;
        data[8..12].copy_from_slice(&crc.to_le_bytes());
    }

    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn rejects_every_truncated_prefix() {
        let data = build(2, &[b"kernel-data", b"rootfs-data", b"partition-two", b"part-three"]);
        for length in 0..data.len() {
            assert!(
                Archive::open("trx", data[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_total_flags_version_and_crc_mutations() {
        let valid = build(1, &[b"kernel-data", b"rootfs-data"]);

        // `total` shrunk below the v1 header size.
        let mut data = valid.clone();
        put32(&mut data, 4, 4);
        assert!(Archive::open("trx", data).is_err());

        // `total` grown past the actual buffer length.
        let mut data = valid.clone();
        put32(&mut data, 4, valid.len() as u32 + 1000);
        assert!(Archive::open("trx", data).is_err());

        // `flags_version` claims an unsupported version (neither 1 nor 2).
        let mut data = valid.clone();
        put32(&mut data, 12, 3 << 16);
        assert!(Archive::open("trx", data).is_err());

        // Stored CRC32 flipped directly, body left untouched.
        let mut data = valid.clone();
        data[8] ^= 0xFF;
        assert!(Archive::open("trx", data).is_err());

        // A body byte flipped without recomputing the CRC32.
        let mut data = valid.clone();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        assert!(Archive::open("trx", data).is_err());
    }

    #[test]
    fn rejects_each_offset_slot_at_its_bounds() {
        for version in [1u32, 2] {
            let slots = slot_count(version);
            for index in 0..slots {
                let partitions: Vec<&[u8]> = (0..=index).map(|_| b"x".as_slice()).collect();
                let valid = build(version, &partitions);
                let header_size = 16 + slots * 4;
                let total = u32::from_le_bytes(valid[4..8].try_into().unwrap());
                let slot_at = 16 + index * 4;

                // Just below the header: too small to be a real partition offset.
                let mut data = valid.clone();
                put32(&mut data, slot_at, header_size as u32 - 1);
                fix_crc(&mut data);
                assert!(
                    Archive::open("trx", data).is_err(),
                    "version {version} slot {index} offset just under header_size"
                );

                // At `total`: no room left for any payload at or past end-of-image.
                let mut data = valid.clone();
                put32(&mut data, slot_at, total);
                fix_crc(&mut data);
                assert!(
                    Archive::open("trx", data).is_err(),
                    "version {version} slot {index} offset == total"
                );

                // Far past `total`: truncated/out-of-bounds offset.
                let mut data = valid.clone();
                put32(&mut data, slot_at, total + 1_000_000);
                fix_crc(&mut data);
                assert!(
                    Archive::open("trx", data).is_err(),
                    "version {version} slot {index} offset far past total"
                );
            }
        }
    }

    #[test]
    fn rejects_non_increasing_and_out_of_order_offsets() {
        // Slot 0's offset duplicated onto slot 1 (overlapping, non-increasing).
        let mut data = build(2, &[b"kernel-data", b"rootfs-data", b"two", b"three"]);
        let slot0 = u32::from_le_bytes(data[16..20].try_into().unwrap());
        put32(&mut data, 20, slot0);
        fix_crc(&mut data);
        assert!(Archive::open("trx", data).is_err());

        // Slots 0 and 1 swapped, so the table is strictly decreasing.
        let mut data = build(2, &[b"kernel-data", b"rootfs-data", b"two", b"three"]);
        let slot0 = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let slot1 = u32::from_le_bytes(data[20..24].try_into().unwrap());
        put32(&mut data, 16, slot1);
        put32(&mut data, 20, slot0);
        fix_crc(&mut data);
        assert!(Archive::open("trx", data).is_err());

        // A zero (empty) slot followed by a nonzero one: once an empty slot
        // is seen, every later slot must also stay empty (lines ~44-56).
        let mut data = build(1, &[b"kernel-data"]);
        let header_size = 16 + 3 * 4;
        // Slot 1 is already 0 here; force slot 2 nonzero behind it.
        put32(&mut data, 16 + 2 * 4, header_size as u32 + 4);
        fix_crc(&mut data);
        assert!(Archive::open("trx", data).is_err());
    }

    #[test]
    fn v1_and_v2_headers_use_a_different_slot_count() {
        // Same single partition, but v1's 3-slot header is 12 bytes shorter
        // than v2's 4-slot header, so the first partition starts 12 bytes
        // earlier for v1.
        let v1 = build(1, &[b"payload"]);
        let v2 = build(2, &[b"payload"]);
        assert_eq!(u32::from_le_bytes(v1[16..20].try_into().unwrap()), 28);
        assert_eq!(u32::from_le_bytes(v2[16..20].try_into().unwrap()), 32);

        let archive = Archive::open("trx", v1).unwrap();
        assert_eq!(archive.names(), ["partition_0.bin"]);
        assert_eq!(archive.read(0).unwrap(), b"payload");

        let archive = Archive::open("trx", v2).unwrap();
        assert_eq!(archive.names(), ["partition_0.bin"]);
        assert_eq!(archive.read(0).unwrap(), b"payload");

        // Relabel a v2 (4-slot, 32-byte header) image as v1: v1's header is
        // only 28 bytes, so the same bytes are sliced differently -- the
        // same 1 payload. The last 4 bytes of the v2 offset table (the
        // unused 4th slot, still zero) now fall after the v1 header and
        // before the payload, and show up as a distinct "prefix.bin" gap
        // rather than being read as a fourth offset slot.
        let mut relabeled = build(2, &[b"payload"]);
        put32(&mut relabeled, 12, 1 << 16);
        fix_crc(&mut relabeled);
        let archive = Archive::open("trx", relabeled).unwrap();
        assert_eq!(archive.names(), ["prefix.bin", "partition_0.bin"]);
        assert_eq!(archive.read(0).unwrap(), [0u8; 4]);
        assert_eq!(archive.read(1).unwrap(), b"payload");
    }

    #[test]
    fn v2_extracts_all_four_partitions_with_correct_ranges_and_names() {
        let kernel = vec![0xABu8; 16];
        let mut rootfs = b"hsqs".to_vec();
        rootfs.extend(std::iter::repeat_n(0u8, 12));
        let part2 = vec![0x11u8; 8];
        let part3 = vec![0x22u8; 20];
        let data = build(2, &[&kernel, &rootfs, &part2, &part3]);

        let archive = Archive::open("trx", data).unwrap();
        assert_eq!(
            archive.names(),
            ["partition_0.bin", "rootfs.squashfs", "partition_2.bin", "partition_3.bin"]
        );
        assert_eq!(archive.read(0).unwrap(), kernel);
        assert_eq!(archive.read(1).unwrap(), rootfs);
        assert_eq!(archive.read(2).unwrap(), part2);
        assert_eq!(archive.read(3).unwrap(), part3);
    }
}
