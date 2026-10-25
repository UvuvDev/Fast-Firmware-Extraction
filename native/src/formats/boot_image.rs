//! Android boot v0-v4 and vendor_boot v3-v4, without temporary files.
//! Layout and extraction names follow the Apache-2.0 AOSP unpack_bootimg.py
//! vendored in third_party/aosp_mkbootimg. Official mkbootimg-generated fixtures
//! are round-tripped with that independent unpacker. Stored segments are
//! returned verbatim; boot signatures are extracted, not authenticated.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "boot_image",
    name: "AndroidBootImage",
    description: "Android Boot / Vendor Boot Image",
    signatures: &[
        Signature::new(0, b"ANDROID!"),
        Signature::new(0, b"VNDRBOOT"),
    ],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("boot image offset overflow".into())
}
fn align(value: usize, page: usize) -> Result<usize> {
    Ok(add(value, page - 1)? & !(page - 1))
}
fn word64(data: &[u8], offset: usize) -> Result<usize> {
    // Only rejects on 32-bit targets; usize == u64 on every target this crate builds for today.
    usize::try_from(u64::from_le_bytes(
        get(data, offset, 8)?.try_into().unwrap(),
    ))
    .map_err(|_| "boot image offset exceeds address space".into())
}
fn member(name: &str, start: usize, size: usize) -> Result<Member> {
    Ok(Member {
        name: name.into(),
        range: start..add(start, size)?,
    })
}
fn valid_page(page: usize) -> Result<()> {
    if !page.is_power_of_two() || !(512..=1048576).contains(&page) {
        return Err("invalid boot image page size".into());
    }
    Ok(())
}
fn boot(data: &[u8]) -> Result<Vec<Member>> {
    let version = le32(data, 40)?;
    let minimum = match version {
        0 => 1632,
        1 => 1648,
        2 => 1660,
        3 => 1580,
        4 => 1584,
        _ => return Err("unsupported boot header version".into()),
    };
    get(data, 0, minimum)?;
    let page = if version < 3 {
        le32(data, 36)? as usize
    } else {
        4096
    };
    valid_page(page)?;
    if page < minimum {
        return Err("boot header exceeds its page".into());
    }
    get(data, 0, page)?;
    let kernel = le32(data, 8)? as usize;
    let ramdisk = le32(data, if version < 3 { 16 } else { 12 })? as usize;
    let ramdisk_start = add(page, align(kernel, page)?)?;
    let mut members = vec![
        member("kernel", page, kernel)?,
        member("ramdisk", ramdisk_start, ramdisk)?,
    ];
    let after_ramdisk = add(ramdisk_start, align(ramdisk, page)?)?;
    if version < 3 {
        let second = le32(data, 24)? as usize;
        if second > 0 {
            members.push(member("second", after_ramdisk, second)?);
        }
        let recovery = if version >= 1 {
            le32(data, 1632)? as usize
        } else {
            0
        };
        if recovery > 0 {
            members.push(member("recovery_dtbo", word64(data, 1636)?, recovery)?);
        }
        if version == 2 {
            let dtb = le32(data, 1648)? as usize;
            let start = add(
                add(after_ramdisk, align(second, page)?)?,
                align(recovery, page)?,
            )?;
            if dtb > 0 {
                members.push(member("dtb", start, dtb)?);
            }
        }
    } else if version == 4 {
        let signature = le32(data, 1580)? as usize;
        if signature > 0 {
            members.push(member("boot_signature", after_ramdisk, signature)?);
        }
    }
    Ok(members)
}
fn vendor(data: &[u8]) -> Result<Vec<Member>> {
    let version = le32(data, 8)?;
    let minimum = match version {
        3 => 2112,
        4 => 2128,
        _ => return Err("unsupported vendor boot header version".into()),
    };
    get(data, 0, minimum)?;
    let page = le32(data, 12)? as usize;
    valid_page(page)?;
    let header_size = le32(data, 2096)? as usize;
    if header_size < minimum {
        return Err("vendor boot header too small".into());
    }
    get(data, 0, header_size)?;
    let ramdisk_start = align(header_size, page)?;
    let ramdisk_size = le32(data, 24)? as usize;
    get(data, ramdisk_start, ramdisk_size)?;
    let dtb_start = add(ramdisk_start, align(ramdisk_size, page)?)?;
    let dtb_size = le32(data, 2100)? as usize;
    let mut members = Vec::new();
    if version == 3 {
        members.push(member("vendor_ramdisk", ramdisk_start, ramdisk_size)?);
    } else {
        let table_size = le32(data, 2112)? as usize;
        let count = le32(data, 2116)? as usize;
        let stride = le32(data, 2120)? as usize;
        let config_size = le32(data, 2124)? as usize;
        if stride < 108 || count > MAX_MEMBERS - 2 || count > table_size / stride {
            return Err("invalid vendor ramdisk table size/count/stride".into());
        }
        let table_start = add(dtb_start, align(dtb_size, page)?)?;
        let table = get(data, table_start, table_size)?;
        for index in 0..count {
            let entry = get(table, index * stride, 108)?;
            let size = le32(entry, 0)? as usize;
            let offset = le32(entry, 4)? as usize;
            if add(offset, size)? > ramdisk_size {
                return Err("vendor fragment exceeds ramdisk area".into());
            }
            members.push(member(
                &format!("vendor_ramdisk{index:02}"),
                add(ramdisk_start, offset)?,
                size,
            )?);
        }
        let config_start = add(table_start, align(table_size, page)?)?;
        members.push(member("bootconfig", config_start, config_size)?);
    }
    if dtb_size > 0 {
        members.push(member("dtb", dtb_start, dtb_size)?);
    }
    Ok(members)
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let members = match get(&data, 0, 8)? {
        b"ANDROID!" => boot(&data)?,
        b"VNDRBOOT" => vendor(&data)?,
        _ => return Err("bad boot image magic".into()),
    };
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const BOOT: &[u8] = include_bytes!("../../../tests/fixtures/boot_image_v3/sample.img");
    const VENDOR: &[u8] = include_bytes!("../../../tests/fixtures/vendor_boot_v3/sample.img");
    fn set32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    // Shortest prefix of `data` that still opens, found via the public API
    // alone (no assumption about where any given fixture's members land).
    fn minimal_valid_length(data: &[u8]) -> usize {
        let (mut lo, mut hi) = (1usize, data.len());
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if Archive::open("boot_image", data[..mid].to_vec()).is_ok() {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    }
    // Byte offset of the v4 vendor ramdisk table, walking the same
    // page-aligned layout `vendor()` does, from the fixture's own header
    // fields (page size, header size, ramdisk size, dtb size).
    fn vendor_v4_table_offset(data: &[u8]) -> usize {
        let field = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        let page = field(12);
        let align = |v: usize| (v + page - 1) & !(page - 1);
        let dtb_start = align(field(2096)) + align(field(24));
        dtb_start + align(field(2100))
    }
    #[test]
    fn rejects_truncated_headers_and_payloads() {
        for data in [BOOT, VENDOR] {
            for length in [0, 7, 43, 100, 1000, 4095] {
                assert!(Archive::open("boot_image", data[..length].to_vec()).is_err());
            }
            let minimal = minimal_valid_length(data);
            assert!(Archive::open("boot_image", data[..minimal - 1].to_vec()).is_err());
        }
    }
    #[test]
    fn rejects_unsupported_versions_oversized_segments_and_bad_pages() {
        for (sample, offset, value) in [
            (BOOT, 40, 5),
            (BOOT, 8, u32::MAX),
            (BOOT, 12, u32::MAX),
            (VENDOR, 8, 5),
            (VENDOR, 12, 0),
            (VENDOR, 12, 3),
            (VENDOR, 2096, 1),
            (VENDOR, 24, u32::MAX),
        ] {
            let mut data = sample.to_vec();
            set32(&mut data, offset, value);
            assert!(Archive::open("boot_image", data).is_err());
        }
    }

    const VENDOR4: &[u8] = include_bytes!("../../../tests/fixtures/vendor_boot_aosp_v4/sample.img");
    #[test]
    fn rejects_v4_table_overflows_and_fragments_outside_ramdisk_area() {
        let table = vendor_v4_table_offset(VENDOR4);
        for (offset, value) in [
            (2112, 1),
            (2116, u32::MAX),
            (2120, 0),
            (2120, 107),
            (2112, u32::MAX),
            (table + 4, 4096),
            (table, u32::MAX),
        ] {
            let mut data = VENDOR4.to_vec();
            set32(&mut data, offset, value);
            assert!(
                Archive::open("boot_image", data).is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn supports_extended_vendor_entry_stride_and_ignores_unsafe_display_names() {
        let table = vendor_v4_table_offset(VENDOR4);
        let mut data = VENDOR4.to_vec();
        let entries = data[table..table + 216].to_vec();
        data[table..table + 108].copy_from_slice(&entries[..108]);
        data[table + 108..table + 112].fill(0);
        data[table + 112..table + 220].copy_from_slice(&entries[108..]);
        data[table + 220..table + 224].fill(0);
        set32(&mut data, 2112, 224);
        set32(&mut data, 2120, 112);
        data[table + 12..table + 44].fill(0);
        data[table + 12..table + 24].copy_from_slice(b"../../escape");
        let original = Archive::open("boot_image", VENDOR4.to_vec()).unwrap();
        let archive = Archive::open("boot_image", data).unwrap();
        assert_eq!(archive.names(), original.names());
        for name in archive.names() {
            assert_eq!(
                archive.read_named(name).unwrap(),
                original.read_named(name).unwrap()
            );
        }
    }

    #[test]
    fn rejects_recovery_offsets_and_truncated_signatures() {
        let mut data = include_bytes!("../../../tests/fixtures/boot_aosp_v1/sample.img").to_vec();
        data[1636..1644].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Archive::open("boot_image", data).is_err());
        let data = include_bytes!("../../../tests/fixtures/boot_aosp_v4_signature/sample.img");
        assert!(Archive::open("boot_image", data[..data.len() - 1].to_vec()).is_err());
        let mut data = include_bytes!("../../../tests/fixtures/boot_aosp_v0/sample.img").to_vec();
        set32(&mut data, 36, 512);
        assert!(Archive::open("boot_image", data).is_err());
    }
}
