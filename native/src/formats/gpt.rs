//! Primary GPT tables on disks with 512-byte logical blocks. Field layout
//! follows formats/gpt.py and UEFI 2.10 section 5.3. This reader verifies CRC32
//! over the declared header length and the full entry array, checks inclusive
//! LBA arithmetic, and exposes stored partition bytes. It does not recover
//! backup tables or infer 4 KiB logical block sizes.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

const BLOCK: usize = 512;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "gpt",
    name: "Gpt",
    description: "GUID Partition Table (512-byte sectors)",
    signatures: &[Signature::new(510, b"\x55\xaaEFI PART")],
    probe: None,
    open,
};
fn word64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        get(data, offset, 8)?.try_into().unwrap(),
    ))
}
fn byte_offset(lba: u64) -> Result<usize> {
    lba.checked_mul(BLOCK as u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("GPT LBA offset overflow".into())
}
fn partition_name(raw: &[u8], index: usize) -> String {
    let words: Vec<_> = raw
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes(word.try_into().unwrap()))
        .take_while(|&word| word != 0)
        .collect();
    let decoded = String::from_utf16_lossy(&words);
    let name = decoded.trim();
    if name.is_empty() {
        format!("part{index}")
    } else {
        name.into()
    }
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if get(&data, 510, 10)? != b"\x55\xaaEFI PART" {
        return Err("missing GPT/MBR signature".into());
    }
    let header = get(&data, BLOCK, 92)?;
    let header_size = le32(header, 12)? as usize;
    if !(92..=BLOCK).contains(&header_size) {
        return Err("invalid GPT header size".into());
    }
    let mut checked_header = get(&data, BLOCK, header_size)?.to_vec();
    checked_header[16..20].fill(0);
    if crc32fast::hash(&checked_header) != le32(header, 16)? {
        return Err("GPT header CRC32 mismatch".into());
    }
    let count = le32(header, 80)? as usize;
    let stride = le32(header, 84)? as usize;
    if count > 4096 || stride < 128 {
        return Err("invalid GPT entry count or stride".into());
    }
    let array_offset = byte_offset(word64(header, 72)?)?;
    let array_size = count
        .checked_mul(stride)
        .ok_or("GPT entry array overflow")?;
    let array = get(&data, array_offset, array_size)?;
    if crc32fast::hash(array) != le32(header, 88)? {
        return Err("GPT partition array CRC32 mismatch".into());
    }
    let mut members = Vec::new();
    for (index, entry) in array.chunks_exact(stride).enumerate() {
        if entry[..16].iter().all(|&byte| byte == 0) {
            continue;
        }
        let first = word64(entry, 32)?;
        let last = word64(entry, 40)?;
        if last < first {
            return Err("reversed GPT partition LBAs".into());
        }
        let start = byte_offset(first)?;
        let end = byte_offset(last.checked_add(1).ok_or("GPT final LBA overflow")?)?;
        members.push(Member {
            name: partition_name(&entry[56..128], index),
            range: start..end,
        });
    }
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/gpt/sample.img");
    fn set32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fix_crc(data: &mut [u8]) {
        let size = u32::from_le_bytes(data[524..528].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(data[592..596].try_into().unwrap()) as usize;
        let stride = u32::from_le_bytes(data[596..600].try_into().unwrap()) as usize;
        let array_crc = crc32fast::hash(&data[1024..1024 + count * stride]);
        set32(data, 600, array_crc);
        set32(data, 528, 0);
        let header_crc = crc32fast::hash(&data[512..512 + size]);
        set32(data, 528, header_crc);
    }
    #[test]
    fn rejects_truncated_headers_arrays_and_partition_data() {
        for length in [0, 511, 519, 603, 1024, 17407, 20479, 24063, 34303] {
            assert!(
                Archive::open("gpt", SAMPLE[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }
    #[test]
    fn rejects_header_and_array_corruption_including_unused_entries() {
        for offset in [510, 512, 528, 560, 1024, 1200, 17000] {
            let mut data = SAMPLE.to_vec();
            data[offset] ^= 1;
            assert!(Archive::open("gpt", data).is_err(), "offset {offset}");
        }
    }
    #[test]
    fn rejects_huge_counts_strides_and_lba_overflows() {
        for (offset, value) in [
            (524, 91),
            (524, 513),
            (592, u32::MAX),
            (596, 127),
            (596, u32::MAX),
        ] {
            let mut data = SAMPLE.to_vec();
            set32(&mut data, offset, value);
            let mut header = data[512..604].to_vec();
            header[16..20].fill(0);
            set32(&mut data, 528, crc32fast::hash(&header));
            assert!(Archive::open("gpt", data).is_err());
        }
        for offset in [584, 1056, 1064] {
            let mut data = SAMPLE.to_vec();
            data[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            if offset >= 1024 {
                fix_crc(&mut data);
            } else {
                let mut h = data[512..604].to_vec();
                h[16..20].fill(0);
                set32(&mut data, 528, crc32fast::hash(&h));
            }
            assert!(Archive::open("gpt", data).is_err());
        }
    }
    #[test]
    fn rejects_reversed_lbas_even_with_valid_crcs() {
        let mut data = SAMPLE.to_vec();
        data[1064..1072].copy_from_slice(&39_u64.to_le_bytes());
        fix_crc(&mut data);
        assert!(Archive::open("gpt", data).is_err());
    }
    #[test]
    fn supports_unicode_names_extended_entries_and_extended_header_crc() {
        for data in [
            include_bytes!("../../../tests/fixtures/gpt_extended/sample.img").as_slice(),
            include_bytes!("../../../tests/fixtures/gpt_extended_header/sample.img").as_slice(),
        ] {
            let archive = Archive::open_auto(data.to_vec()).unwrap();
            assert_eq!(archive.names(), ["modem_数据😀"]);
            assert_eq!(archive.read(0).unwrap().len(), 1024);
        }
    }
}
