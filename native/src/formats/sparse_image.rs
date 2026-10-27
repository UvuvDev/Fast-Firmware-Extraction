//! Android libsparse v1 (RAW/FILL/DONT_CARE/CRC32), used by fastboot.
//! Layout: AOSP system/core/libsparse/sparse_format.h (Apache-2.0).
//! Chunk layouts are validated before allocating the expanded image. DONT_CARE
//! bytes decode to zero; supplied CRC32s cover those zeros, as AOSP specifies.
use std::ops::Range;
use crate::archive::{ArchiveReader, RangeArchive, Result, MAX_FILE_SIZE, MAX_MEMBERS};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "sparse_image", name: "AndroidSparse", description: "Android Sparse Image",
    signatures: &[Signature::new(0, b"\x3a\xff\x26\xed")], probe: None, open,
    max_input_size: None,
    max_file_size: None,
};
const RAW: u16 = 0xcac1;
const FILL: u16 = 0xcac2;
const SKIP: u16 = 0xcac3;
const CRC: u16 = 0xcac4;
fn half(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(get(data, offset, 2)?.try_into().unwrap()))
}
struct Chunk { kind: u16, payload: Range<usize>, output: Range<usize> }
fn decode(data: &[u8]) -> Result<Vec<u8>> {
    get(data, 0, 28)?;
    if le32(data, 0)? != 0xed26ff3a || half(data, 4)? != 1 {
        return Err("bad sparse magic or unsupported major version".into());
    }
    let header = half(data, 8)? as usize;
    let chunk_header = half(data, 10)? as usize;
    let block = le32(data, 12)? as usize;
    if header < 28 || chunk_header < 12 || block == 0 || !block.is_multiple_of(4) {
        return Err("invalid sparse header sizes or block size".into());
    }
    get(data, 0, header)?;
    let total = (le32(data, 16)? as usize).checked_mul(block).ok_or("sparse output overflow")?;
    if total > MAX_FILE_SIZE { return Err("sparse output exceeds size limit".into()); }
    let count = le32(data, 20)? as usize;
    if count > MAX_MEMBERS || count > (data.len() - header) / chunk_header {
        return Err("sparse chunk count exceeds input or limit".into());
    }
    let checksum = le32(data, 24)?;
    let mut chunks = Vec::new();
    let mut position = header;
    let mut output_end = 0_usize;
    for _ in 0..count {
        let record = get(data, position, chunk_header)?;
        let kind = half(record, 0)?;
        let output_size = (le32(record, 4)? as usize).checked_mul(block).ok_or("sparse chunk overflow")?;
        let next_output = output_end.checked_add(output_size).ok_or("sparse output overflow")?;
        if next_output > total { return Err("sparse chunk overruns declared output".into()); }
        let size = le32(record, 8)? as usize;
        let payload_size = size.checked_sub(chunk_header).ok_or("sparse chunk size is smaller than header")?;
        match kind {
            RAW if payload_size == output_size => (),
            FILL if payload_size == 4 => (),
            SKIP if payload_size == 0 => (),
            CRC if payload_size == 4 && output_size == 0 => (),
            _ => return Err("unknown sparse chunk type or invalid chunk layout".into()),
        }
        get(data, position, size)?;
        chunks.push(Chunk { kind, payload: position + chunk_header..position + size, output: output_end..next_output });
        output_end = next_output;
        position += size;
    }
    if output_end != total { return Err("sparse chunks do not cover declared output".into()); }
    let mut output = vec![0; total];
    let mut hash = (checksum != 0 || chunks.iter().any(|chunk| chunk.kind == CRC)).then(crc32fast::Hasher::new);
    for chunk in chunks {
        let payload = &data[chunk.payload];
        let destination = &mut output[chunk.output];
        match chunk.kind {
            RAW => destination.copy_from_slice(payload),
            FILL => { for word in destination.chunks_exact_mut(4) { word.copy_from_slice(payload); } }
            SKIP => (),
            CRC => {
                if hash.as_ref().unwrap().clone().finalize() != u32::from_le_bytes(payload.try_into().unwrap()) {
                    return Err("sparse CRC32 chunk mismatch".into());
                }
                continue;
            }
            _ => unreachable!(),
        }
        if let Some(hash) = &mut hash { hash.update(destination); }
    }
    if checksum != 0 && hash.unwrap().finalize() != checksum { return Err("sparse image checksum mismatch".into()); }
    Ok(output)
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(RangeArchive::decoded_stream("image.raw", decode(&data)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/sparse_image/sample.img");
    fn set32(data: &mut [u8], offset: usize, value: u32) { data[offset..offset+4].copy_from_slice(&value.to_le_bytes()); }
    #[test]
    fn every_truncated_prefix_is_rejected() {
        for length in 0..SAMPLE.len() { assert!(decode(&SAMPLE[..length]).is_err()); }
    }
    #[test]
    fn rejects_invalid_headers_chunks_and_bombs_before_allocation() {
        for (offset, value) in [(4, 2), (8, 0), (12, 0), (12, 3), (16, u32::MAX), (20, u32::MAX), (28, 0), (32, u32::MAX), (36, 8), (36, u32::MAX), (60, 1)] {
            let mut data = SAMPLE.to_vec(); set32(&mut data, offset, value); assert!(decode(&data).is_err(), "offset {offset}, value {value}");
        }
    }
    #[test]
    fn validates_running_crc_chunks_and_final_checksum() {
        let expected = decode(SAMPLE).unwrap();
        let checksum = crc32fast::hash(&expected);
        let mut data = SAMPLE.to_vec();
        set32(&mut data, 20, 4); set32(&mut data, 24, checksum);
        data.extend_from_slice(&CRC.to_le_bytes()); data.extend_from_slice(&[0;2]);
        data.extend_from_slice(&0_u32.to_le_bytes()); data.extend_from_slice(&16_u32.to_le_bytes());
        data.extend_from_slice(&checksum.to_le_bytes());
        assert_eq!(decode(&data).unwrap(), expected);
        let last = data.len()-1; data[last] ^= 1; assert!(decode(&data).is_err());
        let mut data = SAMPLE.to_vec(); set32(&mut data, 24, checksum ^ 1); assert!(decode(&data).is_err());
    }
    #[test]
    fn supports_extended_headers() {
        let expected = decode(SAMPLE).unwrap();
        let mut data = SAMPLE[..28].to_vec();
        data[8..10].copy_from_slice(&32_u16.to_le_bytes());
        data[10..12].copy_from_slice(&16_u16.to_le_bytes());
        data.extend_from_slice(&[0;4]);
        let mut position = 28;
        while position < SAMPLE.len() {
            let size = le32(SAMPLE, position+8).unwrap() as usize;
            data.extend_from_slice(&SAMPLE[position..position+12]);
            let total_offset = data.len()-4;
            set32(&mut data, total_offset, size as u32+4);
            data.extend_from_slice(&[0;4]);
            data.extend_from_slice(&SAMPLE[position+12..position+size]); position += size;
        }
        assert_eq!(decode(&data).unwrap(), expected);
    }
}
