//! Modern LZ4 frames using MIT lz4_flex. Framing follows the upstream LZ4
//! specification v1.6.4. Preflight every block/end marker because the reader
//! also accepts EOF in some truncated streams. Checksums are verified by the
//! decoder. Concatenation and inter-frame skippable records are supported;
//! legacy framing and external dictionaries are deliberately unsupported.
use crate::archive::{ArchiveReader, MAX_FILE_SIZE, MAX_MEMBERS, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use lz4_flex::frame::FrameDecoder;
use std::io::{Cursor, Read};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "lz4_frame",
    name: "Lz4Frame",
    description: "LZ4 framed compression",
    signatures: &[Signature::new(0, b"\x04\x22\x4d\x18")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};
fn frame_end(data: &[u8], start: usize, limit: usize) -> Result<usize> {
    let header = get(data, start, 7)?;
    if le32(header, 0)? != 0x184d2204 {
        return Err("bad LZ4 frame magic".into());
    }
    let flags = header[4];
    let bd = header[5];
    let id = (bd >> 4) & 7;
    if flags >> 6 != 1 || flags & 2 != 0 || bd & 0x8f != 0 || !(4..=7).contains(&id) {
        return Err("unsupported/reserved LZ4 frame flags".into());
    }
    if flags & 1 != 0 {
        return Err("LZ4 external dictionaries unsupported".into());
    }
    let mut position = start + 7;
    if flags & 8 != 0 {
        let size = u64::from_le_bytes(get(data, start + 6, 8)?.try_into().unwrap());
        if size > limit as u64 {
            return Err("LZ4 content size exceeds output limit".into());
        }
        get(data, start + 14, 1)?;
        position = start + 15;
    }
    let max_block = 1usize << (8 + 2 * id);
    for _ in 0..MAX_MEMBERS {
        let word = le32(data, position)?;
        position += 4;
        if word == 0 {
            if flags & 4 != 0 {
                get(data, position, 4)?;
                position += 4;
            }
            return Ok(position);
        }
        let size = (word & 0x7fff_ffff) as usize;
        if size > max_block {
            return Err("LZ4 block exceeds declared maximum".into());
        }
        get(data, position, size)?;
        position += size;
        if flags & 16 != 0 {
            get(data, position, 4)?;
            position += 4;
        }
    }
    Err("too many LZ4 blocks".into())
}
fn decode(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    if get(data, 0, 4)? != b"\x04\x22\x4d\x18" {
        return Err("expected modern LZ4 frame".into());
    }
    let mut output = Vec::new();
    let mut offset = 0;
    let mut count = 0;
    while offset < data.len() {
        count += 1;
        if count > MAX_MEMBERS {
            return Err("too many LZ4 frames".into());
        }
        let magic = le32(data, offset)?;
        if (0x184d2a50..=0x184d2a5f).contains(&magic) {
            let size = le32(data, offset + 4)? as usize;
            get(data, offset + 8, size)?;
            offset += 8 + size;
            continue;
        }
        let end = frame_end(data, offset, limit - output.len())?;
        let mut decoder = FrameDecoder::new(Cursor::new(&data[offset..end]));
        let mut buffer = [0; 8192];
        loop {
            let before = decoder.get_ref().position();
            let capacity = buffer.len().min(limit - output.len() + 1);
            let size = decoder
                .read(&mut buffer[..capacity])
                .map_err(|error| format!("LZ4: {error}"))?;
            if size > limit - output.len() {
                return Err("LZ4 output exceeds file limit".into());
            }
            output.extend_from_slice(&buffer[..size]);
            if size == 0 {
                if decoder.get_ref().position() == (end - offset) as u64 {
                    break;
                }
                if decoder.get_ref().position() == before {
                    return Err("LZ4 decoder stopped before frame end".into());
                }
                // A valid zero-length uncompressed block can return zero before
                // the end marker; continue so checksums/end markers are consumed.
            }
        }
        offset = end;
    }
    Ok(output)
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(RangeArchive::decoded_stream(
        "payload.bin",
        decode(&data, MAX_FILE_SIZE)?,
    )?))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        include_bytes!("../../../tests/fixtures/lz4_frame/sample.lz4").to_vec()
    }
    #[test]
    fn truncation_and_trailing_garbage_rejected() {
        let data = sample();
        for length in [4, 6, 10, data.len() - 1, data.len() - 4, data.len() - 8] {
            assert!(decode(&data[..length], MAX_FILE_SIZE).is_err());
        }
        let mut data = sample();
        data.push(0);
        assert!(open(data).is_err());
    }
    #[test]
    fn checksums_and_block_limits_checked() {
        for off in [6, 15, 20, sample().len() - 1] {
            let mut data = sample();
            data[off] ^= 0x80;
            assert!(open(data).is_err());
        }
        let mut data = sample();
        data[15..19].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(data).is_err());
    }
    #[test]
    fn expansion_bounded_before_allocation() {
        assert!(decode(&sample(), 10).is_err());
        let mut data = sample();
        data[6..14].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(open(data).is_err());
    }
    #[test]
    fn reserved_flags_and_dictionaries_rejected() {
        for (off, mask) in [(4, 2), (4, 1), (5, 8), (4, 0x80)] {
            let mut data = sample();
            data[off] |= mask;
            assert!(open(data).is_err());
        }
    }
    #[test]
    fn concatenation_and_skippable_records() {
        let data = sample();
        let plain = decode(&data, MAX_FILE_SIZE).unwrap();
        let mut both = data.clone();
        both.extend_from_slice(&0x184d2a5au32.to_le_bytes());
        both.extend_from_slice(&3u32.to_le_bytes());
        both.extend_from_slice(b"tag");
        both.extend_from_slice(&data);
        assert_eq!(
            decode(&both, MAX_FILE_SIZE).unwrap(),
            [plain.clone(), plain].concat()
        );
        both.pop();
        assert!(open(both).is_err());
    }
}
