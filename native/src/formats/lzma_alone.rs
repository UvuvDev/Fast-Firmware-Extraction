//! LZMA-alone, including known-size streams without EOS used by R7000.
use std::io::{Cursor, Read};
use lzma_rust2::LzmaReader;
use crate::archive::{ArchiveReader, RangeArchive, Result, MAX_FILE_SIZE};
use crate::registry::{FormatDescriptor, Signature};
const MAX_LZMA_MEMORY_KIB: u32 = 64 * 1024;

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "lzma_alone", name: "LzmaAlone", description: "LZMA-alone stream",
    // Standard LZMA property bytes are < 225. Index candidates by that byte,
    // then validate the dictionary and attempt a bounded prefix decode.
    signatures: &[Signature::byte_range(0, 0, 224)],
    probe: Some(probe_lzma), open,
    max_input_size: None,
    max_file_size: None,
};
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(RangeArchive::single("kernel.bin", decode_lzma(&data)?)?))
}

pub(crate) fn lzma_header(data: &[u8]) -> bool {
    if data.len() < 18 || data[0] >= 225 {
        return false;
    }
    let dictionary = u32::from_le_bytes(data[1..5].try_into().unwrap());
    let size = u64::from_le_bytes(data[5..13].try_into().unwrap());
    (4096..=32 * 1024 * 1024).contains(&dictionary)
        && (dictionary.is_power_of_two()
            || (dictionary % 3 == 0 && (dictionary / 3).is_power_of_two()))
        && (size == u64::MAX || size <= MAX_FILE_SIZE as u64)
}

/// A bounded prefix decode reduces accidental detection on unrelated inputs.
pub fn probe_lzma(data: &[u8]) -> bool {
    if !lzma_header(data) {
        return false;
    }
    let Ok(mut reader) = LzmaReader::new_mem_limit(data, MAX_LZMA_MEMORY_KIB, None) else {
        return false;
    };
    let mut prefix = [0; 256];
    reader.read(&mut prefix).is_ok_and(|size| size > 0)
}

pub fn decode_lzma(data: &[u8]) -> Result<Vec<u8>> {
    if !lzma_header(data) {
        return Err("invalid LZMA-alone header or size limit exceeded".into());
    }
    let declared = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let (output, mut consumed) = decode_lzma_once(data, false)?;
    if declared != u64::MAX && declared != output.len() as u64 {
        return Err("LZMA output length mismatch".into());
    }
    // A declared-size stream may omit EOS (the real R7000 kernel does).
    // If non-padding remains, it must be a valid optional EOS, not garbage.
    if data[consumed..].iter().any(|&b| b != 0 && b != 255) && declared != u64::MAX {
        let (through_eos, end) = decode_lzma_once(data, true)?;
        if through_eos != output {
            return Err("LZMA end marker length mismatch".into());
        }
        consumed = end;
    }
    if data[consumed..].iter().any(|&b| b != 0 && b != 255) {
        return Err("non-padding data after LZMA stream".into());
    }
    Ok(output)
}

fn decode_lzma_once(data: &[u8], require_eos: bool) -> Result<(Vec<u8>, usize)> {
    let mut header: [u8; 13] = data[..13].try_into().unwrap();
    if require_eos {
        header[5..].fill(255);
    }
    let source = Cursor::new(header).chain(Cursor::new(&data[13..]));
    let mut reader = LzmaReader::new_mem_limit(source, MAX_LZMA_MEMORY_KIB, None)
        .map_err(|e| format!("LZMA header: {e}"))?;
    let mut output = Vec::new();
    reader
        .by_ref()
        .take(MAX_FILE_SIZE as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|e| format!("LZMA decode: {e}"))?;
    if output.len() > MAX_FILE_SIZE {
        return Err("LZMA output exceeds size limit".into());
    }
    let (source, buffered) = reader.into_parts();
    let (head, body) = source.into_inner();
    let consumed = (head.position() + body.position()) as usize - buffered.len();
    Ok((output, consumed))
}
