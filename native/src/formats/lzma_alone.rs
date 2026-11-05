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
    let total_read = (head.position() + body.position()) as usize;
    let consumed = total_read
        .checked_sub(buffered.len())
        .ok_or("LZMA reader reported inconsistent buffered length")?;
    Ok((output, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lzma_rust2::{LzmaOptions, LzmaWriter};
    use std::io::Write as _;

    /// Builds a real, valid LZMA-alone (`.lzma`-style) stream for `input`:
    /// a genuine header (standard props/dictionary, correct declared size)
    /// followed by genuinely arithmetic-coded body bytes, optionally ending
    /// with a real encoded end-of-stream marker. This exercises the actual
    /// decoder against real streams, the same way a crafted firmware image
    /// would, rather than against hand-picked byte patterns.
    fn build_stream(input: &[u8], use_end_marker: bool) -> Vec<u8> {
        let options = LzmaOptions::default();
        let mut writer = LzmaWriter::new(
            Vec::new(),
            &options,
            true, // use_header
            use_end_marker,
            Some(input.len() as u64),
        )
        .unwrap();
        writer.write_all(input).unwrap();
        writer.finish().unwrap()
    }

    fn sample_input() -> Vec<u8> {
        // Long enough, and varied enough, that the compressed body spans
        // many bytes (not just a handful of range-coder flush bytes), so
        // truncation/mutation tests below land mid-stream rather than past
        // its end.
        (0..600).map(|i: u32| (i % 251) as u8).collect()
    }

    fn set_declared_size(data: &mut [u8], size: u64) {
        data[5..13].copy_from_slice(&size.to_le_bytes());
    }
    fn set_dictionary(data: &mut [u8], dictionary: u32) {
        data[1..5].copy_from_slice(&dictionary.to_le_bytes());
    }

    #[test]
    fn decodes_a_genuine_stream_with_no_end_marker() {
        // The real R7000 kernel case this format exists for: a known
        // declared size and no embedded end-of-stream marker at all, so
        // the plain declared-size decode alone must succeed with nothing
        // left over.
        let input = sample_input();
        let data = build_stream(&input, false);
        assert_eq!(decode_lzma(&data).unwrap(), input);
    }

    #[test]
    fn decodes_a_genuine_stream_with_an_end_marker() {
        let input = sample_input();
        let data = build_stream(&input, true);
        assert_eq!(decode_lzma(&data).unwrap(), input);
    }

    #[test]
    fn rejects_a_header_shorter_than_eighteen_bytes() {
        let data = build_stream(&sample_input(), false);
        for length in [0, 1, 12, 13, 17] {
            assert!(!probe_lzma(&data[..length]), "probe accepted length {length}");
            assert!(decode_lzma(&data[..length]).is_err(), "decode accepted length {length}");
        }
        // 18 is the minimum length lzma_header will even look at, but it's
        // still far short of a real stream, so decoding it must still fail
        // -- just past the length gate, not past this format's parser.
        assert!(decode_lzma(&data[..18]).is_err());
    }

    #[test]
    fn rejects_a_declared_size_that_does_not_match_the_real_stream() {
        // A genuine stream with no end marker, whose header lies about the
        // output length: the declared-size decode stops exactly where it's
        // told, honestly producing that many bytes, but it's not what the
        // header originally promised matched the actual encoded content for
        // -- shrinking it here still leaves real compressed body bytes
        // (effectively the stream's own continuation, never all padding)
        // after that point, which must not be silently accepted as padding.
        let input = sample_input();
        let mut data = build_stream(&input, false);
        set_declared_size(&mut data, (input.len() / 2) as u64);
        assert!(decode_lzma(&data).is_err());
    }

    #[test]
    fn accepts_a_declared_size_stream_whose_trailing_end_marker_validates() {
        // A declared-size stream that also happens to carry a real embedded
        // end marker after the declared number of bytes: the plain
        // declared-size decode stops short of consuming it (it doesn't need
        // to), leaving those encoded marker bytes as "non-padding" trailing
        // data. The fallback decode (`require_eos: true`) must then consume
        // through the real marker, reproduce the identical output, and be
        // accepted -- this is the "no-EOS R7000 fallback" success path.
        let input = sample_input();
        let data = build_stream(&input, true);
        assert_eq!(decode_lzma(&data).unwrap(), input);
    }

    #[test]
    fn rejects_a_declared_size_shorter_than_the_real_end_marker_stream() {
        // Same genuine with-end-marker stream, but the header claims a
        // shorter declared size than what was actually encoded. Whenever
        // that shorter declared-size decode itself lands cleanly (some cut
        // points mid-stream instead surface their own decode error, which
        // is covered separately below), it honestly produces that shorter
        // prefix; trailing non-padding bytes remain (the rest of the real
        // stream plus its end marker), so the fallback decode runs -- and
        // it decodes the *entire* original (longer) output through the
        // real end marker, which disagrees with the shorter declared-size
        // result. That mismatch must be rejected, not silently resolved in
        // either direction. Scanning a range of candidate declared sizes
        // (rather than one hand-picked cut point) finds one that actually
        // exercises this branch rather than the plain "corrupt decode"
        // error path.
        let input = sample_input();
        let template = build_stream(&input, true);
        let found = (1..input.len() as u64).any(|declared| {
            let mut data = template.clone();
            set_declared_size(&mut data, declared);
            matches!(decode_lzma(&data), Err(err) if err == "LZMA end marker length mismatch")
        });
        assert!(
            found,
            "no shortened declared size exercised the end-marker mismatch branch"
        );
    }

    #[test]
    fn rejects_trailing_non_padding_garbage_after_the_stream() {
        let input = sample_input();
        let mut data = build_stream(&input, false);
        data.push(0x42); // neither 0x00 nor 0xFF padding
        assert!(decode_lzma(&data).is_err());
    }

    #[test]
    fn accepts_trailing_zero_and_0xff_padding_after_the_stream() {
        // Flash images routinely pad with either erased-flash 0xFF or
        // zero-filled alignment; both must be tolerated after a complete,
        // correctly declared-size stream.
        let input = sample_input();
        for pad in [0x00_u8, 0xFF_u8] {
            let mut data = build_stream(&input, false);
            data.extend(std::iter::repeat_n(pad, 7));
            assert_eq!(decode_lzma(&data).unwrap(), input);
        }
    }

    #[test]
    fn rejects_a_dictionary_size_failing_the_power_of_two_or_times_three_check() {
        let mut data = build_stream(&sample_input(), false);
        for bad_dictionary in [0_u32, 5000, 4096 * 5, u32::MAX] {
            set_dictionary(&mut data, bad_dictionary);
            assert!(
                !probe_lzma(&data),
                "probe accepted dictionary {bad_dictionary}"
            );
            assert!(
                decode_lzma(&data).is_err(),
                "decode accepted dictionary {bad_dictionary}"
            );
        }
        // A x3-of-a-power-of-two dictionary (the other half of the check)
        // must still be accepted.
        set_dictionary(&mut data, 3 * 4096);
        assert!(probe_lzma(&data));
    }
}
