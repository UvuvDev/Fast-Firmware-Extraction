//! Android vendor-blob shell wrappers: carve `tail -n +N $0 | tar ...`.
//! Port of formats/android_selfextract.py's bounded byte-pattern reader.
//! This never executes shell text, a license prompt, or the appended payload.
//! Stored bytes are returned verbatim; decompression belongs to the child.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::registry::{FormatDescriptor, Signature};

const SCAN_LIMIT: usize = 1 << 20;
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "android_selfextract",
    name: "AndroidSelfExtract",
    description: "Android self-extracting vendor blob",
    signatures: &[Signature::new(0, b"#!")],
    probe: Some(probe),
    open,
};

// Python's bytes-regex \s includes vertical tab as well as the usual ASCII
// whitespace. Parse bytes directly so binary payloads need not be UTF-8.
fn whitespace(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | b' ')
}
fn spaces(data: &[u8], mut pos: usize, required: bool) -> Option<usize> {
    let start = pos;
    while data.get(pos).is_some_and(|&byte| whitespace(byte)) {
        pos += 1;
    }
    (!required || pos > start).then_some(pos)
}
fn token(data: &[u8], pos: usize, value: &[u8]) -> Option<usize> {
    let end = pos.checked_add(value.len())?;
    data.get(pos..end)?
        .eq_ignore_ascii_case(value)
        .then_some(end)
}

/// A syntactically matched marker with an overflowing line number must still
/// stop the search, just like the legacy regex's first match. No large integer
/// or regex allocation is needed for an attacker-controlled digit string.
fn marker(data: &[u8], start: usize) -> Option<(Option<usize>, usize)> {
    let mut pos = token(data, start, b"tail")?;
    pos = spaces(data, pos, true)?;
    pos = token(data, pos, b"-n")?;
    pos = spaces(data, pos, true)?;
    pos = token(data, pos, b"+")?;
    let digits_start = pos;
    let mut line = Some(0_usize);
    while let Some(&digit) = data.get(pos).filter(|byte| byte.is_ascii_digit()) {
        line = line.and_then(|value| value.checked_mul(10)?.checked_add((digit - b'0') as usize));
        pos += 1;
    }
    if pos == digits_start {
        return None;
    }
    pos = spaces(data, pos, true)?;
    pos = token(data, pos, b"$0")?;
    pos = spaces(data, pos, false)?;
    pos = token(data, pos, b"|")?;
    pos = spaces(data, pos, false)?;
    pos = token(data, pos, b"tar")?;
    Some((line, pos))
}

fn payload_offset(data: &[u8]) -> Result<usize> {
    let prefix = &data[..data.len().min(SCAN_LIMIT)];
    if !prefix.starts_with(b"#!") {
        return Err("missing self-extracting script shebang".into());
    }
    for (start, bytes) in prefix.windows(4).enumerate() {
        if !bytes.eq_ignore_ascii_case(b"tail") {
            continue;
        }
        let Some((line, marker_end)) = marker(prefix, start) else {
            continue;
        };
        let line = line
            .filter(|&number| number > 1)
            .ok_or("invalid self-extracting payload line")?;
        let offset = prefix
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'\n')
            .nth(line - 2)
            .map(|(index, _)| index + 1)
            .ok_or("self-extracting payload line exceeds bounded prefix")?;
        // Reject self-referential ranges that would recreate this wrapper
        // recursively. Valid distribution scripts point past the marker.
        if offset < marker_end {
            return Err("self-extracting payload starts before marker ends".into());
        }
        return Ok(offset);
    }
    Err("self-extracting payload marker not found in bounded prefix".into())
}
fn probe(data: &[u8]) -> bool {
    payload_offset(data).is_ok()
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let start = payload_offset(&data)?;
    let end = data.len();
    Ok(Box::new(RangeArchive::new(
        data,
        vec![Member {
            name: "payload.gz".into(),
            range: start..end,
        }],
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive::Archive, registry};
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/android_selfextract/sample.sh");

    #[test]
    fn fixture_payload_is_carved_verbatim() {
        let archive = Archive::open_auto(SAMPLE.to_vec()).unwrap();
        assert_eq!(archive.names(), ["payload.gz"]);
        assert_eq!(archive.read(0).unwrap(), &SAMPLE[84..]);
    }
    #[test]
    fn matches_legacy_case_whitespace_and_crlf() {
        for data in [
            b"#!/bin/sh\nTaIl\t-N\x0b+3\x0c$0\t|\tTaR zxv\n\xff\0payload".as_slice(),
            b"#!/bin/sh\r\ntail -n +3 $0 | tar zxv\r\n\xff\0payload".as_slice(),
        ] {
            let archive = Archive::open_auto(data.to_vec()).unwrap();
            assert_eq!(archive.read(0).unwrap(), b"\xff\0payload");
        }
    }
    #[test]
    fn rejects_plain_scripts_and_self_referential_or_missing_lines() {
        for data in [
            b"#!/bin/sh\necho hello\n".as_slice(),
            b"tail -n +2 $0 | tar\npayload".as_slice(),
            b"#!/bin/sh\ntail -n +0 $0 | tar\npayload".as_slice(),
            b"#!/bin/sh\ntail -n +1 $0 | tar\npayload".as_slice(),
            b"#!/bin/sh\ntail -n +2 $0 | tar\npayload".as_slice(),
            b"#!/bin/sh\ntail -n +99 $0 | tar\npayload".as_slice(),
        ] {
            assert!(Archive::open("android_selfextract", data.to_vec()).is_err());
            assert!(registry::detect(data).is_none());
        }
    }
    #[test]
    fn bounds_line_number_parsing_and_does_not_skip_a_bad_first_marker() {
        let mut data = b"#!/bin/sh\ntail -n +".to_vec();
        data.extend(std::iter::repeat_n(b'9', 10000));
        data.extend_from_slice(b" $0 | tar\ntail -n +4 $0 | tar\npayload");
        assert!(!probe(&data));
        assert!(Archive::open("android_selfextract", data).is_err());
    }
    #[test]
    fn retains_the_one_mib_banner_limit_for_detection() {
        let mut data = b"#!/bin/sh\n#".to_vec();
        data.resize(70_000, b'x');
        data.extend_from_slice(b"\ntail -n +4 $0 | tar zxv\npayload");
        assert_eq!(registry::detect(&data).unwrap().id, "android_selfextract");
        assert_eq!(
            Archive::open_auto(data).unwrap().read(0).unwrap(),
            b"payload"
        );
        let mut data = b"#!/bin/sh\n#".to_vec();
        data.resize(SCAN_LIMIT, b'x');
        data.extend_from_slice(b"\ntail -n +4 $0 | tar zxv\npayload");
        assert!(!probe(&data));
        assert!(Archive::open("android_selfextract", data).is_err());
    }
    #[test]
    fn truncation_before_payload_line_is_rejected_but_empty_payload_is_allowed() {
        for length in 0..84 {
            assert!(!probe(&SAMPLE[..length]));
        }
        let archive = Archive::open_auto(SAMPLE[..84].to_vec()).unwrap();
        assert!(archive.read(0).unwrap().is_empty());
    }
}
