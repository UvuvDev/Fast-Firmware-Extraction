//! Generated inventory plus an indexed, bounded detection path.
use crate::archive::{ArchiveReader, Result};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::OnceLock,
};

pub const PROBE_LIMIT: usize = 1 << 20;

/// Each signature is an alternative. Longer exact signatures win over broad
/// byte ranges. Overlaps of equal specificity resolve by stable format ID.
pub struct Signature {
    pub offset: usize,
    bytes: &'static [u8],
    first: u8,
    last: u8,
}
impl Signature {
    pub const fn new(offset: usize, bytes: &'static [u8]) -> Self {
        Self {
            offset,
            bytes,
            first: 0,
            last: 0,
        }
    }
    pub const fn byte_range(offset: usize, first: u8, last: u8) -> Self {
        Self {
            offset,
            bytes: &[],
            first,
            last,
        }
    }
    fn matches(&self, data: &[u8]) -> bool {
        if self.bytes.is_empty() {
            data.get(self.offset)
                .is_some_and(|value| (self.first..=self.last).contains(value))
        } else {
            self.offset
                .checked_add(self.bytes.len())
                .and_then(|end| data.get(self.offset..end))
                == Some(self.bytes)
        }
    }
    fn specificity(&self) -> usize {
        self.bytes.len()
    }
}

pub struct FormatDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub signatures: &'static [Signature],
    /// Optional discriminator receives at most PROBE_LIMIT bytes. Full parse
    /// errors must propagate from open, never trigger another decoder.
    pub probe: Option<fn(&[u8]) -> bool>,
    pub open: fn(Vec<u8>) -> Result<Box<dyn ArchiveReader>>,
}

struct Index<'a> {
    formats: &'a [FormatDescriptor],
    ids: HashMap<&'a str, usize>,
    buckets: HashMap<(usize, u8), Vec<(usize, usize)>>,
    offsets: Vec<usize>,
}
impl<'a> Index<'a> {
    fn new(formats: &'a [FormatDescriptor]) -> Self {
        let mut ids = HashMap::new();
        let mut names = HashSet::new();
        let mut buckets: HashMap<_, Vec<_>> = HashMap::new();
        let mut offsets = BTreeSet::new();
        for (i, format) in formats.iter().enumerate() {
            assert!(
                !format.id.is_empty()
                    && format
                        .id
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
                "invalid format ID"
            );
            assert!(
                ids.insert(format.id, i).is_none(),
                "duplicate format ID: {}",
                format.id
            );
            assert!(
                names.insert(format.name),
                "duplicate transform name: {}",
                format.name
            );
            assert!(
                !format.signatures.is_empty(),
                "format needs a detection signature"
            );
            for (s, signature) in format.signatures.iter().enumerate() {
                assert!(
                    signature
                        .offset
                        .checked_add(signature.bytes.len().max(1))
                        .is_some_and(|end| end <= PROBE_LIMIT),
                    "signature exceeds detection prefix"
                );
                offsets.insert(signature.offset);
                let (first, last) = signature
                    .bytes
                    .first()
                    .map_or((signature.first, signature.last), |&byte| (byte, byte));
                assert!(first <= last, "invalid byte range");
                for byte in first..=last {
                    buckets
                        .entry((signature.offset, byte))
                        .or_default()
                        .push((i, s));
                }
            }
        }
        Self {
            formats,
            ids,
            buckets,
            offsets: offsets.into_iter().collect(),
        }
    }
    fn detect(&self, data: &[u8]) -> Option<&'a FormatDescriptor> {
        let data = &data[..data.len().min(PROBE_LIMIT)];
        let mut candidates: HashMap<usize, usize> = HashMap::new();
        for offset in &self.offsets {
            let Some(byte) = data.get(*offset) else {
                continue;
            };
            if let Some(bucket) = self.buckets.get(&(*offset, *byte)) {
                for &(index, signature) in bucket {
                    let signature = &self.formats[index].signatures[signature];
                    if signature.matches(data) {
                        candidates
                            .entry(index)
                            .and_modify(|score| *score = (*score).max(signature.specificity()))
                            .or_insert(signature.specificity());
                    }
                }
            }
        }
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort_unstable_by(|(a, sa), (b, sb)| {
            sb.cmp(sa)
                .then_with(|| self.formats[*a].id.cmp(self.formats[*b].id))
        });
        candidates
            .into_iter()
            .map(|(index, _)| &self.formats[index])
            .find(|format| format.probe.is_none_or(|probe| probe(data)))
    }
}
fn index() -> &'static Index<'static> {
    static INDEX: OnceLock<Index<'static>> = OnceLock::new();
    INDEX.get_or_init(|| Index::new(crate::formats::FORMATS))
}
pub fn formats() -> &'static [FormatDescriptor] {
    let _ = index();
    crate::formats::FORMATS
}
pub fn get(id: &str) -> Option<&'static FormatDescriptor> {
    index().ids.get(id).map(|&i| &index().formats[i])
}
pub fn detect(data: &[u8]) -> Option<&'static FormatDescriptor> {
    index().detect(data)
}
pub(crate) fn detect_index(data: &[u8]) -> Option<usize> {
    detect(data).map(|format| index().ids[format.id])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn probe(_: &[u8]) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        true
    }
    fn unused(_: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
        Err("not opened by detection".into())
    }

    #[test]
    fn thousand_formats_only_probe_matching_candidates() {
        let mut formats = Vec::new();
        for i in 0_u16..1000 {
            let id = Box::leak(format!("format_{i:04}").into_boxed_str());
            let magic = Box::leak(
                [b'F', b'M', b'T', (i >> 8) as u8, i as u8]
                    .to_vec()
                    .into_boxed_slice(),
            );
            let signatures = Box::leak(vec![Signature::new(0, magic)].into_boxed_slice());
            formats.push(FormatDescriptor {
                id,
                name: id,
                description: "test",
                signatures,
                probe: Some(probe),
                open: unused,
            });
        }
        let index = Index::new(&formats);
        CALLS.store(0, Ordering::Relaxed);
        assert_eq!(index.detect(b"FMT\x03\xe7").unwrap().id, "format_0999");
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert!(index.detect(b"unrelated").is_none());
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn exact_signature_precedes_broad_probe_and_corruption_is_not_fallback() {
        let data = include_bytes!("../../tests/fixtures/trx_corrupt/sample.bin");
        assert_eq!(detect(data).unwrap().id, "trx");
        assert!(crate::archive::Archive::open_auto(data.to_vec()).is_err());
        assert!(detect(b"").is_none());
    }
    #[test]
    #[should_panic(expected = "duplicate format ID")]
    fn duplicate_ids_are_rejected() {
        Index::new(&[crate::formats::dtbo::FORMAT, crate::formats::dtbo::FORMAT]);
    }
}
