//! Format-independent archive contract, validation, and common reader helpers.
use crate::registry;
use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_FILE_SIZE: usize = 512 * 1024 * 1024;
pub const MAX_INPUT_SIZE: usize = 1024 * 1024 * 1024;
pub const MAX_MEMBERS: usize = 1_000_000;
/// `FormatDescriptor::max_input_size`/`max_file_size` override for a format
/// that is itself a whole disk/partition image, where the whole input or
/// an individual member routinely exceeding the defaults above is a normal,
/// non-malicious occurrence (a multi-GiB Android system/vendor partition, a
/// squashfs/erofs filesystem nested inside a multi-GiB ISO, a DVD9 image).
/// Formats with no legitimate reason to ever be gigabytes keep the tighter
/// defaults, so a pathological claim from one of *those* still fails fast.
pub const LARGE_CONTAINER_MAX_SIZE: usize = 16 * 1024 * 1024 * 1024;

/// Implement this only for a filesystem or custom decoder. Offset containers
/// and decoded single streams can use RangeArchive directly.
pub trait ArchiveReader {
    fn names(&self) -> &[String];
    fn read(&self, index: usize) -> Result<Vec<u8>>;
    /// A decoded stream is one automatic child, rather than a selectable file.
    fn is_decoded_stream(&self) -> bool {
        false
    }
    /// Exact standalone archive extent inside a larger host image. Consumers
    /// may retain the host for analysis alongside this archive's contents.
    fn embedded_range(&self) -> Option<Range<usize>> {
        None
    }
    /// Optional human-readable analysis information, owned by this reader.
    fn diagnostics(&self) -> &str {
        ""
    }
}

pub struct Member {
    pub name: String,
    pub range: Range<usize>,
}

pub struct RangeArchive {
    data: Vec<u8>,
    members: Vec<Member>,
    names: Vec<String>,
    decoded_stream: bool,
    embedded_range: Option<Range<usize>>,
    diagnostics: String,
}
impl RangeArchive {
    pub fn new(data: Vec<u8>, members: Vec<Member>) -> Result<Self> {
        Self::new_with_file_size_limit(data, members, MAX_FILE_SIZE)
    }
    /// For a format whose `FormatDescriptor::max_file_size` legitimately
    /// raises the crate-wide default (e.g. a multi-GiB file inside an ISO
    /// 9660 image): the same validation as `new`, against `max_file_size`
    /// instead of the constant. `Archive::read` separately re-checks every
    /// read against that same per-format override, so the two stay consistent.
    pub fn new_with_file_size_limit(
        data: Vec<u8>,
        members: Vec<Member>,
        max_file_size: usize,
    ) -> Result<Self> {
        if members.len() > MAX_MEMBERS {
            return Err("too many archive members".into());
        }
        for member in &members {
            let size = member
                .range
                .end
                .checked_sub(member.range.start)
                .ok_or("reversed member range")?;
            if size > max_file_size || data.get(member.range.clone()).is_none() {
                return Err("member out of bounds or exceeds size limit".into());
            }
        }
        let names = members.iter().map(|member| member.name.clone()).collect();
        Ok(Self {
            data,
            members,
            names,
            decoded_stream: false,
            embedded_range: None,
            diagnostics: String::new(),
        })
    }
    pub fn single(name: &str, data: Vec<u8>) -> Result<Self> {
        let length = data.len();
        Self::new(
            data,
            vec![Member {
                name: name.into(),
                range: 0..length,
            }],
        )
    }
    pub fn decoded_stream(name: &str, data: Vec<u8>) -> Result<Self> {
        let mut archive = Self::single(name, data)?;
        archive.decoded_stream = true;
        Ok(archive)
    }
    pub fn with_diagnostics(mut self, diagnostics: String) -> Self {
        self.diagnostics = diagnostics;
        self
    }
    pub fn with_embedded_range(mut self, range: Range<usize>) -> Self {
        self.embedded_range = Some(range);
        self
    }
}
impl ArchiveReader for RangeArchive {
    fn diagnostics(&self) -> &str {
        &self.diagnostics
    }
    fn is_decoded_stream(&self) -> bool {
        self.decoded_stream
    }
    fn embedded_range(&self) -> Option<Range<usize>> {
        self.embedded_range.clone()
    }
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        let member = self.members.get(index).ok_or("file index out of range")?;
        Ok(self.data[member.range.clone()].to_vec())
    }
}

/// Enforce the same names and limits for every parser, before any extraction.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 4096
        || name.contains(['\\', ':'])
        || name.chars().any(char::is_control)
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!("unsafe archive member name: {name:?}"));
    }
    Ok(())
}

/// Shared wording for a reader that drops some of its own entries rather
/// than failing outright (see `Archive::open_format` and `formats::squashfs`,
/// which both skip unsafe/duplicate names one real-world file at a time
/// instead of losing every other, perfectly valid member behind it).
pub fn skip_diagnostics(kind: &str, skipped: &[String]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let shown: Vec<_> = skipped.iter().take(5).map(|name| format!("{name:?}")).collect();
    let more = skipped.len().saturating_sub(shown.len());
    let suffix = if more > 0 {
        format!(", and {more} more")
    } else {
        String::new()
    };
    format!(
        "skipped {} {kind}, not extracted: {}{suffix}",
        skipped.len(),
        shown.join(", "),
    )
}

pub struct Archive {
    pub format: &'static registry::FormatDescriptor,
    reader: Box<dyn ArchiveReader>,
    /// Exposed names, filtered down from `reader.names()`: unsafe and
    /// duplicate names are excluded rather than failing the whole archive
    /// (see `open_format`), so this is usually but not always the full list.
    names: Vec<String>,
    /// `names[i]` came from `reader.names()[original_indices[i]]`; `read`
    /// translates an exposed index back to that original index before
    /// delegating, so skipped entries never shift which bytes a name maps to.
    original_indices: Vec<usize>,
    indices: HashMap<String, usize>,
    diagnostics: String,
}
impl Archive {
    /// Stable string IDs cross the Rust/Python boundary; no numeric enum.
    pub fn open(id: &str, data: Vec<u8>) -> Result<Self> {
        let format = registry::get(id).ok_or_else(|| format!("unknown native format: {id}"))?;
        Self::open_format(format, data)
    }
    pub fn open_auto(data: Vec<u8>) -> Result<Self> {
        let format = registry::detect(&data).ok_or("no supported native format detected")?;
        Self::open_format(format, data)
    }
    fn open_format(format: &'static registry::FormatDescriptor, data: Vec<u8>) -> Result<Self> {
        if data.len() > format.max_input_size.unwrap_or(MAX_INPUT_SIZE) {
            return Err("firmware exceeds input size limit".into());
        }
        let input_size = data.len();
        let reader = (format.open)(data)?;
        if let Some(range) = reader.embedded_range()
            && (reader.is_decoded_stream()
                || range.start >= range.end
                || range.end > input_size
                || range.end - range.start > MAX_FILE_SIZE
                || range == (0..input_size))
        {
            return Err("invalid embedded archive extent".into());
        }
        if reader.is_decoded_stream() && reader.names().len() != 1 {
            return Err("decoded stream must expose exactly one output".into());
        }
        if reader.names().len() > MAX_MEMBERS {
            return Err("too many archive members".into());
        }
        // A single unsafe-named or duplicate entry must not hide every other,
        // perfectly valid member behind it: real Linux filesystems routinely
        // carry a `:` (multiarch dpkg lists) or `\` (systemd-escaped unit
        // names) that are fine on Linux but unsafe to write verbatim on
        // Windows/macOS. Skip just that entry and keep going.
        let mut taken = HashSet::new();
        let mut names = Vec::new();
        let mut original_indices = Vec::new();
        let mut skipped = Vec::new();
        for (index, name) in reader.names().iter().enumerate() {
            if validate_name(name).is_err() || !taken.insert(name) {
                skipped.push(name.clone());
                continue;
            }
            names.push(name.clone());
            original_indices.push(index);
        }
        let skip_message = skip_diagnostics("unsafe or duplicate archive member name(s)", &skipped);
        let diagnostics = match (reader.diagnostics(), skip_message.as_str()) {
            ("", skip) => skip.to_string(),
            (reader_diag, "") => reader_diag.to_string(),
            (reader_diag, skip) => format!("{reader_diag}\n{skip}"),
        };
        let indices = names
            .iter()
            .enumerate()
            .map(|(index, name)| (name.clone(), index))
            .collect();
        Ok(Self {
            format,
            reader,
            names,
            original_indices,
            indices,
            diagnostics,
        })
    }
    pub fn names(&self) -> &[String] {
        &self.names
    }
    pub fn is_decoded_stream(&self) -> bool {
        self.reader.is_decoded_stream()
    }
    pub fn embedded_range(&self) -> Option<Range<usize>> {
        self.reader.embedded_range()
    }
    pub fn diagnostics(&self) -> &str {
        &self.diagnostics
    }
    pub fn read(&self, index: usize) -> Result<Vec<u8>> {
        let original = *self
            .original_indices
            .get(index)
            .ok_or("file index out of range")?;
        let data = self.reader.read(original)?;
        if data.len() > self.format.max_file_size.unwrap_or(MAX_FILE_SIZE) {
            return Err("member exceeds size limit".into());
        }
        Ok(data)
    }
    pub fn read_named(&self, name: &str) -> Result<Vec<u8>> {
        self.read(*self.indices.get(name).ok_or("file not found")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: registry::FormatDescriptor = registry::FormatDescriptor {
        id: "layout_test",
        name: "LayoutTest",
        description: "Reader contract validation",
        signatures: &[],
        probe: None,
        open: |data| {
            let range = data[0] as usize..data[1] as usize;
            let reader = if data[2] == 0 {
                RangeArchive::single("member", data)?
            } else {
                RangeArchive::decoded_stream("member", data)?
            };
            Ok(Box::new(reader.with_embedded_range(range)))
        },
        max_input_size: None,
        max_file_size: None,
    };

    #[test]
    fn embedded_extent_must_be_a_nonempty_proper_subrange() {
        for (start, end, stream) in [(8, 7, 0), (0, 0, 0), (0, 11, 0), (0, 10, 0), (1, 9, 1)] {
            let mut data = vec![0; 10];
            data[..3].copy_from_slice(&[start, end, stream]);
            assert!(Archive::open_format(&LAYOUT, data).is_err());
        }
        for (start, end) in [(1, 9), (0, 9), (1, 10)] {
            let mut data = vec![0; 10];
            data[..2].copy_from_slice(&[start, end]);
            let archive = Archive::open_format(&LAYOUT, data).unwrap();
            assert_eq!(archive.embedded_range(), Some(start as usize..end as usize));
        }
    }

    #[test]
    fn max_input_size_override_replaces_the_crate_wide_default() {
        const SMALL_LIMIT: registry::FormatDescriptor = registry::FormatDescriptor {
            id: "small_limit_test",
            name: "SmallLimitTest",
            description: "max_input_size override test",
            signatures: &[],
            probe: None,
            open: |data| RangeArchive::single("member", data).map(|archive| Box::new(archive) as _),
            max_input_size: Some(5),
            max_file_size: None,
        };
        assert!(Archive::open_format(&SMALL_LIMIT, vec![0; 6]).is_err());
        assert!(Archive::open_format(&SMALL_LIMIT, vec![0; 5]).is_ok());
    }

    #[test]
    fn max_file_size_override_is_honored_at_construction_and_at_read() {
        // RangeArchive::new_with_file_size_limit, used directly: a custom
        // limit (not the crate-wide MAX_FILE_SIZE) is what's enforced.
        let member = |len| Member {
            name: "member".into(),
            range: 0..len,
        };
        assert!(RangeArchive::new_with_file_size_limit(vec![0; 6], vec![member(6)], 5).is_err());
        assert!(RangeArchive::new_with_file_size_limit(vec![0; 5], vec![member(5)], 5).is_ok());

        // Archive::read's own re-check must also consult the format's
        // override, not just trust whatever RangeArchive::new (the
        // crate-wide default) already allowed at construction time.
        const SMALL_READ_LIMIT: registry::FormatDescriptor = registry::FormatDescriptor {
            id: "small_read_limit_test",
            name: "SmallReadLimitTest",
            description: "max_file_size override test",
            signatures: &[],
            probe: None,
            open: |data| {
                let length = data.len();
                RangeArchive::new(data, vec![Member { name: "member".into(), range: 0..length }])
                    .map(|archive| Box::new(archive) as _)
            },
            max_input_size: None,
            max_file_size: Some(5),
        };
        let archive = Archive::open_format(&SMALL_READ_LIMIT, vec![0; 6]).unwrap();
        assert!(archive.read(0).is_err());
    }

    #[test]
    fn unsafe_or_duplicate_names_are_skipped_not_fatal() {
        // Real Debian/Ubuntu squashfs content routinely has one bad-named
        // file (a multiarch `:` in a dpkg list, a systemd `\x2d` escape)
        // among thousands of fine ones; it must not take the whole archive
        // down with it.
        const MIXED: registry::FormatDescriptor = registry::FormatDescriptor {
            id: "mixed_names_test",
            name: "MixedNamesTest",
            description: "skip-unsafe-names test",
            signatures: &[],
            probe: None,
            open: |data| {
                let member = |name: &str, range: Range<usize>| Member {
                    name: name.into(),
                    range,
                };
                RangeArchive::new(
                    data,
                    vec![
                        member("good.txt", 0..1),
                        member("bad:name.txt", 1..2),
                        member("dup.txt", 2..3),
                        member("dup.txt", 3..4),
                        member("another_good", 4..5),
                    ],
                )
                .map(|archive| Box::new(archive) as _)
            },
            max_input_size: None,
            max_file_size: None,
        };
        let archive = Archive::open_format(&MIXED, b"abcde".to_vec()).unwrap();
        assert_eq!(archive.names(), ["good.txt", "dup.txt", "another_good"]);
        assert_eq!(archive.read(0).unwrap(), b"a");
        assert_eq!(archive.read(1).unwrap(), b"c");
        assert_eq!(archive.read(2).unwrap(), b"e");
        assert_eq!(archive.read_named("dup.txt").unwrap(), b"c");
        assert!(archive.read_named("bad:name.txt").is_err());
        assert!(archive.diagnostics().contains("skipped 2"));
        assert!(archive.diagnostics().contains("\"bad:name.txt\""));
    }
}
