//! DTBO/ACPIO offset tables. Layout ported from `formats/dtbo.py`, which was
//! checked against AOSP libufdt's Apache-2.0 `mkdtboimg.py`.
//!
//! Fields are big-endian. Versions 0/1 share the same 32-byte entry layout;
//! metadata (including v1 compression flags) is ignored, as in the Python
//! implementation. Extraction returns the stored bytes without decompression.

use std::fmt;

const DTBO_MAGIC: u32 = 0xd7b7ab1e;
const ACPIO_MAGIC: u32 = 0x41435049;
const HEADER_SIZE: usize = 32;
const ENTRY_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TruncatedHeader,
    InvalidMagic,
    UnsupportedLayout,
    TruncatedTable,
    PayloadOutOfBounds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TruncatedHeader => "truncated DT table header",
            Self::InvalidMagic => "unexpected DT table magic",
            Self::UnsupportedLayout => "unexpected DT table header/entry size",
            Self::TruncatedTable => "DT entry table exceeds input length",
            Self::PayloadOutOfBounds => "DT payload exceeds input length",
        })
    }
}

impl std::error::Error for Error {}

/// One stored payload, borrowed directly from the input image.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub offset: usize,
    pub content: &'a [u8],
}

/// A validated table. Parsing checks all table and payload ranges before
/// exposing any entries, including when callers only request discovery.
#[derive(Debug)]
pub struct Dtbo<'a> {
    data: &'a [u8],
    table_start: usize,
    count: usize,
}

// Called only on a header/entry whose full 32-byte range was checked.
fn word(record: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(record[offset..offset + 4].try_into().unwrap())
}

impl<'a> Dtbo<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = data.get(..HEADER_SIZE).ok_or(Error::TruncatedHeader)?;
        if !matches!(word(header, 0), DTBO_MAGIC | ACPIO_MAGIC) {
            return Err(Error::InvalidMagic);
        }
        if word(header, 8) != HEADER_SIZE as u32 || word(header, 12) != ENTRY_SIZE as u32 {
            return Err(Error::UnsupportedLayout);
        }

        let count = word(header, 16) as usize;
        let table_start = word(header, 20) as usize;
        let table_end = count
            .checked_mul(ENTRY_SIZE)
            .and_then(|size| table_start.checked_add(size))
            .ok_or(Error::TruncatedTable)?;
        let records = data
            .get(table_start..table_end)
            .ok_or(Error::TruncatedTable)?;

        for record in records.chunks_exact(ENTRY_SIZE) {
            let size = word(record, 0) as usize;
            let offset = word(record, 4) as usize;
            let end = offset.checked_add(size).ok_or(Error::PayloadOutOfBounds)?;
            data.get(offset..end).ok_or(Error::PayloadOutOfBounds)?;
        }

        // As in the original parser, total_size/page_size/version/IDs are
        // advisory. The actual buffer length is the boundary for extraction.
        Ok(Self {
            data,
            table_start,
            count,
        })
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = Entry<'a>> + '_ {
        (0..self.count).map(|index| {
            let start = self.table_start + index * ENTRY_SIZE;
            let record = &self.data[start..start + ENTRY_SIZE];
            let size = word(record, 0) as usize;
            let offset = word(record, 4) as usize;
            Entry {
                offset,
                content: &self.data[offset..offset + size],
            }
        })
    }
}

use crate::archive::{ArchiveReader, Member, RangeArchive};
use crate::registry::{FormatDescriptor, Signature};
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "dtbo", name: "Dtbo", description: "DTBO / ACPI table image",
    signatures: &[Signature::new(0, b"\xd7\xb7\xab\x1e"), Signature::new(0, b"ACPI")],
    probe: None, open,
};
fn open(data: Vec<u8>) -> crate::archive::Result<Box<dyn ArchiveReader>> {
    let table = Dtbo::parse(&data).map_err(|e| e.to_string())?;
    let members = table.entries().enumerate().map(|(index, entry)| Member {
        name: format!("dt{index:02}"),
        range: entry.offset..entry.offset + entry.content.len(),
    }).collect();
    Ok(Box::new(RangeArchive::new(data, members)?))
}
