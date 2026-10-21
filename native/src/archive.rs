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

/// Implement this only for a filesystem or custom decoder. Offset containers
/// and decoded single streams can use RangeArchive directly.
pub trait ArchiveReader {
    fn names(&self) -> &[String];
    fn read(&self, index: usize) -> Result<Vec<u8>>;
    /// A decoded stream is one automatic child, rather than a selectable file.
    fn is_decoded_stream(&self) -> bool {
        false
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
}
impl RangeArchive {
    pub fn new(data: Vec<u8>, members: Vec<Member>) -> Result<Self> {
        if members.len() > MAX_MEMBERS {
            return Err("too many archive members".into());
        }
        for member in &members {
            let size = member
                .range
                .end
                .checked_sub(member.range.start)
                .ok_or("reversed member range")?;
            if size > MAX_FILE_SIZE || data.get(member.range.clone()).is_none() {
                return Err("member out of bounds or exceeds size limit".into());
            }
        }
        let names = members.iter().map(|member| member.name.clone()).collect();
        Ok(Self {
            data,
            members,
            names,
            decoded_stream: false,
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
}
impl ArchiveReader for RangeArchive {
    fn is_decoded_stream(&self) -> bool {
        self.decoded_stream
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

pub struct Archive {
    pub format: &'static registry::FormatDescriptor,
    reader: Box<dyn ArchiveReader>,
    indices: HashMap<String, usize>,
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
        if data.len() > MAX_INPUT_SIZE {
            return Err("firmware exceeds input size limit".into());
        }
        let reader = (format.open)(data)?;
        if reader.is_decoded_stream() && reader.names().len() != 1 {
            return Err("decoded stream must expose exactly one output".into());
        }
        if reader.names().len() > MAX_MEMBERS {
            return Err("too many archive members".into());
        }
        let mut taken = HashSet::new();
        for name in reader.names() {
            validate_name(name)?;
            if !taken.insert(name) {
                return Err(format!("duplicate archive member: {name}"));
            }
        }
        let indices = reader
            .names()
            .iter()
            .enumerate()
            .map(|(index, name)| (name.clone(), index))
            .collect();
        Ok(Self {
            format,
            reader,
            indices,
        })
    }
    pub fn names(&self) -> &[String] {
        self.reader.names()
    }
    pub fn is_decoded_stream(&self) -> bool {
        self.reader.is_decoded_stream()
    }
    pub fn read(&self, index: usize) -> Result<Vec<u8>> {
        if index >= self.names().len() {
            return Err("file index out of range".into());
        }
        let data = self.reader.read(index)?;
        if data.len() > MAX_FILE_SIZE {
            return Err("member exceeds size limit".into());
        }
        Ok(data)
    }
    pub fn read_named(&self, name: &str) -> Result<Vec<u8>> {
        self.read(*self.indices.get(name).ok_or("file not found")?)
    }
}
