//! SquashFS v4/XZ regular files via MIT/Apache-2.0 backhand.
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use backhand::{FilesystemReader, InnerNode};
use crate::archive::{ArchiveReader, Result, MAX_FILE_SIZE};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "squashfs", name: "Squashfs", description: "SquashFS v4/XZ filesystem",
    signatures: &[Signature::new(0, b"hsqs")], probe: None, open,
};
struct Squashfs {
    fs: Box<FilesystemReader<'static>>,
    indices: Vec<usize>,
    names: Vec<String>,
}
fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
// Bound metadata allocations before entering the reference reader.
get(&data, 0, 96)?;
if &data[..4] != b"hsqs" || get(&data, 28, 4)? != [4, 0, 0, 0] {
    return Err("expected SquashFS v4.0".into());
}
if get(&data, 20, 2)? != [4, 0] {
    return Err("only XZ SquashFS is enabled".into());
}
let block = le32(&data, 12)?;
if !block.is_power_of_two()
    || !(4096..=1048576).contains(&block)
    || le32(&data, 4)? > 1_000_000
{
    return Err("invalid SquashFS block/inode limits".into());
}
let used = u64::from_le_bytes(get(&data, 40, 8)?.try_into().unwrap());
if used < 96 || used > data.len() as u64 {
    return Err("truncated SquashFS image".into());
}
let fs = Box::new(
    FilesystemReader::from_reader(Cursor::new(data))
        .map_err(|e| format!("SquashFS: {e}"))?,
);
let mut names = Vec::new();
let mut indices = Vec::new();
let mut taken = BTreeSet::new();
for (index, node) in fs.files().enumerate() {
    if let InnerNode::File(file) = &node.inner {
        if file.file_len() > MAX_FILE_SIZE {
            return Err("SquashFS file exceeds size limit".into());
        }
        let name = relative_name(&node.fullpath)?;
        if !taken.insert(name.clone()) {
            return Err("duplicate SquashFS path".into());
        }
        names.push(name);
        indices.push(index);
    }
}
    Ok(Box::new(Squashfs { fs, indices, names }))
}
impl ArchiveReader for Squashfs {
    fn names(&self) -> &[String] { &self.names }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
let node = self.fs
    .files()
    .nth(self.indices[index])
    .ok_or("missing SquashFS inode")?;
let InnerNode::File(file) = &node.inner else {
    return Err("not a regular file".into());
};
let handle = self.fs.file(file);
let reader = handle
    .reader_checked()
    .map_err(|e| format!("SquashFS file: {e}"))?;
let mut output = Vec::new();
reader
    .take(MAX_FILE_SIZE as u64 + 1)
    .read_to_end(&mut output)
    .map_err(|e| format!("SquashFS read: {e}"))?;
if output.len() != file.file_len() {
    return Err("SquashFS file length mismatch".into());
}
Ok(output)
    }
}
/// Backhand paths include a leading filesystem root. Reject traversal rather
/// than normalizing it; the returned name is safe for both hosts and the UI.
fn relative_name(path: &std::path::Path) -> Result<String> {
    let raw = path.to_str().ok_or("non-UTF8 SquashFS path")?;
    let name = raw.strip_prefix('/').unwrap_or(raw);
    crate::archive::validate_name(name)?;
    Ok(name.into())
}
