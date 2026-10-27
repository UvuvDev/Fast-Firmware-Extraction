//! CramFS, a read-only, zlib-compressed filesystem (Linux
//! include/uapi/linux/cramfs_fs.h). The 76-byte "FSID_VERSION_2" superblock,
//! the 12-byte packed inode layout (mode/uid in word0, 24-bit size/gid in
//! word1, 6-bit namelen-in-4-byte-words/26-bit offset-in-4-byte-words in
//! word2), the per-directory entry layout (no "."/".." entries), and the
//! per-file block-pointer table (absolute end-of-block file offsets,
//! individually zlib-wrapped per up-to-4096-byte block) were all verified
//! against real images built with Alpine's `cramfs` 1.1-r7 `mkcramfs` and
//! cross-checked with its `cramfsck`. That tool's GPL-2.0+ source is not
//! vendored here, matching this repository's existing policy for mkimage/dtc;
//! only its output bytes are committed as fixtures.
//!
//! Only the modern FSID_VERSION_2 layout is supported; any other flag bit
//! (including SHIFTED_ROOT_OFFSET or WRONG_SIGNATURE) is rejected rather than
//! guessed at. A zero-length block is read as a hole (all zero bytes)
//! regardless of whether the advisory HOLES flag is set.
use crate::archive::{ArchiveReader, LARGE_CONTAINER_MAX_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{DecompressorOxide, decompress, inflate_flags},
};
use std::collections::HashSet;

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "cramfs",
    name: "Cramfs",
    description: "CramFS filesystem (zlib-compressed)",
    signatures: &[Signature::new(0, b"\x45\x3d\xcd\x28")],
    probe: None,
    open,
    max_input_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
};

const BLOCK_SIZE: usize = 4096;
const SUPPORTED_FLAGS: u32 = 0x103; // FSID_VERSION_2 (0x1) | SORTED_DIRS (0x2) | HOLES (0x100)
const MODE_FMT: u16 = 0xf000;
const MODE_DIR: u16 = 0x4000;
const MODE_REG: u16 = 0x8000;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("cramfs offset overflow".into())
}

struct Inode {
    mode: u16,
    size: usize,
    offset: usize,
    namelen_words: usize,
}
fn parse_inode(raw: &[u8]) -> Result<Inode> {
    let w0 = le32(raw, 0)?;
    let w1 = le32(raw, 4)?;
    let w2 = le32(raw, 8)?;
    Ok(Inode {
        mode: (w0 & 0xffff) as u16,
        size: (w1 & 0xff_ffff) as usize,
        namelen_words: (w2 & 0x3f) as usize,
        offset: ((w2 >> 6) as usize)
            .checked_mul(4)
            .ok_or("cramfs inode offset overflow")?,
    })
}

/// A zlib-wrapped (not raw-deflate) block, bounded to exactly `expected` bytes.
fn inflate_zlib(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; expected + 1];
    let mut state = Box::<DecompressorOxide>::default();
    let (status, consumed, written) = decompress(
        &mut state,
        input,
        &mut output,
        0,
        inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    if status != TINFLStatus::Done || consumed != input.len() || written != expected {
        return Err("invalid/truncated cramfs zlib block or output size mismatch".into());
    }
    // `decompress` never fails the status on its own for a bad trailer; the
    // running and header-declared Adler-32 must be compared explicitly.
    if state.adler32() != state.adler32_header() {
        return Err("cramfs zlib block failed its Adler-32 checksum".into());
    }
    output.truncate(written);
    Ok(output)
}

struct Cramfs {
    data: Vec<u8>,
    names: Vec<String>,
    files: Vec<Inode>,
}
impl Cramfs {
    fn directory(&self, offset: usize, size: usize) -> Result<Vec<(String, Inode)>> {
        let bytes = get(&self.data, offset, size)?;
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            let inode = parse_inode(get(bytes, pos, 12)?)?;
            pos += 12;
            let namebytes = inode.namelen_words * 4;
            let raw_name = get(bytes, pos, namebytes)?;
            pos += namebytes;
            let name_end = raw_name
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(namebytes);
            let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
            if name.is_empty() || name.contains('/') {
                return Err("invalid cramfs directory entry name".into());
            }
            if entries.len() >= MAX_MEMBERS {
                return Err("too many cramfs directory entries".into());
            }
            entries.push((name, inode));
        }
        Ok(entries)
    }
    fn content(&self, inode: &Inode) -> Result<Vec<u8>> {
        if inode.size > LARGE_CONTAINER_MAX_SIZE {
            return Err("cramfs file exceeds size limit".into());
        }
        let num_blocks = inode.size.div_ceil(BLOCK_SIZE);
        let table = get(&self.data, inode.offset, num_blocks * 4)?;
        let mut output = Vec::with_capacity(inode.size);
        let mut prev = add(inode.offset, num_blocks * 4)?;
        for i in 0..num_blocks {
            let ptr = le32(table, i * 4)? as usize;
            if ptr < prev {
                return Err("cramfs block pointer out of order".into());
            }
            let expected = (inode.size - output.len()).min(BLOCK_SIZE);
            let compressed = get(&self.data, prev, ptr - prev)?;
            if compressed.is_empty() {
                output.resize(output.len() + expected, 0);
            } else {
                output.extend(inflate_zlib(compressed, expected)?);
            }
            prev = ptr;
        }
        Ok(output)
    }
    fn index(&mut self, root: Inode) -> Result<()> {
        let mut pending = vec![(String::new(), root, 0_u32)];
        let mut visited = HashSet::new();
        let mut count = 0;
        while let Some((path, inode, depth)) = pending.pop() {
            count += 1;
            if count > MAX_MEMBERS || depth > 256 {
                return Err("cramfs traversal limit exceeded".into());
            }
            match inode.mode & MODE_FMT {
                MODE_DIR => {
                    if !visited.insert(inode.offset) {
                        return Err("cramfs directory cycle or repeated directory".into());
                    }
                    for (name, child) in self.directory(inode.offset, inode.size)?.into_iter().rev() {
                        let full = if path.is_empty() {
                            name
                        } else {
                            format!("{path}/{name}")
                        };
                        validate_name(&full)?;
                        if pending.len() + count >= MAX_MEMBERS {
                            return Err("too many cramfs entries".into());
                        }
                        pending.push((full, child, depth + 1));
                    }
                }
                MODE_REG => {
                    self.names.push(path);
                    self.files.push(inode);
                }
                _ => {} // Skip symlinks and special nodes.
            }
        }
        Ok(())
    }
}
impl ArchiveReader for Cramfs {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        self.content(self.files.get(index).ok_or("cramfs file index out of range")?)
    }
}

fn open(mut data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if le32(&data, 0)? != 0x28cd_3d45 {
        return Err("bad cramfs magic".into());
    }
    let size = le32(&data, 4)? as usize;
    get(&data, 0, size)?;
    data.truncate(size);
    let flags = le32(&data, 8)?;
    if flags & 1 == 0 {
        return Err("cramfs legacy (pre-FSID_VERSION_2) superblock is unsupported".into());
    }
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err("unsupported cramfs flags".into());
    }
    if get(&data, 16, 16)? != b"Compressed ROMFS" {
        return Err("bad cramfs signature".into());
    }
    let root = parse_inode(get(&data, 64, 12)?)?;
    if root.mode & MODE_FMT != MODE_DIR {
        return Err("cramfs root is not a directory".into());
    }
    let mut reader = Cramfs {
        data,
        names: Vec::new(),
        files: Vec::new(),
    };
    reader.index(root)?;
    Ok(Box::new(reader))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const CRAMFS: &[u8] = include_bytes!("../../../tests/fixtures/cramfs/sample.img");

    #[test]
    fn rejects_every_truncated_prefix() {
        for length in 0..CRAMFS.len() {
            assert!(
                Archive::open("cramfs", CRAMFS[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_bad_magic_signature_and_unsupported_flags() {
        for (offset, value) in [(0, 0_u32), (8, 0), (8, 0x400)] {
            let mut data = CRAMFS.to_vec();
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                Archive::open("cramfs", data).is_err(),
                "offset {offset} value {value:#x}"
            );
        }
        let mut data = CRAMFS.to_vec();
        data[16] = b'x';
        assert!(Archive::open("cramfs", data).is_err());
    }

    #[test]
    fn rejects_a_root_that_is_not_a_directory() {
        let mut data = CRAMFS.to_vec();
        data[64..66].copy_from_slice(&0x8000_u16.to_le_bytes());
        assert!(Archive::open("cramfs", data).is_err());
    }
}
