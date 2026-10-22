//! JFFS2, a log-structured flash filesystem with no on-flash index: every
//! dirent/inode node is scanned in log order, and for a given (parent,name)
//! or inode number the highest "version" wins (a dirent with ino 0 deletes
//! that name). Node header offsets, and the CRC32 variant JFFS2 uses for
//! hdr_crc/node_crc/name_crc/data_crc (poly 0x04C11DB7, reflected, seeded
//! with 0, with **no final XOR** -- distinct from the zlib-compatible CRC32
//! this crate uses elsewhere, e.g. TRX/uImage), were brute-forced against
//! every node of real images built with Alpine's `mtd-utils-jffs` 2.2.1
//! `mkfs.jffs2`, cross-checked with its `jffs2dump`. That tool's GPL-2.0+
//! source is not vendored here, the same policy already used for
//! mkimage/dtc/mkcramfs; only its output bytes are committed as fixtures.
//!
//! Only little-endian images with the modern 0x1985 magic are supported (no
//! 0x1984 legacy magic, no big-endian). Compression types NONE, ZERO
//! (a hole), COPY, and ZLIB are supported; RTIME, RUBINMIPS, DYNRUBIN, LZO,
//! and LZMA are not (mkfs.jffs2's own rtime/lzo compressors were disabled
//! when generating fixtures, mirroring how UBIFS here documents LZO/ZSTD as
//! unsupported). Summary, padding, cleanmarker, xattr, and xref nodes are
//! skipped; symlinks and device nodes are not exposed as members.
use crate::archive::{ArchiveReader, LARGE_CONTAINER_MAX_SIZE, MAX_MEMBERS, Result, validate_name};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{DecompressorOxide, decompress, inflate_flags},
};
use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "jffs2",
    name: "Jffs2",
    description: "JFFS2 filesystem (little-endian)",
    signatures: &[Signature::new(0, b"\x85\x19")],
    probe: Some(probe),
    open,
    max_input_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
    max_file_size: Some(crate::archive::LARGE_CONTAINER_MAX_SIZE),
};

const MAGIC: u16 = 0x1985;
const NODETYPE_DIRENT: u16 = 0xe001;
const NODETYPE_INODE: u16 = 0xe002;
const ROOT_INO: u32 = 1;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const COMPR_NONE: u8 = 0;
const COMPR_ZERO: u8 = 1;
const COMPR_COPY: u8 = 4;
const COMPR_ZLIB: u8 = 6;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("JFFS2 offset overflow".into())
}
fn align4(value: usize) -> Result<usize> {
    Ok(add(value, 3)? & !3)
}
fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(get(data, offset, 2)?.try_into().unwrap()))
}

/// JFFS2's own CRC32 variant: poly 0x04C11DB7, reflected, seeded with 0,
/// with no final XOR. Brute-forced against real mkfs.jffs2 output; see the
/// module doc comment.
fn jffs2_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
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
        return Err("invalid/truncated JFFS2 zlib fragment or output size mismatch".into());
    }
    if state.adler32() != state.adler32_header() {
        return Err("JFFS2 zlib fragment failed its Adler-32 checksum".into());
    }
    output.truncate(written);
    Ok(output)
}

/// A node's hdr_crc (bytes 0..8) is verified before trusting its magic as
/// genuine, rather than any content, since it's the cheapest, strongest
/// available discriminator against an incidental 0x1985 byte pair.
fn probe(data: &[u8]) -> bool {
    get(data, 0, 12).is_ok_and(|header| {
        u16::from_le_bytes([header[0], header[1]]) == MAGIC
            && jffs2_crc32(&header[0..8]) == u32::from_le_bytes([header[8], header[9], header[10], header[11]])
    })
}

/// (parent ino, name) -> (version, target ino, dirent DT_* type). Target
/// ino 0 is a deletion tombstone, resolved away before the directory walk.
type Dirents = HashMap<(u32, String), (u32, u32, u8)>;

struct Fragment {
    version: u32,
    offset: usize,
    dsize: usize,
    compr: u8,
    payload: Range<usize>,
}
struct Inode {
    max_version: u32,
    size: usize,
    fragments: Vec<Fragment>,
}

struct Jffs2 {
    data: Vec<u8>,
    names: Vec<String>,
    files: Vec<u32>,
    inodes: HashMap<u32, Inode>,
}
impl Jffs2 {
    /// Scans every node once, resolving the latest dirent per (parent,name)
    /// and collecting every data fragment per inode (fragments are kept
    /// even from superseded versions, since a later version may only cover
    /// part of a file). Unrecognized bytes are treated as erased-flash
    /// filler or an unrecognized/skippable node type and stepped over
    /// 4 bytes at a time; a node whose header CRC genuinely validates but
    /// whose declared length doesn't fit is a truncated/corrupt image,
    /// not filler, and is rejected outright.
    fn scan(&mut self) -> Result<Dirents> {
        let mut dirents: Dirents = HashMap::new();
        let mut found_any_node = false;
        let mut pos = 0;
        while add(pos, 12)? <= self.data.len() {
            if u16le(&self.data, pos)? != MAGIC
                || jffs2_crc32(get(&self.data, pos, 8)?) != le32(&self.data, add(pos, 8)?)?
            {
                pos += 4;
                continue;
            }
            found_any_node = true;
            let nodetype = u16le(&self.data, add(pos, 2)?)?;
            let totlen = le32(&self.data, add(pos, 4)?)? as usize;
            if totlen < 12 {
                return Err("JFFS2 node shorter than its own header".into());
            }
            // Owned, not a borrow of self.data: parse_inode below needs
            // &mut self while the node's own bytes are still in use.
            let node = get(&self.data, pos, totlen)?.to_vec();
            match nodetype {
                NODETYPE_DIRENT => {
                    let (pino, name, version, ino, dtype) = parse_dirent(&node)?;
                    let key = (pino, name);
                    let is_new = !dirents.contains_key(&key);
                    if is_new && dirents.len() >= MAX_MEMBERS {
                        return Err("too many JFFS2 directory entries".into());
                    }
                    if is_new || dirents[&key].0 <= version {
                        dirents.insert(key, (version, ino, dtype));
                    }
                }
                NODETYPE_INODE => self.parse_inode(&node, pos)?,
                _ => {}
            }
            pos = align4(add(pos, totlen)?)?;
        }
        if !found_any_node {
            return Err("no JFFS2 node found (bad magic or header CRC)".into());
        }
        Ok(dirents)
    }
    fn parse_inode(&mut self, node: &[u8], pos: usize) -> Result<()> {
        if node.len() < 68 {
            return Err("truncated JFFS2 inode node".into());
        }
        if jffs2_crc32(&node[0..60]) != le32(node, 64)? {
            return Err("JFFS2 inode header CRC mismatch".into());
        }
        let ino = le32(node, 12)?;
        let version = le32(node, 16)?;
        let size = le32(node, 28)? as usize;
        let offset = le32(node, 44)? as usize;
        let csize = le32(node, 48)? as usize;
        let dsize = le32(node, 52)? as usize;
        let compr = node[56];
        let payload = get(node, 68, csize)?;
        if jffs2_crc32(payload) != le32(node, 60)? {
            return Err("JFFS2 inode data CRC mismatch".into());
        }
        if !matches!(compr, COMPR_NONE | COMPR_ZERO | COMPR_COPY | COMPR_ZLIB) {
            return Err("unsupported JFFS2 compression type".into());
        }
        if size > LARGE_CONTAINER_MAX_SIZE || dsize > LARGE_CONTAINER_MAX_SIZE {
            return Err("JFFS2 file exceeds size limit".into());
        }
        let payload_start = add(pos, 68)?;
        let entry = self.inodes.entry(ino).or_insert_with(|| Inode {
            max_version: version,
            size,
            fragments: Vec::new(),
        });
        if version >= entry.max_version {
            entry.max_version = version;
            entry.size = size;
        }
        if entry.fragments.len() >= MAX_MEMBERS {
            return Err("too many JFFS2 data fragments".into());
        }
        entry.fragments.push(Fragment {
            version,
            offset,
            dsize,
            compr,
            payload: payload_start..add(payload_start, csize)?,
        });
        Ok(())
    }
    fn decode_fragment(&self, fragment: &Fragment) -> Result<Vec<u8>> {
        let payload = &self.data[fragment.payload.clone()];
        match fragment.compr {
            COMPR_NONE | COMPR_COPY => {
                if payload.len() != fragment.dsize {
                    return Err("JFFS2 stored fragment size mismatch".into());
                }
                Ok(payload.to_vec())
            }
            COMPR_ZERO => Ok(vec![0; fragment.dsize]),
            COMPR_ZLIB => inflate_zlib(payload, fragment.dsize),
            _ => Err("unsupported JFFS2 compression type".into()),
        }
    }
    fn walk(&mut self, dirents: &Dirents) -> Result<()> {
        let mut children: HashMap<u32, Vec<(String, u32, u8)>> = HashMap::new();
        for (&(pino, ref name), &(_, ino, dtype)) in dirents {
            if ino != 0 {
                children.entry(pino).or_default().push((name.clone(), ino, dtype));
            }
        }
        for list in children.values_mut() {
            list.sort();
        }
        let mut pending = vec![(String::new(), ROOT_INO, 0_u32)];
        let mut visited = HashSet::new();
        let mut count = 0;
        while let Some((path, ino, depth)) = pending.pop() {
            count += 1;
            if count > MAX_MEMBERS || depth > 256 {
                return Err("JFFS2 traversal limit exceeded".into());
            }
            let Some(entries) = children.get(&ino) else {
                continue;
            };
            if !visited.insert(ino) {
                return Err("JFFS2 directory cycle or repeated directory".into());
            }
            for (name, child_ino, dtype) in entries.iter().rev() {
                let full = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                validate_name(&full)?;
                if pending.len() + count >= MAX_MEMBERS {
                    return Err("too many JFFS2 entries".into());
                }
                match *dtype {
                    DT_DIR => pending.push((full, *child_ino, depth + 1)),
                    DT_REG => {
                        self.names.push(full);
                        self.files.push(*child_ino);
                    }
                    _ => {} // Skip symlinks and special nodes.
                }
            }
        }
        Ok(())
    }
}
fn parse_dirent(node: &[u8]) -> Result<(u32, String, u32, u32, u8)> {
    if node.len() < 40 {
        return Err("truncated JFFS2 dirent node".into());
    }
    if jffs2_crc32(&node[0..32]) != le32(node, 32)? {
        return Err("JFFS2 dirent header CRC mismatch".into());
    }
    let pino = le32(node, 12)?;
    let version = le32(node, 16)?;
    let ino = le32(node, 20)?;
    let nsize = node[28] as usize;
    let dtype = node[29];
    let name = get(node, 40, nsize)?;
    if jffs2_crc32(name) != le32(node, 36)? {
        return Err("JFFS2 dirent name CRC mismatch".into());
    }
    let name = String::from_utf8_lossy(name).into_owned();
    if name.is_empty() || name.contains('/') {
        return Err("invalid JFFS2 dirent name".into());
    }
    Ok((pino, name, version, ino, dtype))
}
impl ArchiveReader for Jffs2 {
    fn names(&self) -> &[String] {
        &self.names
    }
    fn read(&self, index: usize) -> Result<Vec<u8>> {
        let ino = *self.files.get(index).ok_or("JFFS2 file index out of range")?;
        let inode = self
            .inodes
            .get(&ino)
            .ok_or("JFFS2 regular file has no inode metadata")?;
        let mut fragments: Vec<&Fragment> = inode.fragments.iter().collect();
        fragments.sort_by_key(|fragment| fragment.version);
        let mut output = vec![0_u8; inode.size];
        for fragment in fragments {
            let end = add(fragment.offset, fragment.dsize)?;
            if end > LARGE_CONTAINER_MAX_SIZE {
                return Err("JFFS2 fragment exceeds size limit".into());
            }
            if end > output.len() {
                output.resize(end, 0);
            }
            let decoded = self.decode_fragment(fragment)?;
            output[fragment.offset..end].copy_from_slice(&decoded);
        }
        output.truncate(inode.size);
        Ok(output)
    }
}

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let mut reader = Jffs2 {
        data,
        names: Vec::new(),
        files: Vec::new(),
        inodes: HashMap::new(),
    };
    let dirents = reader.scan()?;
    reader.walk(&dirents)?;
    Ok(Box::new(reader))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const JFFS2: &[u8] = include_bytes!("../../../tests/fixtures/jffs2/sample.img");

    #[test]
    fn rejects_prefixes_too_short_for_any_node_or_truncated_mid_node() {
        // Unlike most formats here, JFFS2 has no total-length field to check
        // against: it's an append-only log with no index, so running out of
        // buffer right on a 4-byte-aligned node boundary (or within 11 bytes
        // of one, too few to even read the next header) is legitimately
        // indistinguishable from the image ending there on purpose -- a real
        // kernel reader has the same ambiguity. What IS always rejected: a
        // prefix too short to contain even the first cleanmarker (<12 bytes),
        // and a prefix that validates a node's 12-byte header (magic +
        // hdr_crc) but then cuts off before that node's declared length.
        for length in 0..12 {
            assert!(
                Archive::open("jffs2", JFFS2[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
        // The first dirent (12..59) validates its header at 12..24 but
        // needs its full 47-byte totlen; cutting anywhere in 24..59 must fail.
        for length in [24, 35, 58] {
            assert!(
                Archive::open("jffs2", JFFS2[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_an_image_with_no_recognizable_node() {
        // Flipping the cleanmarker's own magic byte is not by itself a
        // meaningful corruption: this parser never interprets a cleanmarker's
        // content, so the scan would just treat it as filler and carry on to
        // the real dirent/inode nodes right after it, completely intact.
        // Corrupting every "0x1985" occurrence is what actually leaves no
        // recognizable node anywhere in the image.
        let mut data = JFFS2.to_vec();
        for pos in 0..data.len().saturating_sub(1) {
            if data[pos] == 0x85 && data[pos + 1] == 0x19 {
                data[pos] ^= 0xFF;
            }
        }
        assert!(Archive::open("jffs2", data).is_err());
    }

    #[test]
    fn rejects_a_corrupted_dirent_header() {
        let mut data = JFFS2.to_vec();
        data[12 + 12] ^= 0xFF; // one byte into the first dirent's pino field
        assert!(Archive::open("jffs2", data).is_err());
    }

    #[test]
    fn a_higher_version_deletion_dirent_hides_the_entry() {
        // Append a full copy of the first dirent (header + name), bump its
        // version, and zero its target ino -- a deletion marker. The name
        // it pointed at must disappear entirely from the reconstructed tree.
        let archive = Archive::open("jffs2", JFFS2.to_vec()).unwrap();
        let before = archive.names().len();
        assert!(before > 0);

        let mut data = JFFS2.to_vec();
        // Locate the first dirent node (right after the 12-byte cleanmarker).
        let pos = 12;
        assert_eq!(u16(&data, pos), 0x1985);
        assert_eq!(u16(&data, pos + 2), 0xe001);
        let totlen = u32_at(&data, pos + 4) as usize;
        let mut node = data[pos..pos + totlen].to_vec();
        // Bump version, zero the target ino (deletion), fix both CRCs. The
        // name and its own name_crc are untouched, so they stay valid.
        let version = u32_at(&node, 16) + 100;
        node[16..20].copy_from_slice(&version.to_le_bytes());
        node[20..24].copy_from_slice(&0_u32.to_le_bytes());
        let node_crc = super::jffs2_crc32(&node[0..32]);
        node[32..36].copy_from_slice(&node_crc.to_le_bytes());
        let hdr_crc = super::jffs2_crc32(&node[0..8]);
        node[8..12].copy_from_slice(&hdr_crc.to_le_bytes());
        data.extend_from_slice(&node);

        let archive = Archive::open("jffs2", data).unwrap();
        assert_eq!(archive.names().len(), before - 1);
    }

    #[test]
    fn rejects_an_unsupported_compression_type() {
        // compr 2 is JFFS2's "rtime" compressor, disabled when generating
        // this fixture and not implemented here.
        let pos = first_inode_offset();
        let mut data = JFFS2.to_vec();
        data[pos + 56] = 2;
        let node_crc = super::jffs2_crc32(&data[pos..pos + 60]);
        data[pos + 64..pos + 68].copy_from_slice(&node_crc.to_le_bytes());
        assert!(Archive::open("jffs2", data).is_err());
    }

    fn u16(data: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
    }
    fn u32_at(data: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
    }
    fn first_inode_offset() -> usize {
        let mut pos = 0;
        loop {
            if u16(JFFS2, pos) == 0x1985 && u16(JFFS2, pos + 2) == 0xe002 {
                return pos;
            }
            let totlen = u32_at(JFFS2, pos + 4) as usize;
            pos += totlen;
            pos = (pos + 3) & !3;
        }
    }
}
