//! CPIO "newc" (070701) archives, the format the Linux kernel documents for
//! initramfs images (Documentation/driver-api/early-userspace/buffer-format.rst)
//! and the one GNU/BSD cpio write with `-H newc`. The 110-byte ASCII-hex fixed
//! header, the name/data padding (each aligned to 4 bytes from the start of
//! the archive, not from the start of the entry), and the "TRAILER!!!"
//! terminator were verified against real archives built with macOS's
//! `/usr/bin/cpio` (bsdcpio/libarchive), including nested directories and a
//! "./" path prefix from `find .`, which is stripped from member names here.
//!
//! Only "070701" is supported; the "070702" CRC variant (whose c_check field
//! bsdcpio cannot even write) is not. Only regular files are exposed, as
//! plain byte ranges -- cpio stores file data verbatim, so no decoder is
//! needed. Directories, symlinks, device nodes, and hardlink bookkeeping are
//! not represented as members.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::get;
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "cpio_newc",
    name: "CpioNewc",
    description: "CPIO newc (070701) archive",
    signatures: &[Signature::new(0, b"070701")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};

const HEADER_SIZE: usize = 110;
const MODE_FMT: u32 = 0o170000;
const MODE_REG: u32 = 0o100000;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("cpio offset overflow".into())
}
fn align4(value: usize) -> Result<usize> {
    Ok(add(value, 3)? & !3)
}
fn hex_field(data: &[u8], offset: usize) -> Result<u32> {
    let field = get(data, offset, 8)?;
    let text = std::str::from_utf8(field).map_err(|_| "non-ASCII cpio header field")?;
    u32::from_str_radix(text, 16).map_err(|_| "invalid cpio header field".into())
}
/// `find .`-built archives prefix every path with "./"; a bare "/" is
/// defensively stripped too, so this never emits an absolute member name.
fn clean_name(name: &str) -> &str {
    name.strip_prefix("./").unwrap_or(name).trim_start_matches('/')
}

fn members(data: &[u8]) -> Result<Vec<Member>> {
    let mut offset = 0;
    let mut members = Vec::new();
    loop {
        if get(data, offset, 6)? != b"070701" {
            return Err("bad cpio newc magic".into());
        }
        let mode = hex_field(data, add(offset, 14)?)?;
        let filesize = hex_field(data, add(offset, 54)?)? as usize;
        let namesize = hex_field(data, add(offset, 94)?)? as usize;
        if namesize == 0 {
            return Err("cpio entry has an empty name field".into());
        }
        let header_end = add(offset, HEADER_SIZE)?;
        let name_field = get(data, header_end, namesize)?;
        let name = std::str::from_utf8(&name_field[..namesize - 1])
            .map_err(|_| "non-UTF8 cpio filename")?;
        let data_start = align4(add(header_end, namesize)?)?;
        let data_end = add(data_start, filesize)?;
        get(data, data_start, filesize)?;
        if name == "TRAILER!!!" {
            break;
        }
        if mode & MODE_FMT == MODE_REG {
            if members.len() >= MAX_MEMBERS {
                return Err("too many cpio entries".into());
            }
            members.push(Member {
                name: clean_name(name).into(),
                range: data_start..data_end,
            });
        }
        offset = align4(data_end)?;
    }
    Ok(members)
}

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    let members = members(&data)?;
    Ok(Box::new(RangeArchive::new(data, members)?))
}

#[cfg(test)]
mod tests {
    use crate::archive::Archive;
    const CPIO: &[u8] = include_bytes!("../../../tests/fixtures/cpio_newc/sample.cpio");

    #[test]
    fn rejects_every_truncated_prefix() {
        for length in 0..CPIO.len() {
            assert!(
                Archive::open("cpio_newc", CPIO[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = CPIO.to_vec();
        data[0] = b'X';
        assert!(Archive::open("cpio_newc", data).is_err());
    }

    #[test]
    fn strips_the_dot_slash_prefix_and_skips_directories() {
        let archive = Archive::open("cpio_newc", CPIO.to_vec()).unwrap();
        assert!(archive.names().iter().all(|name| !name.starts_with("./")));
        assert!(archive.names().iter().all(|name| !name.is_empty()));
    }

    #[test]
    fn rejects_a_namesize_that_overruns_the_buffer() {
        let mut data = CPIO.to_vec();
        data[94..102].copy_from_slice(b"7fffffff");
        assert!(Archive::open("cpio_newc", data).is_err());
    }

    #[test]
    fn rejects_a_corrupted_trailer_header() {
        // The trailer is the last "070701" magic in the stream; corrupting
        // it must surface as an error rather than silently stopping short.
        let position = CPIO.windows(6).rposition(|w| w == b"070701").unwrap();
        let mut data = CPIO.to_vec();
        data[position] = b'X';
        assert!(Archive::open("cpio_newc", data).is_err());
    }
}
