//! U-Boot Flattened Image Tree (FIT), a devicetree blob whose `/images` node
//! holds one subnode per embedded image with a `data` property carrying the
//! raw bytes (see U-Boot's doc/usage/fit/source_file_format.txt). This module
//! implements only enough of the flattened devicetree structure-block format
//! (devicetree.org's Devicetree Specification) to walk `/images/*` and read
//! each child's properties; it is not a general FDT/overlay reader.
//!
//! The token layout, header field offsets, and the multi-byte-table/padding
//! behavior below were checked against real `.itb` files produced by the
//! official `mkimage -f image.its` (which compiles the source with libfdt),
//! inspected independently with `fdtdump`/`fdtget` from the `dtc` package.
//! Neither tool's GPL-2.0 source is vendored here; only committed fixture
//! bytes come from their output, as with the dtc-compiled DTBO overlays
//! under tests/fixture_sources/dtbo.
//!
//! A plain (non-FIT) devicetree blob shares this magic but has no `/images`
//! node, so it is rejected rather than misreported as a FIT image.
use crate::archive::{ArchiveReader, MAX_MEMBERS, Member, RangeArchive, Result};
use crate::bytes::be32;
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "uboot_fit",
    name: "UBootFit",
    description: "U-Boot Flattened Image Tree (FIT)",
    signatures: &[Signature::new(0, b"\xd0\x0d\xfe\xed")],
    probe: None,
    open,
    max_input_size: None,
    max_file_size: None,
};

const HEADER_SIZE: usize = 40;
const MIN_VERSION: u32 = 17;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("devicetree offset overflow".into())
}
fn align4(value: usize) -> Result<usize> {
    Ok(add(value, 3)? & !3)
}
/// A nul-terminated string's end index, searched only within `..limit`.
fn cstr_end(data: &[u8], start: usize, limit: usize) -> Result<usize> {
    data.get(start..limit)
        .ok_or("devicetree string exceeds its region")?
        .iter()
        .position(|&byte| byte == 0)
        .map(|index| start + index)
        .ok_or("unterminated devicetree string".into())
}
fn display_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.strip_suffix(b"\0").unwrap_or(bytes)).into_owned()
}

struct Image {
    name: String,
    range: Option<(usize, usize)>,
    info: Vec<String>,
}

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if be32(&data, 0)? != 0xd00d_feed {
        return Err("bad devicetree magic".into());
    }
    let total = be32(&data, 4)? as usize;
    let image = data.get(..total).ok_or("truncated devicetree blob")?;
    if total < HEADER_SIZE {
        return Err("truncated devicetree header".into());
    }
    if be32(image, 20)? < MIN_VERSION {
        return Err("devicetree version predates FIT (requires 17+)".into());
    }
    let struct_start = be32(image, 8)? as usize;
    let struct_size = be32(image, 36)? as usize;
    let struct_end = add(struct_start, struct_size)?;
    image
        .get(struct_start..struct_end)
        .ok_or("devicetree structure block exceeds the blob")?;
    let strings_start = be32(image, 12)? as usize;
    let strings_size = be32(image, 32)? as usize;
    let strings_end = add(strings_start, strings_size)?;
    image
        .get(strings_start..strings_end)
        .ok_or("devicetree strings block exceeds the blob")?;

    let mut cursor = struct_start;
    let mut path: Vec<String> = Vec::new();
    let mut saw_images_node = false;
    let mut images: Vec<Image> = Vec::new();
    loop {
        if cursor.checked_add(4).is_none_or(|end| end > struct_end) {
            return Err("missing FDT_END in devicetree structure block".into());
        }
        let token = be32(image, cursor)?;
        cursor = add(cursor, 4)?;
        match token {
            FDT_NOP => {}
            FDT_BEGIN_NODE => {
                let name_end = cstr_end(image, cursor, struct_end)?;
                let name = display_string(&image[cursor..name_end]);
                cursor = align4(add(name_end, 1)?)?;
                if path.len() == 1 && name == "images" {
                    saw_images_node = true;
                }
                if path.len() == 2 && path[1] == "images" {
                    if images.len() >= MAX_MEMBERS {
                        return Err("too many FIT images".into());
                    }
                    images.push(Image {
                        name: name.clone(),
                        range: None,
                        info: Vec::new(),
                    });
                }
                path.push(name);
            }
            FDT_END_NODE => {
                path.pop().ok_or("unbalanced devicetree node")?;
            }
            FDT_PROP => {
                let length = be32(image, cursor)? as usize;
                let nameoff = be32(image, add(cursor, 4)?)? as usize;
                let value_start = add(cursor, 8)?;
                let value_end = add(value_start, length)?;
                if value_end > struct_end {
                    return Err("devicetree property value exceeds the structure block".into());
                }
                let value = &image[value_start..value_end];
                cursor = align4(value_end)?;

                let name_start = add(strings_start, nameoff)?;
                let name_end = cstr_end(image, name_start, strings_end)?;
                let prop_name = &image[name_start..name_end];

                if path.len() == 3
                    && path[1] == "images"
                    && let Some(current) = images.last_mut()
                {
                    match prop_name {
                        b"data" => current.range = Some((value_start, value_end)),
                        b"description" | b"type" | b"arch" | b"os" | b"compression" => {
                            current.info.push(format!(
                                "{}={}",
                                display_string(prop_name),
                                display_string(value)
                            ));
                        }
                        b"load" | b"entry" if length == 4 => {
                            current.info.push(format!(
                                "{}=0x{:08x}",
                                display_string(prop_name),
                                be32(value, 0)?
                            ));
                        }
                        _ => {}
                    }
                }
            }
            FDT_END => {
                if !path.is_empty() {
                    return Err("devicetree structure block ended before closing all nodes".into());
                }
                break;
            }
            _ => return Err("unknown devicetree structure token".into()),
        }
    }
    if !saw_images_node {
        return Err("devicetree has no /images node; not a FIT image".into());
    }

    let mut members = Vec::new();
    let mut diagnostics = String::new();
    for entry in &images {
        let (start, end) = entry
            .range
            .ok_or("FIT image entry has no data property")?;
        members.push(Member {
            name: entry.name.clone(),
            range: start..end,
        });
        diagnostics.push_str(&entry.name);
        diagnostics.push_str(": ");
        diagnostics.push_str(&entry.info.join(" "));
        diagnostics.push('\n');
    }
    Ok(Box::new(
        RangeArchive::new(data, members)?.with_diagnostics(diagnostics),
    ))
}

#[cfg(test)]
mod tests {
    use super::{FDT_END, FDT_END_NODE};
    use crate::archive::Archive;
    const FIT: &[u8] = include_bytes!("../../../tests/fixtures/uboot_fit/sample.itb");

    #[test]
    fn rejects_every_truncated_prefix() {
        for length in 0..FIT.len() {
            assert!(
                Archive::open("uboot_fit", FIT[..length].to_vec()).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = FIT.to_vec();
        data[0] ^= 0xFF;
        assert!(Archive::open("uboot_fit", data).is_err());
    }

    #[test]
    fn reads_the_two_images_from_the_its_fixture() {
        let archive = Archive::open("uboot_fit", FIT.to_vec()).unwrap();
        assert_eq!(archive.names(), ["kernel-1", "fdt-1"]);
        assert!(!archive.read_named("kernel-1").unwrap().is_empty());
        assert!(!archive.read_named("fdt-1").unwrap().is_empty());
    }

    #[test]
    fn rejects_a_plain_devicetree_with_no_images_node() {
        // Same header/magic, but the "images" node name is overwritten so
        // the structure no longer has that direct child of the root.
        let mut data = FIT.to_vec();
        let needle = b"images\0";
        let position = data
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        data[position..position + 6].copy_from_slice(b"xxxxxx");
        assert!(Archive::open("uboot_fit", data).is_err());
    }

    #[test]
    fn rejects_an_fdt_end_that_arrives_before_every_node_is_closed() {
        // The structure block always ends with the root's own FDT_END_NODE
        // immediately followed by the terminal FDT_END; replacing that
        // FDT_END_NODE with another FDT_END must be rejected, since the
        // root (and everything above it) is still open at that point.
        let mut data = FIT.to_vec();
        let struct_start = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
        let struct_size = u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize;
        let struct_end = struct_start + struct_size;
        assert_eq!(
            u32::from_be_bytes(data[struct_end - 4..struct_end].try_into().unwrap()),
            FDT_END
        );
        assert_eq!(
            u32::from_be_bytes(data[struct_end - 8..struct_end - 4].try_into().unwrap()),
            FDT_END_NODE
        );
        data[struct_end - 8..struct_end - 4].copy_from_slice(&FDT_END.to_be_bytes());
        assert!(Archive::open("uboot_fit", data).is_err());
    }

    #[test]
    fn rejects_an_unknown_structure_token() {
        let mut data = FIT.to_vec();
        let struct_start = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
        data[struct_start..struct_start + 4].copy_from_slice(&0x5_u32.to_be_bytes());
        assert!(Archive::open("uboot_fit", data).is_err());
    }
}
