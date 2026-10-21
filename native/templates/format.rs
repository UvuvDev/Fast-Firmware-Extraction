//! EXAMPLE ONLY: four-byte EXMP magic, LE u32 size, stored payload.
//! Replace the example layout with a verified specification/reference and
//! record that source, license, and fixture provenance here.
use crate::archive::{ArchiveReader, Member, RangeArchive, Result};
use crate::bytes::{get, le32};
use crate::registry::{FormatDescriptor, Signature};

pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "example_frame",
    name: "ExampleFrame",
    description: "Example frame (replace with the real format)",
    signatures: &[Signature::new(0, b"EXMP")],
    probe: None,
    open,
};

fn open(data: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
    if get(&data, 0, 4)? != b"EXMP" {
        return Err("bad example magic".into());
    }
    let size = le32(&data, 4)? as usize;
    let end = 8_usize.checked_add(size).ok_or("payload size overflow")?;
    let members = vec![Member { name: "payload.bin".into(), range: 8..end }];
    Ok(Box::new(RangeArchive::new(data, members)?))
}
