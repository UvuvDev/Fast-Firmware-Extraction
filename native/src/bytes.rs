//! Checked binary reads shared by format modules.
use crate::archive::Result;
pub fn get(data: &[u8], start: usize, length: usize) -> Result<&[u8]> {
    start
        .checked_add(length)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| "truncated firmware or out-of-bounds range".into())
}

pub fn be32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        get(data, offset, 4)?.try_into().unwrap(),
    ))
}
pub fn le32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        get(data, offset, 4)?.try_into().unwrap(),
    ))
}
