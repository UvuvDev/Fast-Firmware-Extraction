pub mod archive;
pub mod bytes;
pub mod registry;
pub mod formats {
    include!(concat!(env!("OUT_DIR"), "/formats.rs"));
}
// Retain the parser's public path for consumers of the initial DTBO port.
pub use formats::dtbo;
mod ffi;
