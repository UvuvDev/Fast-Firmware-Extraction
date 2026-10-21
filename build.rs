//! Every format is a sibling file exporting FORMAT; no hand-maintained list.
use std::{env, fs, path::PathBuf};

fn main() {
    let directory =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("native/src/formats");
    println!("cargo:rerun-if-changed={}", directory.display());
    let mut files: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect();
    files.sort();
    let mut generated = String::new();
    for path in &files {
        let id = path.file_stem().unwrap().to_str().unwrap();
        assert!(
            id.starts_with(|c: char| c.is_ascii_lowercase())
                && id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "format filenames must be lowercase Rust identifiers: {id}"
        );
        println!("cargo:rerun-if-changed={}", path.display());
        generated.push_str(&format!("#[path = {path:?}] pub mod {id};\n"));
    }
    generated.push_str("pub static FORMATS: &[crate::registry::FormatDescriptor] = &[\n");
    for path in &files {
        generated.push_str(&format!(
            "{}::FORMAT,\n",
            path.file_stem().unwrap().to_str().unwrap()
        ));
    }
    generated.push_str("];\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("formats.rs"),
        generated,
    )
    .unwrap();
}
