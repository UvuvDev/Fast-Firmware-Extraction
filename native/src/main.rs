//! Generic recursive extraction; format modules know nothing about this CLI.
use firmware_unpack::{
    archive::{Archive, validate_name},
    registry,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_DEPTH: usize = 16;
// A full OS/distro ISO recursed into its nested (and often decompressed
// larger than compressed) squashfs/erofs filesystems routinely produces
// tens of GiB and six-figure file counts; 4 GiB/100,000 files was sized
// for firmware partitions, not that. 64 GiB / 1,000,000 files (matching
// the existing MAX_MEMBERS per-archive cap) still bounds a pathological
// decompression bomb while fitting a real desktop Linux live image.
const MAX_OUTPUT: u64 = 64 * 1024 * 1024 * 1024;
const MAX_FILES: usize = 1_000_000;

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(data)?;
    Ok(())
}

/// Per-directory allocator preserves Linux case collisions on macOS/Windows.
#[derive(Default)]
struct Paths {
    directories: BTreeMap<String, String>,
    taken: BTreeSet<String>,
}
impl Paths {
    fn generated_directory(&mut self, name: &str) -> String {
        // Generated archive folders must not alias a real member directory.
        let mut candidate = name.to_string();
        let mut suffix = 1;
        while self.taken.contains(&candidate.to_lowercase()) {
            candidate = format!("{name}~{suffix}");
            suffix += 1;
        }
        self.taken.insert(candidate.to_lowercase());
        candidate
    }
    fn allocate(&mut self, name: &str, directory: bool) -> String {
        let parts: Vec<_> = name.split('/').collect();
        let mut logical = String::new();
        let mut actual = String::new();
        for (index, part) in parts.iter().enumerate() {
            if !logical.is_empty() {
                logical.push('/');
            }
            logical.push_str(part);
            let is_dir = directory || index + 1 < parts.len();
            if is_dir && let Some(existing) = self.directories.get(&logical) {
                actual = existing.clone();
                continue;
            }
            let prefix = if actual.is_empty() {
                String::new()
            } else {
                format!("{actual}/")
            };
            let mut candidate = format!("{prefix}{part}");
            let mut suffix = 1;
            while self.taken.contains(&candidate.to_lowercase()) {
                candidate = format!("{prefix}{part}~{suffix}");
                suffix += 1;
            }
            self.taken.insert(candidate.to_lowercase());
            actual = candidate;
            if is_dir {
                self.directories.insert(logical.clone(), actual.clone());
            }
        }
        actual
    }
}

#[derive(Default)]
struct Budget {
    bytes: u64,
    files: usize,
}
fn extract(archive: Archive, output: &Path, depth: usize, budget: &mut Budget) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err("recursive extraction exceeds depth limit".into());
    }
    if !archive.diagnostics().is_empty() {
        eprintln!("{}", archive.diagnostics());
    }
    fs::create_dir(output)?;
    let mut paths = Paths::default();
    let manifest = paths.allocate(".ffe-paths.tsv", false);
    let mut mapping = String::from("original_path\textracted_path\tformat\tchildren_directory\n");
    for name in archive.names() {
        validate_name(name)?;
        let data = archive.read_named(name)?;
        budget.files += 1;
        budget.bytes += data.len() as u64;
        if budget.files > MAX_FILES || budget.bytes > MAX_OUTPUT {
            return Err("recursive extraction exceeds output budget".into());
        }
        let actual = paths.allocate(name, false);
        write_new(&output.join(&actual), &data)?;
        let nested = registry::detect(&data);
        let mut recursed_as = "";
        let directory = if let Some(format) = nested {
            let directory = paths.generated_directory(&format!("{actual}.unpacked"));
            match Archive::open(format.id, data) {
                Ok(child) => {
                    extract(child, &output.join(&directory), depth + 1, budget)?;
                    recursed_as = format.id;
                    directory
                }
                // A detected-but-unopenable nested format (an unsupported
                // sub-feature, or genuine corruption) must not abort
                // extraction of everything else in this archive: the
                // opaque file is already written above, so just leave it
                // un-recursed-into rather than losing the whole run over it.
                Err(error) => {
                    eprintln!("{name} ({}): {error}", format.id);
                    String::new()
                }
            }
        } else {
            String::new()
        };
        mapping.push_str(&format!("{name}\t{actual}\t{recursed_as}\t{directory}\n"));
    }
    write_new(&output.join(manifest), mapping.as_bytes())?;
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "--list-formats" {
        for format in registry::formats() {
            println!("{}\t{}", format.id, format.description);
        }
        return Ok(());
    }
    if args.len() != 3 {
        return Err("usage: firmware-unpack INPUT NEW_OUTPUT_DIRECTORY | --list-formats".into());
    }
    let mut input = Vec::new();
    fs::File::open(&args[1])?
        .take(registry::max_input_size() as u64 + 1)
        .read_to_end(&mut input)?;
    let archive = Archive::open_auto(input)?;
    let mut budget = Budget::default();
    extract(archive, Path::new(&args[2]), 0, &mut budget)?;
    println!(
        "Extracted {} files ({} bytes) to {}",
        budget.files,
        budget.bytes,
        Path::new(&args[2]).display()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("firmware-unpack: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Paths;
    #[test]
    fn generated_directories_cannot_merge_with_firmware_directories() {
        let mut paths = Paths::default();
        assert_eq!(
            paths.generated_directory("image.unpacked"),
            "image.unpacked"
        );
        assert_eq!(
            paths.allocate("image.unpacked/file", false),
            "image.unpacked~1/file"
        );
        let mut paths = Paths::default();
        assert_eq!(
            paths.allocate("image.unpacked/file", false),
            "image.unpacked/file"
        );
        assert_eq!(
            paths.generated_directory("image.unpacked"),
            "image.unpacked~1"
        );
    }
    #[test]
    fn preserves_case_collisions_and_file_directory_collisions() {
        let mut paths = Paths::default();
        assert_eq!(paths.allocate("lib/HL.so", false), "lib/HL.so");
        assert_eq!(paths.allocate("lib/hl.so", false), "lib/hl.so~1");
        assert_eq!(paths.allocate("lib/HL.so/data", false), "lib/HL.so~2/data");
        assert_eq!(paths.allocate("LIB/other", false), "LIB~1/other");
    }
}
