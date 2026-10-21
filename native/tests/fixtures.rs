//! All native fixture directories are discovered at runtime, without a list.
use firmware_unpack::{archive::Archive, registry};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

fn check(archive: Archive, children: &Value, label: &str) {
    let children = children.as_object().expect("children must be an object");
    assert_eq!(
        archive.names().iter().collect::<BTreeSet<_>>(),
        children.keys().collect(),
        "{label}"
    );
    for (name, info) in children {
        let data = archive
            .read_named(name)
            .unwrap_or_else(|e| panic!("{label}/{name}: {e}"));
        assert_eq!(
            data.len() as u64,
            info["length"].as_u64().expect("length required"),
            "{label}/{name}"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&data)),
            info["sha256"].as_str().expect("sha256 required"),
            "{label}/{name}"
        );
        if info.get("children").is_some() {
            check(
                Archive::open_auto(data).unwrap(),
                &info["children"],
                &format!("{label}/{name}"),
            );
        }
    }
}

#[test]
fn all_native_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut directories: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    directories.sort();
    let mut covered = BTreeSet::new();
    let mut corrupt = BTreeSet::new();
    for directory in directories {
        let path = directory.join("expected.json");
        if !path.is_file() {
            continue;
        }
        let expected: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let Some(id) = expected["native_format"].as_str() else {
            continue;
        };
        assert!(registry::get(id).is_some(), "unknown native_format: {id}");
        let data = fs::read(directory.join(expected["sample"].as_str().unwrap())).unwrap();
        let label = directory.display().to_string();
        if expected["expect_failure"] == true {
            assert!(
                Archive::open(id, data).is_err(),
                "{label}: accepted corrupt fixture"
            );
            corrupt.insert(id.to_string());
        } else {
            assert_eq!(
                registry::detect(&data).map(|format| format.id),
                Some(id),
                "{label}: detection"
            );
            check(
                Archive::open_auto(data).unwrap(),
                &expected["children"],
                &label,
            );
            covered.insert(id.to_string());
        }
    }
    for format in registry::formats() {
        assert!(
            covered.contains(format.id),
            "{} needs a valid native fixture",
            format.id
        );
        assert!(
            corrupt.contains(format.id),
            "{} needs a corrupt native fixture",
            format.id
        );
    }
}
