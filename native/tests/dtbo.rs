use firmware_unpack::dtbo::{Dtbo, Error};

const SAMPLE: &[u8] = include_bytes!("../../tests/fixtures/dtbo/sample.img");
const CORRUPT: &[u8] = include_bytes!("../../tests/fixtures/dtbo_corrupt/sample.img");
const AOSP_IMAGES: [&[u8]; 2] = [
    include_bytes!("../../tests/fixtures/dtbo_aosp_v0/sample.img"),
    include_bytes!("../../tests/fixtures/dtbo_aosp_v1/sample.img"),
];
const COMPILED_OVERLAYS: [&[u8]; 2] = [
    include_bytes!("../../tests/fixture_sources/dtbo/overlay0.dtbo"),
    include_bytes!("../../tests/fixture_sources/dtbo/overlay1.dtbo"),
];

fn set_word(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn extracts_fixture_payloads_without_copying() {
    let table = Dtbo::parse(SAMPLE).unwrap();
    let entries: Vec<_> = table.entries().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].offset, 96);
    assert_eq!(
        entries[0].content,
        [b"\xd0\x0d\xfe\xed".as_slice(), &b"FAKEDTB0".repeat(4)].concat()
    );
    assert_eq!(entries[1].offset, 132);
    assert_eq!(
        entries[1].content,
        [b"\xd0\x0d\xfe\xed".as_slice(), &b"FAKEDTB1".repeat(6)].concat()
    );
    assert_eq!(entries[0].content.as_ptr(), SAMPLE[96..].as_ptr());
}

#[test]
fn extracts_aosp_v0_and_v1_images_to_original_dtc_overlays() {
    // These images were created and independently extracted by the pinned
    // official AOSP tool, not by the implementation under test.
    for image in AOSP_IMAGES {
        let table = Dtbo::parse(image).unwrap();
        assert_eq!(table.entries().len(), COMPILED_OVERLAYS.len());
        for (entry, original) in table.entries().zip(COMPILED_OVERLAYS) {
            assert_eq!(entry.content, original);
            assert_eq!(entry.content.as_ptr(), image[entry.offset..].as_ptr());
        }
    }
}

#[test]
fn rejects_every_truncated_aosp_image_prefix() {
    for (version, image) in AOSP_IMAGES.iter().enumerate() {
        for length in 0..image.len() {
            assert!(
                Dtbo::parse(&image[..length]).is_err(),
                "accepted v{version} prefix of length {length}"
            );
        }
    }
}

#[test]
fn accepts_acpio_and_v1_metadata_without_changing_payloads() {
    let mut data = SAMPLE.to_vec();
    data[..4].copy_from_slice(b"ACPI");
    set_word(&mut data, 28, 1);
    // The v1 flags are metadata; this port preserves the stored bytes.
    set_word(&mut data, 48, 0x1234);
    let actual: Vec<_> = Dtbo::parse(&data)
        .unwrap()
        .entries()
        .map(|e| e.content)
        .collect();
    let expected: Vec<_> = Dtbo::parse(SAMPLE)
        .unwrap()
        .entries()
        .map(|e| e.content)
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn accepts_empty_tables_and_zero_length_payload_at_eof() {
    let mut empty = SAMPLE[..32].to_vec();
    set_word(&mut empty, 16, 0);
    assert_eq!(Dtbo::parse(&empty).unwrap().entries().len(), 0);

    let mut data = SAMPLE.to_vec();
    set_word(&mut data, 32, 0);
    set_word(&mut data, 36, SAMPLE.len() as u32);
    assert!(
        Dtbo::parse(&data)
            .unwrap()
            .entries()
            .next()
            .unwrap()
            .content
            .is_empty()
    );
}

#[test]
fn accepts_padding_before_table_and_after_payloads() {
    let mut data = SAMPLE.to_vec();
    data.splice(32..32, [0; 16]);
    set_word(&mut data, 20, 48);
    set_word(&mut data, 52, 112);
    set_word(&mut data, 84, 148);
    data.extend_from_slice(&[0; 16]);
    let table = Dtbo::parse(&data).unwrap();
    assert_eq!(
        table.entries().map(|e| e.content.len()).collect::<Vec<_>>(),
        [36, 52]
    );
}

#[test]
fn rejects_existing_corrupt_fixture() {
    assert_eq!(Dtbo::parse(CORRUPT).unwrap_err(), Error::TruncatedTable);
}

#[test]
fn rejects_every_truncated_prefix_without_panicking() {
    for length in 0..SAMPLE.len() {
        assert!(
            Dtbo::parse(&SAMPLE[..length]).is_err(),
            "accepted prefix of length {length}"
        );
    }
}

#[test]
fn rejects_wrong_magic_and_little_endian_header() {
    let mut data = SAMPLE.to_vec();
    data[..4].reverse();
    assert_eq!(Dtbo::parse(&data).unwrap_err(), Error::InvalidMagic);
    data = SAMPLE.to_vec();
    for field in data[..32].chunks_exact_mut(4) {
        field.reverse();
    }
    assert_eq!(Dtbo::parse(&data).unwrap_err(), Error::InvalidMagic);
}

#[test]
fn rejects_nonstandard_record_sizes() {
    for offset in [8, 12] {
        for size in [0, 31, 33, u32::MAX] {
            let mut data = SAMPLE.to_vec();
            set_word(&mut data, offset, size);
            assert_eq!(Dtbo::parse(&data).unwrap_err(), Error::UnsupportedLayout);
        }
    }
}

#[test]
fn rejects_table_ranges_before_iterating_or_allocating() {
    for (offset, value) in [(16, u32::MAX), (20, u32::MAX), (20, 153)] {
        let mut data = SAMPLE.to_vec();
        set_word(&mut data, offset, value);
        assert_eq!(Dtbo::parse(&data).unwrap_err(), Error::TruncatedTable);
    }
}

#[test]
fn rejects_payload_ranges_in_every_entry() {
    for record in [32, 64] {
        for (field, value) in [(0, u32::MAX), (4, u32::MAX), (4, SAMPLE.len() as u32)] {
            let mut data = SAMPLE.to_vec();
            set_word(&mut data, record + field, value);
            assert_eq!(Dtbo::parse(&data).unwrap_err(), Error::PayloadOutOfBounds);
        }
    }
}

#[test]
fn arbitrary_short_inputs_do_not_panic() {
    // A deterministic, dependency-free smoke test of the untrusted-input API.
    let mut state = 0x42_u32;
    for length in 0..512 {
        let mut data = vec![0; length];
        for byte in &mut data {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *byte = (state >> 24) as u8;
        }
        let _ = Dtbo::parse(&data);
        if length >= 32 {
            data[..4].copy_from_slice(&SAMPLE[..4]);
            set_word(&mut data, 8, 32);
            set_word(&mut data, 12, 32);
            let _ = Dtbo::parse(&data);
        }
    }
}
