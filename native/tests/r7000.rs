use firmware_unpack::archive::Archive;
use firmware_unpack::formats::lzma_alone::{decode_lzma, probe_lzma};

const CHK: &[u8] = include_bytes!("../../tests/fixtures/netgear_chk/sample.bin");
const TRX: &[u8] = include_bytes!("../../tests/fixtures/trx/sample.bin");
const LZMA: &[u8] = include_bytes!("../../tests/fixtures/lzma_alone/sample.bin");
const SQUASH: &[u8] = include_bytes!("../../tests/fixtures/squashfs_mksquashfs/sample.bin");

fn set32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn fix_crc(data: &mut [u8]) {
    let crc = crc32fast::hash(&data[12..]) ^ u32::MAX;
    set32(data, 8, crc);
}

#[test]
fn complete_chain_extracts_original_inputs() {
    let chk = Archive::open("netgear_chk", CHK.to_vec()).unwrap();
    assert_eq!(chk.names(), ["firmware.trx"]);
    assert_eq!(chk.read_named("firmware.trx").unwrap(), TRX);
    let trx = Archive::open("trx", TRX.to_vec()).unwrap();
    assert_eq!(trx.names(), ["kernel.lzma", "rootfs.squashfs"]);
    assert_eq!(trx.read_named("kernel.lzma").unwrap(), LZMA);
    assert_eq!(trx.read_named("rootfs.squashfs").unwrap(), SQUASH);
    let kernel = Archive::open("lzma_alone", LZMA.to_vec()).unwrap();
    assert_eq!(
        kernel.read_named("kernel.bin").unwrap(),
        [
            0xd3, 0xf0, 0x21, 0xe3, 6, 0x33, 0xa0, 0xe3, 0, 0x40, 0xa0, 0xe3, 4, 0x40, 0x93, 0xe7
        ]
        .repeat(16)
    );
    let fs = Archive::open("squashfs", SQUASH.to_vec()).unwrap();
    assert_eq!(fs.names(), ["bin/test-data", "etc/banner"]);
    assert_eq!(
        fs.read_named("bin/test-data").unwrap(),
        b"cross-block XZ payload\n".repeat(1000)
    );
    assert_eq!(
        fs.read_named("etc/banner").unwrap(),
        b"firmware-unpack regression fixture\n"
    );
}

#[test]
fn chk_rejects_truncation_and_invalid_header_sizes() {
    for length in 0..CHK.len() {
        assert!(
            Archive::open("netgear_chk", CHK[..length].to_vec()).is_err(),
            "CHK prefix {length}"
        );
    }
    for size in [0_u32, 39, 40, u32::MAX] {
        let mut data = CHK.to_vec();
        data[4..8].copy_from_slice(&size.to_be_bytes());
        assert!(Archive::open("netgear_chk", data).is_err());
    }
}

#[test]
fn chk_preserves_vendor_trailers() {
    let mut data = CHK.to_vec();
    data.extend_from_slice(b"vendor trailer");
    let archive = Archive::open("netgear_chk", data).unwrap();
    assert_eq!(
        archive.read_named("trailer.bin").unwrap(),
        b"vendor trailer"
    );
}

#[test]
fn trx_rejects_corruption_and_every_truncated_prefix() {
    for length in 0..TRX.len() {
        assert!(
            Archive::open("trx", TRX[..length].to_vec()).is_err(),
            "TRX prefix {length}"
        );
    }
    for index in [8, TRX.len() - 1] {
        let mut data = TRX.to_vec();
        data[index] ^= 1;
        assert!(Archive::open("trx", data).is_err());
    }
}

#[test]
fn trx_rejects_invalid_offsets_even_with_a_valid_crc() {
    for (slot, value) in [
        (16, 1),
        (16, TRX.len() as u32),
        (20, 28),
        (20, u32::MAX),
        (24, 30),
    ] {
        let mut data = TRX.to_vec();
        set32(&mut data, slot, value);
        fix_crc(&mut data);
        assert!(Archive::open("trx", data).is_err());
    }
}

#[test]
fn trx_v2_extracts_four_partitions() {
    let mut data = vec![0; 48];
    data[..4].copy_from_slice(b"HDR0");
    set32(&mut data, 4, 48);
    set32(&mut data, 12, 2 << 16);
    for index in 0..4 {
        set32(&mut data, 16 + index * 4, 32 + index as u32 * 4);
    }
    data[32..].copy_from_slice(b"aaaabbbbccccdddd");
    fix_crc(&mut data);
    let archive = Archive::open("trx", data).unwrap();
    for (index, expected) in [b"aaaa", b"bbbb", b"cccc", b"dddd"].iter().enumerate() {
        assert_eq!(&archive.read(index).unwrap(), expected);
    }
}

#[test]
fn lzma_supports_unknown_size_and_rejects_oversized_headers() {
    assert!(probe_lzma(LZMA));
    let mut data = LZMA.to_vec();
    data[5..13].fill(255);
    assert_eq!(decode_lzma(&data).unwrap(), decode_lzma(LZMA).unwrap());
    data[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_lzma(&data).is_err());
    data = LZMA.to_vec();
    data[5..13].copy_from_slice(&(1024_u64 * 1024 * 1024).to_le_bytes());
    assert!(decode_lzma(&data).is_err());
}

#[test]
fn lzma_rejects_invalid_and_truncated_data() {
    for length in 0..18 {
        assert!(decode_lzma(&LZMA[..length]).is_err());
    }
    assert!(!probe_lzma(
        b"\x7fELF\x01\x01\x01\0\0\0\0\0\0\0\0\0\0\0\0\0"
    ));
    let mut data = LZMA.to_vec();
    data.extend_from_slice(b"not padding");
    assert!(decode_lzma(&data).is_err());
}

#[test]
fn squashfs_rejects_invalid_sizes_and_unsupported_compression() {
    for (offset, value) in [(12, 0_u32), (12, 17), (28, 3), (20, 1), (40, u32::MAX)] {
        let mut data = SQUASH.to_vec();
        set32(&mut data, offset, value);
        assert!(Archive::open("squashfs", data).is_err());
    }
    for length in 0..96 {
        assert!(Archive::open("squashfs", SQUASH[..length].to_vec()).is_err());
    }
}

#[test]
fn invalid_file_requests_fail_without_panicking() {
    let archive = Archive::open("netgear_chk", CHK.to_vec()).unwrap();
    assert!(archive.read(usize::MAX).is_err());
    assert!(archive.read_named("../../outside").is_err());
}
