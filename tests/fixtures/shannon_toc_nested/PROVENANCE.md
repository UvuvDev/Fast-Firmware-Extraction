Synthetic Shannon TOC packed independently with Python struct. BOOT contains three repetitions of `synthetic BOOT code\n` followed by 528 0xff bytes that the reader trims. The zero-offset NV_NORM entry is virtual and must be skipped even though its size is 0xffffffff. MAIN contains the qcom_mbn_qcdt fixture; expected lengths and SHA-256 hashes are computed from those input bytes. No vendor firmware bytes or authentic signatures are included.

This standalone format PR verifies MAIN as an opaque, byte-identical payload.
Its expected manifest does not require the separately registered QCOM MBN,
QCDT, or DTBO parsers.
