# F2FS fixtures and scope

All images are hand-built regression fixtures, not produced by mkfs.f2fs or
captured from hardware. The reader supports 4 KiB blocks and reads static NAT
entries only. Inline xattrs, compressed/encrypted files, checkpoint payload
overflow, large NAT bitmap layouts, NAT journal/roll-forward replay and checksum
verification remain unsupported. A valid checkpoint version pair alone does
not establish that journal entries are unnecessary; this is a limited extractor,
not a complete F2FS mount/recovery implementation.

The existing `f2fs` fixture has inline files, an inline directory, a block-backed
subdirectory, an extra-attribute inode and a direct multi-block file. During the
Rust port its directory bitmaps were changed from MSB to LSB order, occupied
continuation bits for long names were filled, and placeholder node footer IDs
were populated. File bytes and expected hashes are unchanged. `f2fs_corrupt`
is truncated before its referenced NAT/inode data.

Regenerate the additional images (and normalize the original fixture idempotently):

    python3 tests/fixture_sources/f2fs/generate.py

`f2fs_mapped` chooses the newer checkpoint and the second NAT copy using its
MSB version bit; the stale NAT copy deliberately has no valid entries. An inline
directory has long names occupying multiple LSB bitmap slots. A skipped symlink,
a 3,784,741-byte file reaching a direct node, and a 12,120,161-byte sparse file
reaching an indirect node exercise the namespace and mappings. Physical images
are only 245,760 bytes; expected holes are synthesized from explicit zeroes
and expected hashes from source payloads, without invoking the reader.
`f2fs_secondary` has the same content with a bad primary superblock, exercising
recognition via the secondary signature at offset 5120.

Python parity checks all three valid images against the corrected legacy reader.
Inline Rust tests exercise checkpoint fallback, differing NAT/directory bit
orders, NAT/footer ownership, inline and extra-attribute bounds, malformed name
slots, unsupported features and every node-pointer tier. Double-indirect
subtrees are tested directly: their ordinary file offset exceeds the shared
512 MiB output limit, so no multi-gigabyte output is allocated for the test.

Layout facts were rechecked against Linux v6.12, without copying implementation
code from these GPL-licensed sources:

- [On-disk fields and node footers](https://github.com/torvalds/linux/blob/v6.12/include/linux/f2fs_fs.h).
- [Directory bitmap order and multi-slot names](https://github.com/torvalds/linux/blob/v6.12/fs/f2fs/dir.c).
- [NAT bitmap order and checkpoint bitmap layout](https://github.com/torvalds/linux/blob/v6.12/fs/f2fs/f2fs.h).

The Python source documents the original independent layout research. These
fixtures establish regression/parity coverage, not real-device compatibility.
