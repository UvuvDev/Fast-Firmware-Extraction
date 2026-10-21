# Boot-image fixtures

Run `python3 scripts/generate_boot_fixtures.py` (or `--check`).

`boot_aosp_v0` through `boot_aosp_v4`, `init_boot_aosp_v4`, and
`vendor_boot_aosp_v3/v4` are produced by the **official, unmodified AOSP
mkbootimg.py**, pinned to `android-16.0.0_r1`. Its import-only GKI helper is
vendored alongside it; signing options are never used. Source URLs, licensing,
and hashes are in `third_party/aosp_mkbootimg/NOTICE.md`.

All payloads are synthetic strings defined in the generator. Expected hashes
come from those original inputs. The independent vendored AOSP unpacker must
return exactly those inputs before the generator writes a fixture. The kernel
crosses page boundaries. v1/v2 exercise second-stage and recovery-DTBO
segments; v2 also has a DTB. v4 vendor boot has two fragments and bootconfig.
Init boot exercises the zero-length kernel.

`boot_aosp_v4_signature` starts with official v4 producer output, then patches
the signature-size field and appends synthetic signature bytes. It exercises
segment extraction only and is **not** an authenticated/signed boot image.

`provenance.json` records producer commands, tool/input/output SHA-256 hashes,
and this mutation. The older `boot_image_v3`/`vendor_boot_v3` fixtures are
retained for compatibility, including their advisory fields.
