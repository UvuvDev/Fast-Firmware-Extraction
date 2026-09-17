# Container Browser Extension Plugin

Tired of spending an hour per firmware image doing endless extraction? Use Binary Ninja's builtin container browser and have it automated instead!

## Supported formats

- **FBPack** — Fastboot Package (FBPK) v1/v2
- **AndroidBootImage** — Android Boot / Vendor Boot Image
- **AndroidSparse** — Android Sparse Image
- **AndroidSelfExtract** — Android self-extracting vendor blob
- **Dtbo** — DTBO / DT Table Image
- **Qcdt** — Qualcomm Device Tree Table (QCDT)
- **QcomMbn** — Qualcomm Legacy MBN Firmware Header
- **ShannonTOC** — Samsung Shannon Baseband TOC
- **UnisocMECP** — Unisoc CP memory-decoupling modem image
- **FwTypeHeader** — Vendor fw-type Header
- **Gpt** — GUID Partition Table (GPT)
- **Ext4** — ext4 filesystem
- **Erofs** — EROFS filesystem
- **F2fs** — F2FS filesystem
- **Squashfs** — SquashFS filesystem
- **Ubi** — UBI flash image

Adding a new format has a single file format under `formats/` — see [docs/ADDING_A_FORMAT.md](docs/ADDING_A_FORMAT.md). This can be incredibly easily automated with AI (most of this was AI generated), so if you find a new format, please contribute it! The primary difficulty is not the actual format implementation, it's just variety of images and firmwares. Lots of formats that random Vendors will use one off. 

