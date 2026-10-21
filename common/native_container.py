"""One adapter for all Rust formats, generated from the native inventory."""
from binaryninja import DataBuffer, TransformCapabilities
from .container_base import FilesystemContainer
from .native import NativeArchive, detect, formats, open_archive


class NativeContainer(FilesystemContainer):
    FORMAT_ID = None
    # Named format adapters are available for explicit selection. A single
    # dispatcher detects all formats, avoiding N Python callbacks per input.
    capabilities = TransformCapabilities.TransformSupportsContext

    def decode_without_selection(self, fs: NativeArchive, context):
        if not fs.is_stream:
            return None
        child = context.create_child(DataBuffer(fs.read(fs.names[0])), "")
        self.configure_child(child, fs.names[0])
        return True

    def perform_decode(self, data: bytes, params: dict):
        with self.open_filesystem(data) as archive:
            return archive.read(archive.names[0]) if archive.is_stream else None

    def configure_child(self, child, path: str) -> None:
        info = detect(child.input.read(0, min(child.input.length, 65536)))
        if info:
            child.set_transform_name(info["name"])

    def open_filesystem(self, data: bytes) -> NativeArchive:
        archive = open_archive(self.FORMAT_ID, data)
        if archive is None:
            raise RuntimeError("Rust unpacker is not built; run cargo build --release and restart Binary Ninja")
        return archive

    def list_paths(self, fs: NativeArchive) -> list[str]:
        return list(fs.names)

    def read_file(self, fs: NativeArchive, path: str) -> bytes:
        return fs.read(path)


class NativeDispatcher(NativeContainer):
    name = "FirmwareNative"
    long_name = "Firmware containers (Rust)"
    capabilities = FilesystemContainer.capabilities

    def can_decode(self, input) -> bool:
        return detect(input.read(0, min(input.length, 65536))) is not None


_registered = []


def register_formats():
    inventory = formats()
    for info in inventory:
        adapter = type(info["name"], (NativeContainer,), {
            "FORMAT_ID": info["id"], "name": info["name"], "long_name": info["description"],
        })
        adapter.register()
        _registered.append(adapter)
    if inventory:
        NativeDispatcher.register()
