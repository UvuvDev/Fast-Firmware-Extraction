"""Binary Ninja adapters come exclusively from the Rust inventory."""
from binaryninja import Transform, TransformCapabilities
from easy_firmware_opening.common.native import formats
from easy_firmware_opening.common.native_container import NativeDispatcher, _registered


def test_every_native_format_has_a_generated_adapter():
    inventory = formats()
    assert inventory, "build the Rust backend before running native integration tests"
    assert {adapter.FORMAT_ID for adapter in _registered} == {info["id"] for info in inventory}
    for info in inventory:
        assert Transform[info["name"]] is not None


def test_only_one_native_adapter_participates_in_detection():
    detection = TransformCapabilities.TransformSupportsDetection
    assert NativeDispatcher.capabilities & detection
    assert all(not adapter.capabilities & detection for adapter in _registered)
