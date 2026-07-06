"""
emulation_service.py
Wraps qemu_launcher to auto-select the right QEMU binary based on the
architecture detected by arch_detector.py.
"""

from qemu_launcher import run_emulation

SUPPORTED_ARCHES = ["mips", "arm", "x86"]


def emulate_firmware(extracted_root: str, architecture: str) -> dict:
    if architecture not in SUPPORTED_ARCHES:
        return {
            "success": False,
            "error": f"Unsupported or unknown architecture: {architecture}",
        }

    return run_emulation(extracted_root, architecture)
