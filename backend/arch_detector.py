"""
arch_detector.py
Detects CPU architecture of an extracted firmware filesystem by parsing
the output of the `file` command against the busybox binary.
"""

import subprocess
import os


def detect_architecture(extracted_root: str) -> dict:
    busybox_path = os.path.join(extracted_root, "bin", "busybox")

    if not os.path.exists(busybox_path):
        return {
            "success": False,
            "error": "busybox not found in extracted firmware",
        }

    result = subprocess.run(
        ["file", busybox_path],
        capture_output=True,
        text=True,
    )

    output = result.stdout
    architecture = "unknown"

    if "MIPS" in output:
        architecture = "mips"
    elif "ARM" in output:
        architecture = "arm"
    elif "80386" in output or "x86" in output:
        architecture = "x86"

    return {
        "success": True,
        "architecture": architecture,
        "raw_output": output.strip(),
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python3 arch_detector.py <extracted_rootfs_path>")
        sys.exit(1)

    print(json.dumps(detect_architecture(sys.argv[1]), indent=2))
