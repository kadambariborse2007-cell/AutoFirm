"""
extractor.py
Automates binwalk extraction of a firmware image and returns the
path to the extracted root filesystem (not just the top extraction dir).
"""

import subprocess
import os


def extract_firmware(firmware_path: str, output_dir: str = None) -> str:
    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(f"Firmware file not found: {firmware_path}")

    work_dir = output_dir or os.path.dirname(os.path.abspath(firmware_path))

    result = subprocess.run(
        ["binwalk", "-e", "--run-as=root", firmware_path],
        cwd=work_dir,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"binwalk failed: {result.stderr}")

    extracted_dir = os.path.join(
        work_dir, f"_{os.path.basename(firmware_path)}.extracted"
    )

    if not os.path.isdir(extracted_dir):
        raise RuntimeError(
            f"binwalk did not produce expected output dir: {extracted_dir}\n"
            f"stdout: {result.stdout}"
        )

    rootfs = find_rootfs(extracted_dir)
    if not rootfs:
        raise RuntimeError(
            f"Could not locate a valid rootfs (bin/busybox) inside {extracted_dir}"
        )

    return rootfs


def find_rootfs(extracted_dir: str) -> str:
    """
    Binwalk sometimes produces multiple squashfs-root* folders (nested
    filesystems). Prefer the plain 'squashfs-root' (no numeric suffix)
    since that's usually the primary/top-level rootfs. Fall back to any
    folder that actually contains bin/busybox.
    """
    candidates = []
    for root, dirs, files in os.walk(extracted_dir):
        if os.path.basename(root).startswith("squashfs-root") and \
           os.path.isfile(os.path.join(root, "bin", "busybox")):
            candidates.append(root)

    if not candidates:
        return None

    # Prefer exact "squashfs-root" over "squashfs-root-0", "squashfs-root-1", etc.
    for c in candidates:
        if os.path.basename(c) == "squashfs-root":
            return c

    # Otherwise return the shortest path (least nested = likely top-level)
    return min(candidates, key=len)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 extractor.py <firmware_path>")
        sys.exit(1)
    print(extract_firmware(sys.argv[1]))
