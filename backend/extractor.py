"""
extractor.py
Automates binwalk extraction of a firmware image and returns the
path to the extracted filesystem.
"""

import subprocess
import os


def extract_firmware(firmware_path: str, output_dir: str = None) -> str:
    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(f"Firmware file not found: {firmware_path}")

    work_dir = output_dir or os.path.dirname(os.path.abspath(firmware_path))

    result = subprocess.run(
        ["binwalk", "-e", firmware_path],
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

    return extracted_dir


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 extractor.py <firmware_path>")
        sys.exit(1)
    print(extract_firmware(sys.argv[1]))
