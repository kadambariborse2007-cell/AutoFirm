"""
qemu_launcher.py
Low-level QEMU chroot emulation logic, adapted from FirmStrike.
"""

import subprocess
import shutil
import os


def run_emulation(extracted_root: str, architecture: str) -> dict:
    """
    Copy the correct qemu-user-static binary into the rootfs and run a
    simple sanity command (busybox ls) inside a chroot to confirm the
    firmware boots under emulation.
    """
    qemu_binary = f"qemu-{architecture}"
    qemu_source = shutil.which(qemu_binary)

    if not qemu_source:
        return {
            "success": False,
            "error": f"{qemu_binary} not found on system",
        }

    qemu_dest = os.path.join(extracted_root, qemu_binary)

    try:
        if not os.path.exists(qemu_dest):
            shutil.copy(qemu_source, qemu_dest)
            os.chmod(qemu_dest, 0o755)

        result = subprocess.run(
            ["chroot", extracted_root, f"./{qemu_binary}", "./bin/busybox", "ls"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Emulation timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}
