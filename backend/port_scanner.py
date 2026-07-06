"""
port_scanner.py
Starts a service (uhttpd) inside the emulated firmware via chroot+QEMU,
then scans for open ports and grabs banners.
Adapted from FirmStrike's scan_ports().
"""

import subprocess
import socket
import time


def start_service(extracted_root: str, architecture: str, port: int = 8888) -> dict:
    """
    Launch uhttpd inside the chroot using the QEMU binary already copied
    into extracted_root by qemu_launcher.run_emulation().
    """
    qemu_binary = f"./qemu-{architecture}"
    service_binary = "/usr/sbin/uhttpd"

    try:
        subprocess.Popen(
            [
                "chroot", extracted_root, qemu_binary,
                service_binary, "-p", str(port), "-h", "/www",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        return {"success": True, "port": port}
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan_ports(host: str, ports=None, timeout: float = 1.0) -> list:
    """
    Scan `host` for open ports and attempt a banner grab on each.
    """
    ports = ports or [8888, 80, 22, 23]
    results = []

    for port in ports:
        entry = {"port": port, "open": False, "banner": ""}
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                entry["open"] = True
                sock.settimeout(timeout)
                try:
                    banner = sock.recv(1024)
                    entry["banner"] = banner.decode(errors="replace").strip()
                except socket.timeout:
                    pass
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        results.append(entry)

    return results


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(json.dumps(scan_ports(target), indent=2))
