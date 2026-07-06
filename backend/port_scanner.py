"""
Starts a service (uhttpd) inside the emulated firmware via chroot+QEMU,
then scans for open ports and grabs banners.
Adapted from FirmStrike's scan_ports().
"""
import subprocess
import socket
import time


def start_service(extracted_root: str, architecture: str, port: int = 8888) -> dict:
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
    ports = ports or [8888, 80, 22, 23]
    http_ports = {80, 8888, 8080, 443}
    results = []
    for port in ports:
        entry = {"port": port, "open": False, "banner": ""}
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                entry["open"] = True
                sock.settimeout(timeout)

                if port in http_ports:
                    try:
                        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    except OSError:
                        pass

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
