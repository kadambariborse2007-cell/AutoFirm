"""
pipeline.py
Chains Extraction -> Architecture Detection -> Emulation -> Service Start
-> Port Scan -> CVE Matching into a single end-to-end function.
"""

import json

from extractor import extract_firmware
from arch_detector import detect_architecture
from emulation_service import emulate_firmware
from port_scanner import start_service, scan_ports
from cve_matcher import match_scan_results

# Map of service we deliberately launch -> port, so CVE matcher can
# identify it even when the banner itself doesn't reveal the service name
SERVICE_PORT = 8888
SERVICE_MAP = {SERVICE_PORT: "uhttpd"}


def run_pipeline(firmware_path: str) -> dict:
    report = {
        "firmware_path": firmware_path,
        "stage": None,
        "success": False,
    }

    # 1. Extraction
    report["stage"] = "extraction"
    try:
        extracted_root = extract_firmware(firmware_path)
    except Exception as e:
        report["error"] = str(e)
        return report
    report["extracted_root"] = extracted_root

    # 2. Architecture Detection
    report["stage"] = "arch_detection"
    arch_result = detect_architecture(extracted_root)
    report["arch_detection"] = arch_result
    if not arch_result.get("success"):
        report["error"] = arch_result.get("error", "Architecture detection failed")
        return report
    architecture = arch_result["architecture"]

    # 3. Emulation (sanity check that firmware boots under QEMU)
    report["stage"] = "emulation"
    emulation_result = emulate_firmware(extracted_root, architecture)
    report["emulation"] = emulation_result
    if not emulation_result.get("success"):
        report["error"] = emulation_result.get("error", "Emulation failed")
        return report

    # 4. Start service inside chroot (e.g. uhttpd) for scanning
    report["stage"] = "service_start"
    service_result = start_service(extracted_root, architecture, port=SERVICE_PORT)
    report["service_start"] = service_result
    if not service_result.get("success"):
        report["error"] = service_result.get("error", "Service start failed")
        return report

    # 5. Port Scan
    report["stage"] = "port_scan"
    scan_results = scan_ports("127.0.0.1")
    report["scan_results"] = scan_results

    # 6. CVE Matching
    report["stage"] = "cve_matching"
    enriched_results = match_scan_results(scan_results, service_map=SERVICE_MAP)
    report["scan_results"] = enriched_results

    report["stage"] = "complete"
    report["success"] = True
    return report


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 pipeline.py <firmware_path>")
        sys.exit(1)

    result = run_pipeline(sys.argv[1])
    print(json.dumps(result, indent=2))
