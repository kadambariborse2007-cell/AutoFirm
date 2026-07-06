from port_scanner import start_service, scan_ports
import json

root = '/home/kali/AutoFirm/test-firmware/_openwrt-25.12.5-ath79-generic-adtran_bsap1800-v2-squashfs-sysupgrade.bin.extracted/sysupgrade-adtran_bsap1800-v2/_root.extracted/squashfs-root'

start_result = start_service(root, 'mips', 8888)
print('Start service:', json.dumps(start_result, indent=2))

scan_result = scan_ports('127.0.0.1')
print('Scan result:', json.dumps(scan_result, indent=2))
