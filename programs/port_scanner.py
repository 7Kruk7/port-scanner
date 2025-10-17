from scapy.all import ARP, Ether, srp
import ipaddress
import psutil
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from prometheus_client import start_http_server, Counter
import errno
from pathlib import Path
import os

# Prometheus counter (example)
calculation_total_ports = Counter('calculation_total_ports', 'Total number of ports scanned')

def scan_port(ip, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            return (port, "open")
        elif result in (errno.ECONNREFUSED, 10061):
            return (port, "closed")
        else:
            return (port, "filtered")
    except Exception:
        return (port, "filtered")
    finally:
        s.close()

# Output directory (safe, script-relative)
script_dir = Path(__file__).resolve().parent
output_dir = script_dir / "files"
output_dir.mkdir(parents=True, exist_ok=True)  # avoids PermissionError if allowed

# Find first suitable IPv4 interface (skip loopback/APIPA)
interfaces = psutil.net_if_addrs()
network = None
for iface, addrs in interfaces.items():
    for addr in addrs:
        if addr.family == socket.AF_INET and not addr.address.startswith("127.") and not addr.address.startswith("169.254."):
            ip_addr = addr.address
            netmask = addr.netmask  # e.g. '255.255.255.0'
            # Build network
            try:
                network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
                print(f"Using interface {iface}: {ip_addr}/{netmask} -> {network}")
                break
            except Exception as e:
                print("Failed to parse network from", ip_addr, netmask, e)
    if network is not None:
        break

if network is None:
    raise SystemExit("No suitable IPv4 interface found. Are you connected?")

# ARP scan (requires admin/npacp on Windows)
arp = ARP(pdst=str(network))
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp
ans = srp(packet, timeout=2, verbose=1)[0]  # ans is list of (sent, recv)

# Start Prometheus server early (so metrics can be scraped while scanning)
start_http_server(8000)

output_file = output_dir / "output.txt"
with output_file.open("w", encoding="utf-8") as file:
    for sent, received in ans:
        host_ip = received.psrc
        file.write(f"Host: {host_ip}\n")
        # We'll scan ports 1..1024
        calculation_total_ports.inc(1024)  # example increment; adjust semantics as needed
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, host_ip, port) for port in range(1, 1025)]
            for future in as_completed(futures):
                port, status = future.result()
                if status != "filtered":
                    file.write(f"  {port}: {status}\n")
        file.write("\n")

print("Scan complete. Results in:", output_file)
