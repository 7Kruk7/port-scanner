# Important, the code must be run in order to verify it correctness, prometheus lines are added

from scapy.all import ARP, Ether, srp
import ipaddress
import psutil
import socket
import scan_port_function as spf
from concurrent.futures import ThreadPoolExecutor, as_completed
from prometheus_client import start_http_server, Counter # new line for `prometheus`

calculation_total_ports = Counter('calculation_total_ports', 'Total number of ports scanned') # new line for `prometheus`
#read the network IP address from the host IP and the subnet address
interfaces = psutil.net_if_addrs()

network  = ""
for interface_name, addresses in interfaces.items():
    for addr in addresses:
        calculation_total_ports.inc() # new line for `prometheus`
        if addr.family == socket.AF_INET and not(addr.address.startswith("127.")) and not(addr.address.startswith("169.254.")):
            my_IP_address = addr.address
            my_MAC_address = addr.netmask
            network = ipaddress.IPv4Network(f"{my_IP_address}/{my_MAC_address}", strict=False)

arp = ARP(pdst=str(network)) #network was an object, but ARP function requires string as an argument
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp
result = srp(packet, timeout=1, verbose=0)[0]

#scanning the network
with open("../files/output.txt", 'w') as file:
    for sent, recived in result:
        ip = recived.psrc
        result = []
        with ThreadPoolExecutor(100) as executor:
            ports_status = [executor.submit(spf.scan_port, ip, port) for port in range(1,1025)]
            for future in as_completed(ports_status):
                port, status = future.result()
                if status != "filtered":
                    file.write(f"Host: {ip}, {port}: {status} \n")
        file.write("\n")

start_http_server(8000)