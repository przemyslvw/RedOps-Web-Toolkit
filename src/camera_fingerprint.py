import socket
import sys
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from host_discovery import start_scanner

# Target ports for cameras
CAMERA_PORTS = [554, 80, 8080, 81, 8000, 37777, 1935]

# Common Camera MAC OUIs (Prefixes)
# You can expand this list with more manufacturers
CAMERA_OUIS = {
    "00:40:8C": "Axis Communications",
    "00:0F:7C": "Dahua Technology",
    "E0:50:8B": "Dahua Technology",
    "10:12:FB": "Dahua Technology",
    "4C:11:BF": "Dahua Technology", # Specific sub-brands
    "80:69:1A": "Hikvision",
    "44:E0:41": "Hikvision",
    "1C:B0:94": "Hikvision",
    "18:6C:C6": "Hikvision",
    "00:09:33": "Foscam",
    "00:62:6E": "Foscam",
    "00:80:F0": "Panasonic",
    "00:02:D1": "Vivotek",
    "00:13:07": "Paragon Software (Often used in embedded cams)",
    "B0:C5:54": "D-Link",
    "00:1B:11": "D-Link",
}

def get_mac_address(ip_address):
    """
    Retrieves the MAC address for a given IP from the system's ARP table.
    Works on Linux.
    """
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip_address:
                    return parts[3]
    except FileNotFoundError:
        print("[-] Could not read /proc/net/arp")
    return None

def check_port(ip, port):
    """
    Checks if a TCP port is open.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    result = sock.connect_ex((ip, port))
    sock.close()
    return port if result == 0 else None

def scan_ports(ip):
    """
    Scans the target IP for common camera ports.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(check_port, ip, port) for port in CAMERA_PORTS]
        for future in futures:
            port = future.result()
            if port:
                open_ports.append(port)
    return open_ports

def identify_vendor(mac_address):
    """
    Identifies the vendor based on the MAC OUI.
    """
    if not mac_address:
        return "Unknown"
    
    # Normalize MAC to uppercase
    mac = mac_address.upper()
    prefix = mac[:8].replace('-', ':') # standard format XX:XX:XX
    
    return CAMERA_OUIS.get(prefix, "Unknown")

def main():
    print("=============================================")
    print("   Camera Fingerprint Scanner")
    print("=============================================")
    
    # Step 1: Discover Hosts
    # We pass None to let it auto-detect subnet, or sys.argv[1] if provided
    target_subnet = sys.argv[1] if len(sys.argv) > 1 else None
    
    print("\n[Phase 1] discovering active hosts...")
    # This requires root for raw sockets
    try:
        active_hosts = start_scanner(target_subnet)
    except SystemExit:
        # host_discovery might exit if root is missing
        return
    except Exception as e:
        print(f"[-] Discovery failed: {e}")
        return

    if not active_hosts:
        print("[-] No hosts found.")
        return

    print(f"\n[Phase 2] Fingerprinting {len(active_hosts)} hosts...")
    print(f"{'IP Address':<16} | {'MAC Address':<18} | {'Vendor':<20} | {'Open Ports'}")
    print("-" * 80)

    potential_cameras = []

    for host in active_hosts:
        # Get MAC
        mac = get_mac_address(host)
        
        # Identify Vendor
        vendor = identify_vendor(mac)
        
        # Scan Ports
        ports = scan_ports(host)
        
        ports_str = ", ".join(map(str, ports)) if ports else "None"
        
        print(f"{host:<16} | {str(mac):<18} | {vendor:<20} | {ports_str}")

        # Heuristic for "Likely Camera"
        # 1. Known Camera Vendor
        # 2. Open RTSP (554) or 8000 (Hikvision)
        if vendor != "Unknown" or 554 in ports or 8000 in ports:
            potential_cameras.append((host, ports))

    print("-" * 80)
    if potential_cameras:
        print(f"\n[+] Found {len(potential_cameras)} potential cameras!")
        for cam_ip, cam_ports in potential_cameras:
            print(f"    -> {cam_ip} (Ports: {cam_ports})")
            print(f"       Try: rtsp://{cam_ip}:554/")
    else:
        print("\n[-] No obvious cameras identified.")

if __name__ == "__main__":
    main()
