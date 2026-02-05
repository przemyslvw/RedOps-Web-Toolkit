from scapy.all import ARP, Ether, srp
import sys
import ipaddress
import socket

# Znane prefiksy MAC adresów Raspberry Pi (OUI)
RPI_MAC_PREFIXES = [
    "B8:27:EB",
    "DC:A6:32",
    "E4:5F:01",
    "28:CD:C1",
    "D8:3A:DD",
    "2C:CF:67",
    "DE:9D:C0" # Dodatkowy
]

def get_local_ip_and_cidr():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    
    # Proste założenie maski /24 dla sieci domowej, można by to pobierać dokładniej
    return IP, "24"

def scan_network(target_ip):
    print(f"[*] Skanowanie sieci: {target_ip} ...")
    
    # Tworzenie pakietu ARP
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Wysyłanie i odbieranie (timeout 2s)
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    print(f"[*] Znaleziono {len(result)} urządzeń:")
    print("-" * 60)
    print(f"{'IP Address':<20} {'MAC Address':<20} {'Vendor/Note'}")
    print("-" * 60)

    found_rpi = False

    for sent, received in result:
        mac = received.hwsrc.upper()
        ip = received.psrc
        vendor = "Unknown"
        
        # Sprawdzanie czy to RPi
        is_rpi = False
        for prefix in RPI_MAC_PREFIXES:
            if mac.startswith(prefix):
                vendor = "RASPBERRY PI FOUND!"
                is_rpi = True
                found_rpi = True
                break
        
        if is_rpi:
            # Highlight RPi
            print(f"\033[92m{ip:<20} {mac:<20} {vendor}\033[0m")
        else:
            print(f"{ip:<20} {mac:<20} {vendor}")
            
        devices.append({'ip': ip, 'mac': mac, 'is_rpi': is_rpi})

    print("-" * 60)
    if not found_rpi:
        print("[-] Nie znaleziono Raspberry Pi w tej sieci.")
    else:
        print("[+] Skanowanie zakończone pomyślnie. Zidentyfikowano potencjalne cele.")

    return devices

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # Automatyczne wykrywanie podsieci
        local_ip, cidr = get_local_ip_and_cidr()
        # np. 192.168.1.15 -> 192.168.1.0/24
        network_prefix = ".".join(local_ip.split('.')[:-1]) + ".0/" + cidr
        target = network_prefix
        print(f"[*] Wykryto lokalne IP: {local_ip}")
    
    scan_network(target)
