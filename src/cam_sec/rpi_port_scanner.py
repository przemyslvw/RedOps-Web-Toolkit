from scapy.all import IP, TCP, sr1
import sys

# Lista portów do sprawdzenia zgodnie z planem
INTERESTING_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1883: "MQTT",
    5900: "VNC",
    8080: "HTTP-Alt"
}

def scan_ports(target_ip):
    print(f"[*] Rozpoczynanie skanowania portów dla {target_ip}...")
    print(f"[*] Sprawdzane porty: {list(INTERESTING_PORTS.keys())}")
    
    open_ports = []
    
    for port in INTERESTING_PORTS:
        # TCP SYN Scan
        # Flag 'S' = SYN
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        # Oczekiwanie na odpowiedź (timeout krótki dla sieci lokalnej)
        response = sr1(packet, timeout=1, verbose=0)
        
        if response:
            # Sprawdzenie flagi w odpowiedzi
            # 0x12 = SYN+ACK (Open)
            # 0x14 = RST+ACK (Closed)
            if response.haslayer(TCP):
                flags = response.getlayer(TCP).flags
                if flags == 0x12:
                    service = INTERESTING_PORTS[port]
                    print(f"\033[92m[+] Port {port} ({service}) jest OTWARTY\033[0m")
                    open_ports.append(port)
                elif flags == 0x14:
                    # print(f"[-] Port {port} jest zamknięty")
                    pass
        else:
             # Brak odpowiedzi (Filtered/Firewalled)
             # print(f"[-] Port {port} filtrowany (brak odpowiedzi)")
             pass

    print("-" * 40)
    print(f"[*] Skanowanie zakończone. Otwarte porty: {open_ports}")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Użycie: sudo python3 rpi_port_scanner.py <TARGET_IP>")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_ports(target)
