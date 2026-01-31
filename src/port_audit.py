#!/usr/bin/env python3
import subprocess
import sys
import socket
from colorama import Fore, Style, init

# Inicjalizacja
init(autoreset=True)

COMMON_PORTS = {
    80: "HTTP (Web)",
    443: "HTTPS (Web Secure)",
    8080: "Alt-HTTP (Proxy/Dev)",
    8443: "Alt-HTTPS (Proxy/Dev)",
    22: "SSH (Admin)",
    21: "FTP",
    3389: "RDP",
    54560: "Dev Port (znaleziony w CSP!)" 
}

def check_connectivity(target, port=443):
    """Sprawdza czy w ogóle mamy styk z serwerem, udając zwykłe gniazdo"""
    print(f"{Fore.CYAN}[*] Test łączności (Socket Connect) na porcie {port}...{Style.RESET_ALL}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            print(f"{Fore.GREEN}[OK] Połączenie socketowe udane! Host żyje.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] Socket connect failed. Firewall wycina pakiety lub brak routingu.{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}[!] Błąd socketa: {e}{Style.RESET_ALL}")
        return False

def run_legit_scan(target):
    print(f"\n{Fore.YELLOW}[*] Uruchamiam Nmap w trybie TCP Connect (-sT -Pn)...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[i] Info: To najwolniejsza, ale najbardziej 'naturalna' metoda.{Style.RESET_ALL}")

    # Budujemy listę portów do sprawdzenia
    ports_str = ",".join(map(str, COMMON_PORTS.keys()))

    command = [
        "nmap",
        "-sT",          # Pełne połączenie TCP (trudniejsze do odróżnienia od przeglądarki)
        "-Pn",          # Nie pinguj (zakładamy że żyje)
        "-p", ports_str, # Skanuj tylko konkretne porty (mniej hałasu = mniejsza szansa na bana)
        "--open",       # Pokaż tylko otwarte
        "-n",           # Bez rozwiązywania nazw DNS (szybciej)
        target
    ]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        found = False
        for line in process.stdout:
            line = line.strip()
            if "/tcp" in line and "open" in line:
                found = True
                print(f"{Fore.GREEN}[+] ZNALEZIONO: {line}{Style.RESET_ALL}")
        
        if not found:
            print(f"{Fore.RED}[-] Nmap nadal nic nie widzi.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[Hint] Jeśli test socketowy (wyżej) przeszedł, a Nmap nie -> Admin wyciął sygnaturę User-Agent Nmapa.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Błąd: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Użycie: python3 {sys.argv[0]} <host>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 1. Najpierw prosty test czy w ogóle sieć działa
    if check_connectivity(target):
        # 2. Jeśli działa, puszczamy Nmapa
        run_legit_scan(target)
    else:
        print(f"\n{Fore.MAGENTA}[!] DIAGNOZA:{Style.RESET_ALL}")
        print("Nie mogę nawiązać połączenia nawet przez Pythona.")
        print("1. Czy jesteś połączony z VPN? (Jeśli to środowisko wewnętrzne)")
        print("2. Czy Twój IP jest na Whiliście?")
        print("3. Spróbuj: traceroute -p 443 " + target)