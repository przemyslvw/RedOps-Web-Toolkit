#!/usr/bin/env python3
import requests
import sys
import urllib3
from colorama import Fore, Style, init

# Inicjalizacja
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def audit_headers(url):
    print(f"{Fore.CYAN}[*] Rozpoczynam ZAAWANSOWANY audyt nagłówków (v2) dla: {url}{Style.RESET_ALL}")
    
    # 1. Nagłówki Wymagane (Hardening & Isolation)
    security_headers = {
        "Strict-Transport-Security": "Wymusza HTTPS (HSTS)",
        "Content-Security-Policy": "Mitygacja XSS i Data Injection (Kluczowe!)",
        "X-Frame-Options": "Ochrona przed Clickjackingiem",
        "X-Content-Type-Options": "Blokada MIME-sniffing",
        "Referrer-Policy": "Kontrola wycieku danych w nagłówku Referer",
        "Permissions-Policy": "Kontrola dostępu do API przeglądarki",
        "X-Permitted-Cross-Domain-Policies": "Blokada polityk Adobe/Flash",
        "Cross-Origin-Opener-Policy": "Izolacja kontekstu przeglądania (COOP) - ochrona przed atakami XS-Leaks",
        "Cross-Origin-Embedder-Policy": "Wymusza ładowanie tylko bezpiecznych zasobów (COEP)",
        "Cross-Origin-Resource-Policy": "Ochrona zasobów przed ładowaniem przez obce serwisy (CORP)",
        "X-XSS-Protection": "Filtr XSS (Legacy - nowoczesne standardy zalecają CSP)"
    }

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSentinel/Audit-v2'}
        response = requests.get(url, headers=headers, verify=False, timeout=10)

        print(f"{Fore.BLUE}[INFO] Status Code: {response.status_code}{Style.RESET_ALL}\n")

        # Analiza obecności nagłówków
        for header, description in security_headers.items():
            if header in response.headers:
                value = response.headers[header]
                print(f"{Fore.GREEN}[+] {header}: OBECNY{Style.RESET_ALL}")
                print(f"    Wartość: {value}")
                
                # --- HEURYSTYKA BŁĘDÓW ---
                # CSP
                if header == "Content-Security-Policy" and ("unsafe-inline" in value or "unsafe-eval" in value):
                    print(f"{Fore.YELLOW}    [!] OSTRZEŻENIE: CSP zawiera 'unsafe-inline' lub 'unsafe-eval'.{Style.RESET_ALL}")
                if header == "Content-Security-Policy" and "localhost" in value:
                    print(f"{Fore.RED}    [!] KRYTYCZNE: Wykryto 'localhost' w CSP na produkcji!{Style.RESET_ALL}")
                
                # X-Frame-Options
                if header == "X-Frame-Options" and value not in ["DENY", "SAMEORIGIN"]:
                    print(f"{Fore.YELLOW}    [!] OSTRZEŻENIE: Słaba wartość X-Frame-Options.{Style.RESET_ALL}")
                
                # X-XSS-Protection (Legacy check)
                if header == "X-XSS-Protection" and value != "0":
                     print(f"{Fore.LIGHTBLACK_EX}    [i] Info: Ten nagłówek jest przestarzały. Zalecane ustawienie to '0' przy aktywnym CSP.{Style.RESET_ALL}")

            else:
                # Rozróżnienie kolorów dla nowych nagłówków izolacji (mogą nie być jeszcze wdrożone)
                if "Cross-Origin" in header:
                    print(f"{Fore.MAGENTA}[-] {header}: BRAK (Zalecane dla pełnej izolacji){Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] {header}: BRAK{Style.RESET_ALL}")
                print(f"    Rola: {description}")

        # 2. Sprawdzenie wycieków (Information Disclosure) - W tym X-AspNet-Version ze zrzutu
        info_leak_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        print(f"\n{Fore.CYAN}[*] Sprawdzanie wycieku informacji (Fingerprinting):{Style.RESET_ALL}")
        leaks_found = False
        for leak in info_leak_headers:
            if leak in response.headers:
                print(f"{Fore.RED}[!] Wykryto nagłówek {leak}: {response.headers[leak]} (USUNĄĆ!){Style.RESET_ALL}")
                leaks_found = True
        
        if not leaks_found:
            print(f"{Fore.GREEN}[OK] Brak oczywistych nagłówków fingerprintingu.{Style.RESET_ALL}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[ERROR] Błąd połączenia z celem: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Użycie: python3 {sys.argv[0]} <url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    audit_headers(target_url)