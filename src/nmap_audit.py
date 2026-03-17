import nmap
import asyncio
import json
from datetime import datetime
from playwright.async_api import async_playwright

class WebSecurityScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()
        self.scan_results = []
        self.findings = [] # Struktura na wykryte podatności

    def run_nmap_evasion_scan(self):
        print(f"[*] Inicjowanie skanowania Nmap dla: {self.target}")
        arguments = '-sS -f --mtu 24 -g 80 -D RND:5 -T4'
        self.nm.scan(self.target, arguments=arguments, ports='80,443,8080')
        
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    if self.nm[host][proto][port]['state'] == 'open':
                        self.scan_results.append({'host': host, 'port': port, 'proto': proto})
        return self.scan_results

    async def verify_with_playwright(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            for res in self.scan_results:
                url = f"http{'s' if res['port'] == 443 else ''}://{res['host']}:{res['port']}"
                print(f"[+] Skanowanie Playwright: {url}")
                
                try:
                    response = await page.goto(url, timeout=5000)
                    headers = response.headers
                    
                    # Weryfikacja nagłówków
                    expected_headers = ["content-security-policy", "x-frame-options", "strict-transport-security"]
                    missing_headers = [h for h in expected_headers if h not in headers]
                    
                    if missing_headers:
                        self.findings.append({
                            "url": url,
                            "type": "Security Misconfiguration",
                            "severity": "Medium",
                            "description": f"Brak krytycznych nagłówków bezpieczeństwa: {', '.join(missing_headers)}",
                            "poc": f"Wykonaj żądanie GET na {url} i sprawdź odpowiedź serwera. Brakujące nagłówki pozwalają m.in. na ataki Clickjacking (X-Frame-Options).",
                            "remediation": "Skonfiguruj serwer webowy lub aplikację, aby zwracała wymagane nagłówki (np. używając middleware 'helmet' w środowiskach JS/React lub w nagłówkach PHP)."
                        })
                    
                    # Sprawdzanie edge-case'ów
                    await self.check_sensitive_paths(page, url)
                    
                except Exception as e:
                    print(f"  [-] Błąd połączenia z {url}: {e}")

            await browser.close()

    async def check_sensitive_paths(self, page, base_url):
        # Słownik ścieżek dostosowany do stacku PHP/JS
        paths = ["/.env", "/admin", "/config.php", "/package.json", "/.git/config"]
        for path in paths:
            test_url = f"{base_url}{path}"
            response = await page.goto(test_url)
            
            # Weryfikujemy nie tylko status, ale upewniamy się, że to nie jest np. customowa strona 404 zwracająca 200 OK
            if response.status == 200 and "404" not in await page.title():
                self.findings.append({
                    "url": test_url,
                    "type": "Sensitive Data Exposure",
                    "severity": "High",
                    "description": f"Znaleziono potencjalnie wrażliwy plik lub panel administracyjny pod adresem: {path}",
                    "poc": f"Otwórz przeglądarkę i wejdź na adres: {test_url}",
                    "remediation": "Ogranicz dostęp do ścieżki na poziomie serwera webowego (np. reguły deny w Nginx/Apache) lub upewnij się, że pliki konfiguracyjne znajdują się poza głównym katalogiem publicznym (DocumentRoot)."
                })

    def export_json(self, filename="report.json"):
        report_data = {
            "target": self.target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": self.scan_results,
            "findings": self.findings
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"[*] Wyeksportowano raport JSON do {filename}")

    def export_markdown(self, filename="report.md"):
        md_content = f"# Raport Bezpieczeństwa: {self.target}\n"
        md_content += f"**Data skanowania:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        md_content += "## 1. Otwarte Porty (Reconnaissance)\n"
        for port in self.scan_results:
            md_content += f"- **Port:** {port['port']}/{port['proto']} (Host: {port['host']})\n"
        
        md_content += "\n## 2. Wykryte Podatności i Błędy Konfiguracji\n"
        if not self.findings:
            md_content += "Nie wykryto oczywistych podatności w zdefiniowanych wektorach testowych.\n"
        
        for idx, finding in enumerate(self.findings, 1):
            md_content += f"### {idx}. [{finding['severity'].upper()}] {finding['type']}\n"
            md_content += f"- **URL:** `{finding['url']}`\n"
            md_content += f"- **Opis:** {finding['description']}\n\n"
            md_content += "#### Proof of Concept (PoC)\n"
            md_content += f"> {finding['poc']}\n\n"
            md_content += "#### Rekomendacje Naprawcze\n"
            md_content += f"{finding['remediation']}\n\n"
            md_content += "---\n"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"[*] Wyeksportowano raport Markdown do {filename}")

async def main():
    target_ip = "127.0.0.1" # ZMIEŃ NA DOCELOWY ADRES
    scanner = WebSecurityScanner(target_ip)
    
    scanner.run_nmap_evasion_scan()
    if scanner.scan_results:
        await scanner.verify_with_playwright()
        scanner.export_json()
        scanner.export_markdown()
    else:
        print("[-] Skrypt Nmap nie znalazł otwartych portów HTTP/HTTPS. Przerywam działanie.")

if __name__ == "__main__":
    asyncio.run(main())
