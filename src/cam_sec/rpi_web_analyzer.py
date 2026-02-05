import requests
import sys
import urllib3
import concurrent.futures

# Wyłącz ostrzeżenia o braku weryfikacji SSL (dla self-signed certs w sieci lokalnej)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_PATHS = [
    "/",
    "/admin",
    "/admin/",
    "/login",
    "/login.php",
    "/login.html",
    "/admin/login.php",
    "/dashboard",
    "/api/version",
    "/pihole",
    "/admin/index.php", # Pi-hole
    "/main.html",
    "/index.html",
    "/html/",
    "/config",
    "/web/", # OctoPrint?
    "/system",
]

KNOWN_SIGNATURES = {
    "Pi-hole": ["Pi-hole", "AdminLTE"],
    "OctoPrint": ["OctoPrint", "Loading OctoPrint"],
    "MotionEye": ["motionEye"],
    "Home Assistant": ["Home Assistant", "lovelace"],
    "RaspAP": ["RaspAP"],
    "Apache Default": ["Apache2 Ubuntu Default Page", "It works!"],
    "Nginx Default": ["Welcome to nginx"],
}

def check_url(url):
    try:
        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
        status = response.status_code
        length = len(response.content)
        title = ""
        
        # Proste wyciąganie tytułu
        if b"<title>" in response.content:
            try:
                start = response.content.find(b"<title>") + 7
                end = response.content.find(b"</title>", start)
                title = response.content[start:end].decode('utf-8').strip()
            except:
                pass
        
        return {
            "url": url,
            "status": status,
            "length": length,
            "title": title,
            "headers": response.headers,
            "content": response.text
        }
    except requests.exceptions.RequestException:
        return None

def identify_software(content, headers):
    detected = []
    
    # Sprawdzanie po zawartości
    for soft, indicators in KNOWN_SIGNATURES.items():
        for ind in indicators:
            if ind.lower() in content.lower():
                detected.append(soft)
                break
    
    # Sprawdzanie po nagłówkach
    server_header = headers.get("Server", "")
    if server_header:
        detected.append(f"Server: {server_header}")
        
    auth_header = headers.get("WWW-Authenticate", "")
    if auth_header:
        detected.append(f"Auth: {auth_header}")

    return list(set(detected))

def run_analysis(target_ip):
    protocols = ["http", "https"]
    print(f"[*] Rozpoczynanie analizy WWW dla {target_ip}...")
    
    found_urls = []
    
    # Generowanie pełnych URLi do sprawdzenia
    urls_to_scan = []
    for proto in protocols:
        base = f"{proto}://{target_ip}"
        for path in COMMON_PATHS:
            urls_to_scan.append(f"{base}{path}")
            
    # Skanowanie równoległe
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(check_url, url): url for url in urls_to_scan}
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            if result:
                # Interesują nas głównie 200, 3xx, 401, 403 (ale 403 tylko jeśli coś ciekawego)
                if result['status'] in [200, 301, 302, 401]:
                    print(f"[+] Found: {result['url']} (Status: {result['status']}, Size: {result['length']})")
                    if result['title']:
                        print(f"    Title: {result['title']}")
                    
                    software = identify_software(result['content'], result['headers'])
                    if software:
                        print(f"    \033[92m[!] Detected: {', '.join(software)}\033[0m")
                    
                    found_urls.append(result)
                elif result['status'] == 403:
                     # Czasami 403 jest ciekawe, np. /admin
                     if "admin" in result['url']:
                         print(f"[*] Access Forbidden: {result['url']} (Status: 403) - Potentially Interesting")

    if not found_urls:
         print("[-] Nie znaleziono żadnych dostępnych stron (tylko błędy lub timeouty).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Użycie: python3 {sys.argv[0]} <Target_IP>")
        sys.exit(1)
        
    target = sys.argv[1]
    run_analysis(target)
