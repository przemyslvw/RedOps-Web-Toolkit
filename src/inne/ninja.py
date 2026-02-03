import requests
import re
from urllib.parse import urljoin

# Konfiguracja
BASE_URL = "https://task.zostansecurity.ninja/"

# Używamy Session, aby zachować cookies między etapami (kluczowe!)
session = requests.Session()

def solve():
    # --- ETAP 1 ---
    print(f"[*] 1. Wchodzę na stronę główną: {BASE_URL}")
    try:
        # Pobieramy stronę startową, żeby dostać świeży token/timestamp
        response_init = session.get(BASE_URL)
    except Exception as e:
        print(f"[!] Błąd połączenia: {e}")
        return

    # Szukamy URL do pierwszego kroku za pomocą wyrażenia regularnego (Regex)
    match_step1 = re.search(r'/\?step=1&challenge=[a-f0-9]+&timestamp=\d+', response_init.text)
    
    if not match_step1:
        print("[-] Nie znaleziono linku do Etapu 1.")
        return

    step_1_url = urljoin(BASE_URL, match_step1.group(0))
    print(f"[*] 2. Wykonuję Etap 1: {step_1_url}")
    
    response_step_1 = session.get(step_1_url)
    
    # --- ETAP 2 ---
    print("[*] Analizuję odpowiedź z Etapu 1...")
    # Szukamy wzorca: "X-challenge: [ciąg znaków]"
    match_challenge = re.search(r'X-challenge:\s+([a-f0-9]+)', response_step_1.text)
    match_timestamp = re.search(r'X-timestamp:\s+(\d+)', response_step_1.text)

    if match_challenge and match_timestamp:
        val_challenge = match_challenge.group(1)
        val_timestamp = match_timestamp.group(1)
        
        print(f"[+] Znaleziono dane do Etapu 2:")
        print(f"    Challenge: {val_challenge[:10]}...")
        print(f"    Timestamp: {val_timestamp}")
        
        # Przygotowujemy nagłówki
        headers = {
            'X-challenge': val_challenge,
            'X-timestamp': val_timestamp
        }
        
        print("[*] 3. Wysyłam GET (Etap 2) z nagłówkami...")
        step_2_url = urljoin(BASE_URL, "/?step=2")
        
        # WAŻNE: Przekazujemy parametr 'headers'
        response_step_2 = session.get(step_2_url, headers=headers)
        
        print("\n" + "="*40)
        print(" ODPOWIEDŹ")
        print("="*40)
        print(response_step_2.text)
        print("="*40)
        
    else:
        print("[-] Błąd parsowania danych do Etapu 2.")
        print("Zwrócona treść strony:\n", response_step_1.text)

if __name__ == "__main__":
    solve()