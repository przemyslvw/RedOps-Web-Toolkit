import requests
import re
from urllib.parse import urljoin
import json
import hashlib

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
    match_challenge_2 = re.search(r'X-challenge:\s+([a-f0-9]+)', response_step_1.text)
    match_timestamp_2 = re.search(r'X-timestamp:\s+(\d+)', response_step_1.text)

    if not (match_challenge_2 and match_timestamp_2):
        print("[-] Błąd parsowania Etapu 2.")
        return

    headers_step_2 = {
        'X-challenge': match_challenge_2.group(1),
        'X-timestamp': match_timestamp_2.group(1)
    }
    
    print("[*] 3. Wysyłam GET (Etap 2)...")
    step_2_url = urljoin(BASE_URL, "/?step=2")
    response_step_2 = session.get(step_2_url, headers=headers_step_2)

    # --- ETAP 3 ---
    print("\n[*] --- ETAP 3 ROZPOCZĘTY ---")
    print("[*] Analizuję odpowiedź z Etapu 2...")

    # 1. Wyciągamy Challenge i Timestamp dla Etapu 3
    # Szukamy w treści instrukcji, np. "- challenge: <hash>"
    match_challenge_3 = re.search(r'-\s+challenge:\s+([a-f0-9]+)', response_step_2.text)
    match_timestamp_3 = re.search(r'-\s+timestamp:\s+(\d+)', response_step_2.text)

    # 2. Wyciągamy słownik JSON (szukamy klamer { ... })
    match_json = re.search(r'(\{.*?\})', response_step_2.text, re.DOTALL)

    if match_challenge_3 and match_timestamp_3 and match_json:
        val_challenge_3 = match_challenge_3.group(1)
        val_timestamp_3 = match_timestamp_3.group(1)
        json_str = match_json.group(1)

        print(f"[+] Pobrano dane. Challenge: {val_challenge_3[:10]}...")

        # Parsowanie JSON
        try:
            data_dict = json.loads(json_str)
        except json.JSONDecodeError:
            print("[-] Błąd parsowania JSON!")
            return

        # Sortowanie kluczy odwrotnie alfabetycznie
        sorted_keys = sorted(data_dict.keys(), reverse=True)
        
        # Tworzenie ciągu klucz=wartość&...
        # Format your dictionary as key1=value1&key2=value2...
        pairs = [f"{key}={data_dict[key]}" for key in sorted_keys]
        query_string = "&".join(pairs)
        
        print(f"[i] Wygenerowany ciąg do haszowania (start): {query_string[:30]}...")

        # Obliczanie SHA256
        sha_signature = hashlib.sha256(query_string.encode('utf-8')).hexdigest()
        print(f"[+] Obliczony hash: {sha_signature}")
        
        # Przygotowujemy nagłówki
        payload = {
            'challenge': val_challenge_3,
            'timestamp': val_timestamp_3,
            'hash': sha_signature
        }
        
        print("[*] 4. Wysyłam POST (Etap 3)...")
        step_3_url = urljoin(BASE_URL, "/?step=3")
        
        # Requests automatycznie ustawi Content-Type: application/x-www-form-urlencoded
        # gdy użyjemy parametru 'data'
        response_step_3 = session.post(step_3_url, data=payload)
        
        print("\n" + "="*40)
        print(" ODPOWIEDŹ:")
        print("="*40)
        print(response_step_3.text)
        print("="*40)

    else:
        print("[-] Błąd parsowania danych do Etapu 3.")
        print("Zwrócona treść strony:\n", response_step_2.text)

if __name__ == "__main__":
    solve()