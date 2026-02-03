import requests
import re
from urllib.parse import urljoin

# Konfiguracja
BASE_URL = "https://task.zostansecurity.ninja/"

# Używamy Session, aby zachować cookies między etapami (kluczowe!)
session = requests.Session()

def solve():
    print(f"[*] 1. Wchodzę na stronę główną: {BASE_URL}")
    try:
        # Pobieramy stronę startową, żeby dostać świeży token/timestamp
        response = session.get(BASE_URL)
    except Exception as e:
        print(f"[!] Błąd połączenia: {e}")
        return

    # Szukamy URL do pierwszego kroku za pomocą wyrażenia regularnego (Regex)
    match = re.search(r'/\?step=1&challenge=[a-f0-9]+&timestamp=\d+', response.text)

    if match:
        step_1_path = match.group(0)
        print(f"[+] Znaleziono ścieżkę: {step_1_path}")
        
    else:
        print("[-] Nie udało się znaleźć linku startowego. Sprawdź wyrażenie regularne.")
        print("Zwrócona treść strony:\n", response.text[:200])

if __name__ == "__main__":
    solve()