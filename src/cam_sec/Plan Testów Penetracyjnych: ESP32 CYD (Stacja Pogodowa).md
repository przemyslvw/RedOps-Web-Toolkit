# Plan Testów Penetracyjnych: ESP32 CYD (Stacja Pogodowa)

Celem jest zidentyfikowanie urządzenia ESP32 w sieci lokalnej, przechwycenie jego komunikacji z API pogodowym oraz próba manipulacji wyświetlanymi danymi (przejęcie kontroli nad treścią).

## Zrozumienie Celu
Urządzenie to ESP32 z wyświetlaczem (CYD - Cheap Yellow Display) działające jako stacja pogodowa.
- **Funkcja**: Pobiera dane o pogodzie z zewnętrznego API.
- **Komunikacja**: Prawdopodobnie HTTP/HTTPS po WiFi.
- **Wymiana danych**: JSON/XML z serwerem pogodowym.

## Faza 1: Rozpoznanie i Identyfikacja (Discovery)
Musimy znaleźć adres IP urządzenia ESP32 w sieci lokalnej.
1. **Skanowanie sieci**: Użycie skanera ARP/ICMP.
2. **Fingerprinting**: Identyfikacja po adresie MAC (OUI dla Espressif to zazwyczaj `24:6F:28`, `30:AE:A4` itp.) lub otwartych portach.
   - *Narzędzie*: Skrypt Python (`scapy` lub `socket`) lub `nmap`.

## Faza 2: Analiza Ruchu (Sniffing)
Zrozumienie, z jakim API łączy się stacja.
1. **Pasywny Sniffing**: Nasłuchiwanie pakietów broadcast/multicast (mało skuteczne w switchowanej sieci dla unicast).
2. **Aktywny Sniffing (ARP Spoofing)**:
   - Ustawienie ataku Man-in-the-Middle (MITM) pomiędzy ESP32 a Bramą sieciową (Routerem).
   - *Cel*: Przekierowanie ruchu przez nasz komputer atakujący.
3. **Analiza Pakietów**:
   - Wykorzystanie `Wireshark` lub skryptu w `Scapy` do podglądu zapytań HTTP.
   - *Szukamy*: Adresu URL API, klucza API (API Key), struktury odpowiedzi (JSON).

## Faza 3: Przejęcie Kontroli (Exploitation)
Próba wpłynięcia na to, co wyświetla stacja.
1. **Data Tampering (Modyfikacja w locie)**:
   - Jeśli komunikacja jest nieszyfrowana (HTTP): Napisanie proxy/skryptu, który przechwytuje odpowiedź z API pogodowego i zmienia wartości (np. temperaturę na 99°C, ikonę pogody).
   - Jeśli HTTPS: Sprawdzenie, czy urządzenie weryfikuje certyfikaty SSL. Próba ataku SSL Strip lub podstawienia własnego certyfikatu (może nie zadziałać na ESP32 z hardcodowanym certyfikatem).
2. **Denial of Service (DoS)**:
   - Zablokowanie komunikacji z API, aby sprawdzić zachowanie urządzenia (np. czy wyświetli błąd, czy się zawiesi).

## Plan Działania (Automatyzacja Python)
1. **`esp_finder.py`**: Skrypt do znalezienia IP urządzenia ESP32 w sieci.
2. **`weather_interceptor.py`**: Skrypt realizujący ARP Spoofing i logujący zapytania HTTP z ESP32.
3. **`weather_spoofer.py`**: Rozszerzona wersja interceptora, która podmienia dane w odpowiedziach JSON.