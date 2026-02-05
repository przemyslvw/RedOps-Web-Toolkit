# Plan Audytu Bezpieczeństwa Raspberry Pi w Sieci Lokalnej

## 1. Cel Audytu
Weryfikacja poziomu bezpieczeństwa urządzenia Raspberry Pi pracującego w sieci lokalnej. Celem jest identyfikacja słabych punktów konfiguracji, domyślnych ustawień oraz potencjalnych wektorów ataku, które umożliwiają atakującemu dostęp do poufnych danych lub przejęcie kontroli nad systemem.

## 2. Zakres Testów
Audyt obejmuje wyłącznie urządzenia Raspberry Pi w sieci lokalnej, do której audytor posiada uprawnienia.
**Główne wektory ataku:**
- Przejęcie informacji (Information Gathering / Interception)
- Przejęcie kontroli (Exploitation / Access Control)

---

## 3. Faza 1: Przejęcie Informacji (Information Gathering)
Na tym etapie gromadzimy informacje o celu bez ingerencji w jego działanie (lub z minimalną interakcją).

### 3.1. Wykrywanie i Identyfikacja (Discovery)
Zlokalizowanie Raspberry Pi w sieci lokalnej.
*   **Techniki:**
    *   **Skanowanie sieci (ARP/Ping Scan):** Wykorzystanie biblioteki **Scapy** do wysyłania zapytań ARP w celu wykrycia aktywnych hostów.
    *   Analiza adresów MAC (OUI: `B8:27:EB`, `DC:A6:32`, `E4:5F:01`, `28:CD:C1`).
    *   Pasywny nasłuch ruchu broadcast/multicast (mDNS, SSDP).

### 3.2. Skanowanie Usług (Enumeration)
Identyfikacja uruchomionych usług i otwartych portów.
*   **Kluczowe porty:**
    *   `22` (SSH) - Weryfikacja banneru, wersja OpenSSH.
    *   `80/443/8080` (HTTP/HTTPS) - Serwery WWW, panele kamer, OctoPrint, Pi-hole.
    *   `5900` (VNC) - Zdalny pulpit.
    *   `1883` (MQTT) - Komunikacja IoT (Home Assistant).
    *   `445` (SMB) - Udostępnianie plików.

### 3.3. Przechwytywanie Ruchu (Sniffing & MITM)
Przechwycenie haseł, tokenów lub niezaszyfrowanych danych.
*   **Techniki:**
    *   **ARP Spoofing (Scapy):** Użycie **Scapy** do zatruwania tablic ARP (ARP Poisoning), co pozwoli na przekierowanie ruchu ofiary przez nasz komputer.
    *   **Analiza pakietów:** Wykorzystanie `tcpdump`, `Wireshark` lub sniffera w **Scapy** do analizy przechwyconego ruchu.

---

## 4. Faza 2: Przejęcie Kontroli (Taking Control)
Aktywne próby uzyskania dostępu do systemu operacyjnego lub panelu administracyjnego.

### 4.1. Ataki na Uwierzytelnianie (Brute-Force / Default Creds)
*   **SSH / VNC / HTTP:**
    *   Sprawdzenie domyślnych poświadczeń (najczęstsza podatność RPi):
        *   User: `pi`, Pass: `raspberry`
        *   User: `admin`, Pass: `admin` / `password`
    *   Słownikowy atak siłowy na usługę SSH (np. przy użyciu Hydry lub własnego skryptu Python/Paramiko).

### 4.2. Eksploitacja Usług (Exploitation)
*   **Znane podatności (CVE):** Sprawdzenie wersji usług wykrytych w Fazie 1 pod kątem publicznych exploitów.
*   **Misconfiguration:**
    *   Otwarty MQTT bez autoryzacji (możliwość wstrzykiwania poleceń do automatyki domowej).
    *   VNC bez hasła.
    *   System plików NFS/SMB dostępny bez logowania.

### 4.3. Uzyskanie Powłoki (Shell)
*   Po udanym uwierzytelnieniu (SSH) lub eksploitacji, celem jest uzyskanie interaktywnej powłoki systemowej.
*   Weryfikacja uprawnień (`whoami`, `sudo -l`) – sprawdzenie, czy mamy dostęp `root` (domyślny użytkownik `pi` często ma sudo bez hasła).

---

## 5. Plan Działania Krok po Kroku (Do wykonania w kolejnych etapach)

1.  **Przygotowanie środowiska:** Uruchomienie skryptów rozpoznawczych (Python: `scapy`, `nmap` module).
2.  **Skanowanie:** Zidentyfikowanie IP Raspberry Pi.
3.  **Sniffing:** Uruchomienie ataku ARP Spoofing i próba przechwycenia logowania (symulacja).
4.  **Brute-Force SSH:** Uruchomienie skryptu łamiącego hasła na wykrytym IP.
5.  **Exfiltration:** Po wbiciu się, pobranie "tajnego" pliku z urządzenia.
