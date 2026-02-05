# Scenariusz Testowy: Przejęcie wizji z kamery IP w sieci lokalnej

Ten dokument opisuje procedurę testowania bezpieczeństwa kamer IP w sieci domowej, inspirowaną technikami z "Black Hat Python", ale dostosowaną do specyfiki monitoringu wizyjnego.

## Cel
Zidentyfikować kamery IP w sieci lokalnej i podjąć próbę uzyskania dostępu do strumienia wideo (RTSP/HTTP).

## Krok 1: Precyzyjna Identyfikacja (Fingerprinting)
Zamiast ogólnego skanowania, skupiamy się na znalezieniu urządzeń, które wyglądają jak kamery.

1.  **Rozpoznanie adresów IP (Host Discovery)**
    *   Użyj skryptu `src/host_discovery.py`, aby znaleźć aktywne urządzenia w podsieci.
2.  **Skanowanie portów usług wideo**
    *   Kamery zazwyczaj nasłuchują na specyficznych portach. Twoje narzędzie powinno sprawdzać:
        *   **554** (RTSP - Real Time Streaming Protocol) - standard przesyłania wideo.
        *   **80 / 8080 / 81** (HTTP) - panel zarządzania i strumieniowanie MJPEG.
        *   **8000** (Często używany przez Hikvision/Dahua).
        *   **37777** (Dahua proprietary).
        *   **1935** (RTMP).
3.  **Identyfikacja producenta (MAC OUI)**
    *   Pobierz adres MAC urządzenia (np. z tablicy ARP lub odpowiedzi skanera) i sprawdź pierwsze 3 bajty (OUI).
    *   Producenci kamer (np. Hikvision, Dahua, Axis, Foscam) mają przypisane unikalne prefiksy. Pozwala to odróżnić kamerę od telefonu czy lodówki.

## Krok 2: Próba Przejęcia Strumienia (Direct Access)
Po zidentyfikowaniu "podejrzanego" IP i otwartego portu 554 (RTSP), należy spróbować odtworzyć strumień.

1.  **Sprawdzenie dostępu bez uwierzytelniania**
    *   Niektóre starsze lub źle skonfigurowane kamery udostępniają strumień bez hasła.
    *   Należy spróbować połączyć się pod adres: `rtsp://<IP_KAMERY>:554/`
2.  **Enumeracja ścieżek RTSP**
    *   Każdy producent używa innej ścieżki do strumienia (np. `/live`, `/h264`, `/ch1/main/av_stream`).
    *   Należy użyć prostej listy najpopularniejszych ścieżek i próbować się z nimi połączyć.
3.  **Brute-force (Słabe hasła)**
    *   Jeśli kamera żąda hasła (odpowiedź RTSP 401 Unauthorized), należy sprawdzić domyślne pary login/hasło (np. admin/admin, admin/12345, root/root).

## Krok 3: Atak Pośredni (Jeśli Krok 2 zawiódł)
Jeśli kamera jest zabezpieczona hasłem i nie ma znanych luk, można spróbować przechwycić ruch innej osoby (np. właściciela oglądającego podgląd).

1.  **ARP Poisoning (Man-in-the-Middle)**
    *   Użyj techniki ARP Spoofing (np. z biblioteką `scapy`), aby ustawić się między kamerą a bramą (routerem) lub komputerem użytkownika.
2.  **Sniffing i Ekstrakcja**
    *   Podsłuchuj ruch sieciowy.
    *   Jeśli strumień idzie po HTTP (MJPEG) lub nieszyfrowanym RTSP, można wyciąć obraz bezpośrednio z pakietów.

## Plan Działania (Automatyzacja)
Należy zbudować narzędzie w Pythonie (`camera_hunter.py`), które zintegruje te kroki:
1.  Zaimportuje moduł `host_discovery` do znalezienia IP.
2.  Dla każdego aktywnego IP sprawdzi port 554.
3.  Dla każdego otwartego portu 554 spróbuje połączyć się (np. używając OpenCV `cv2.VideoCapture`) z listą popularnych ścieżek RTSP.
4.  Zrobi zrzut ekranu (klatkę) jeśli połączenie się powiedzie i zapisze jako dowód (`proof_<IP>.jpg`).