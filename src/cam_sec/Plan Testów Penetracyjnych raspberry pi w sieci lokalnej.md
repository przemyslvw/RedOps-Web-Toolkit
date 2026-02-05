# Plan Testów Penetracyjnych raspberry pi w sieci lokalnej

Aby wykonać test podatności i przejęcia kontroli nad urządzeniem w sieci domowej, inspirowany atakiem na samochód opisanym w książce, musisz dostosować narzędzia do środowiska sieciowego. Charlie Miller, autor przedmowy, wspomniał, że do zdalnego przejęcia kontroli nad Jeepem Cherokee (sterowanie kierownicą, hamulcami) użył modułu dbus-python, który pozwalał na komunikację z wewnętrzną magistralą samochodu.
W przypadku urządzeń w sieci domowej (IoT, routery, kamery), zamiast magistrali samochodowej, będziesz operować na protokołach sieciowych (TCP/UDP, HTTP). Opierając się na rozdziałach książki "Black Hat Python", oto jak możesz zbudować podobny proces testowania przy użyciu Pythona:
1. Rozpoznanie celów (Skaner hostów) Zanim przejmiesz kontrolę, musisz zidentyfikować urządzenia. W sieci domowej możesz stworzyć skaner wykrywający aktywne hosty.
• Książka opisuje budowę skanera wykorzystującego protokół UDP. Wysyłasz datagramy UDP na zamknięte porty i oczekujesz odpowiedzi ICMP (Destination Unreachable), co potwierdza obecność urządzenia.
• Możesz użyć modułu ipaddress do iteracji przez całą podsieć oraz socket do wysyłania pakietów.
2. Analiza ruchu (Sniffing) Aby zrozumieć, jak "rozmawiać" z urządzeniem (np. jak wysłać komendę "wyłącz światło"), musisz podsłuchać jego komunikację.
• Możesz napisać sniffer używając surowych gniazd (socket z SOCK_RAW), aby przechwytywać i dekodować nagłówki IP oraz ICMP, co pozwoli zobaczyć, kto z kim się komunikuje.
• Bardziej zaawansowanym podejściem jest użycie biblioteki Scapy. Pozwala ona na łatwe przechwytywanie pakietów (funkcja sniff) i ich analizę.
3. Przechwytywanie komunikacji (Man-in-the-Middle) Aby przejąć kontrolę nad urządzeniem, które komunikuje się z chmurą lub aplikacją mobilną, możesz użyć ataku ARP Poisoning.
• Książka opisuje tworzenie skryptu arper.py przy użyciu Scapy. Pozwala to "otruć" tablicę ARP urządzenia docelowego i bramy sieciowej, zmuszając ruch do przepływu przez Twój komputer.
• Dzięki temu możesz analizować pakiety (np. wyciągać obrazy z ruchu HTTP) lub modyfikować je w locie.
4. Interakcja i wysyłanie komend Gdy już znasz protokół, możesz napisać klienta, który wyśle żądane komendy.
• TCP/UDP: Jeśli urządzenie używa prostych protokołów, możesz użyć modułu socket do stworzenia klienta TCP lub UDP i wysłania odpowiednich bajtów danych.
• SSH: Jeśli urządzenie (np. Raspberry Pi lub router) ma otwarty port SSH, możesz użyć biblioteki Paramiko. Książka pokazuje, jak stworzyć skrypt (np. ssh_cmd.py), który łączy się z serwerem, uwierzytelnia i wykonuje polecenia.
• Web/HTTP: Jeśli urządzenie ma panel webowy, możesz użyć biblioteki requests do interakcji z API lub formularzami, a nawet przeprowadzić atak brute-force na hasło logowania, jak opisano w przypadku WordPressa.
5. Utrzymanie dostępu (Trojan) Jeśli uda Ci się uzyskać dostęp do systemu operacyjnego urządzenia (np. komputera z Windows), książka opisuje tworzenie trojana sterowanego przez GitHub (github3.py). Pozwala to na zdalne wysyłanie modułów i odbieranie wyników bez bezpośredniego połączenia.
Podsumowanie narzędzi z książki do Twojego celu:
• socket: Do podstawowej komunikacji sieciowej i skanowania.
• scapy: Do manipulacji pakietami i ataków ARP.
• paramiko: Do ataków i sterowania przez SSH.
• requests: Do manipulacji urządzeniami z interfejsem HTTP.