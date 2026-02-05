#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import sys
import codecs

# Set stdout encoding to utf-8
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)

def scan(ip):
    """
    Skanuje sieć lokalną ARP w poszukiwaniu urządzeń.
    Zwraca listę słowników z IP i MAC znalezionych urządzeń.
    """
    print(f"[*] Skanowanie sieci: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    # Verbose=0 ucisza scapy
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def is_espressif(mac):
    """
    Sprawdza czy MAC adres należy do Espressif (producent ESP32).
    Espressif ma kilka OUI.
    """
    # Znane OUI Espressif
    espressif_ouis = [
        "24:6f:28", "30:ae:a4", "3c:71:bf", "48:55:19", "54:43:b2",
        "58:cf:79", "60:01:94", "68:b6:b3", "80:7d:3a", "84:cc:a8",
        "90:97:d5", "a0:20:a6", "a4:cf:12", "ac:67:b2", "b4:e6:2d",
        "bc:dd:c2", "c4:4f:33", "cc:50:e3", "d8:a0:1d", "dc:4f:22",
        "e0:5a:1b", "e8:db:84", "ec:62:60", "ec:94:cb", "ac:15:18"
    ]
    
    mac_prefix = mac.lower()[:8]
    return mac_prefix in espressif_ouis

def print_result(results_list):
    print("IP\t\t\t\tMAC Address\t\t\tVendor")
    print("--------------------------------------------------------------------------")
    found_esp = False
    for client in results_list:
        vendor = "Unknown"
        if is_espressif(client["mac"]):
            vendor = "Espressif (ESP32/ESP8266)"
            found_esp = True
            print(f"\033[92m{client['ip']}\t\t{client['mac']}\t\t{vendor}\033[0m") # Green for ESP
        else:
            print(f"{client['ip']}\t\t{client['mac']}\t\t{vendor}")
            
    if found_esp:
        print("\n\033[92m[+] Znaleziono potencjalne urządzenia ESP32!\033[0m")
    else:
        print("\n[-] Nie znaleziono urządzeń Espressif.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ESP32 Finder - Local Network Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP / CIDR range (e.g. 192.168.1.1/24)", required=True)
    options = parser.parse_args()

    scan_result = scan(options.target)
    print_result(scan_result)
