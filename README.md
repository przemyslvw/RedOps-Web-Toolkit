# RedOps-Web-Toolkit (RWT) - Advanced Security Suite

![Security](https://img.shields.io/badge/Security-Offensive-red.svg)
![DevSecOps](https://img.shields.io/badge/Strategy-OWASP_Top_10-orange.svg)
![Target](https://img.shields.io/badge/Tech_Stack-Angular_React_Vue_Net_SQL-blue.svg)

## 🎯 Cel Projektu
**RedOps-Web-Toolkit** to profesjonalne środowisko do testowania bezpieczeństwa nowoczesnych aplikacji webowych (SPA, Cloud-native, Enterprise). Projekt łączy manualne techniki Red Teamingowe z automatyzacją klasy Enterprise (SonarQube, Burp Suite), skupiając się na technologiach takich jak **React/Angular/Vue, .NET Core, Firebase oraz MSSQL/PostgreSQL**.

Narzędzie jest zaprojektowane zgodnie z metodologią **OWASP WSTG** (Web Security Testing Guide).

---

## 🛠 Architektura i Pila Technologiczna (Tech Stack)

### Testowane Technologie:
* **Frontend:** Angular, React, Vue.js (Analiza DOM-based XSS, Client-Side Logic).
* **Backend:** .NET (C#), Node.js, Firebase (Analiza Insecure Direct Object References).
* **Databases:** MSSQL, PostgreSQL, NoSQL (SQLi, Time-based Injections).
* **Cloud:** Firebase/GCP (Insecure Rules, Misconfigurations).

### Moduły Systemu:

| Moduł | Kategoria | Narzędzia / Frameworki | Funkcja |
| :--- | :--- | :--- | :--- |
| **`Port-Sentinel`** | Infra Recon | `Python / Kali (nmap)` | Skanowanie portów L4, detekcja usług deweloperskich (SMB, RDP, SQL). |
| **`Header-Analyzer`** | Hardening | `Custom Python Engine` | Audyt polityk CSP, HSTS, CORS w architekturze SPA. |
| **`Burp-Pro-Ext`** | Manual Ops | `Jython / Burp Suite API` | Automatyzacja bypassów WAF i niestandardowych nagłówków autoryzacji. |
| **`Static-Scanner`** | SAST | `SonarQube API / Semgrep` | Integracja skanowania kodu źródłowego pod kątem Hardcoded Secrets i CVE. |
| **`OWASP-Automator`** | Web Attack | `ffuf / Nuclei / Kali` | Automatyzacja testów pod kątem OWASP Top 10 (Injection, Broken Auth). |
| **`Decoder-Utils`** | Utility | `Python` | Wielowarstwowe dekodowanie ciągów (Base64, Hex, ROT13, URL). |
| **`Payload-Enumerator`** | Web Attack | `Python / Requests` | Automatyzacja wysyłania payloadów Base64 i ekstrakcja danych (e-mail) z odpowiedzi. |

---

## 🚀 Kluczowe Funkcjonalności

### 1. OWASP Top 10 Coverage
Zestaw skryptów dedykowanych pod konkretne podatności:
* **Broken Access Control:** Automatyczne testowanie IDOR w API .NET/Firebase.
* **Injection:** Zaawansowane payloady dla MSSQL oraz NoSQL (Firebase/MongoDB).
* **Security Misconfigurations:** Wykrywanie niebezpiecznych ustawień w plikach `web.config` oraz `appsettings.json`.

### 2. Burp Suite Professional Extensions (`/burp_ext`)
Autorskie wtyczki zwiększające efektywność testów manualnych:
* **JWT-Auto-Signer:** Wykrywanie słabych kluczy w tokenach aplikacji .NET.
* **CORS-Assessor:** Testowanie błędów w nagłówku `Access-Control-Allow-Origin`.

### 3. Static Analysis (SAST) Integration
Moduł `sonarqube_connector.py` pozwala na wyciąganie wyników skanowania bezpośrednio do raportu końcowego, łącząc podatności statyczne (kod) z dynamicznymi (DAST).

### 4. Recon & Port Discovery
Integracja z narzędziami Kali Linux (nmap, masscan) opakowana w Pythonowy wrapper, umożliwiająca fingerprinting systemów MSSQL i serwerów IIS.

### 5. AI-Augmented Vulnerability Research
Toolkit integruje modele LLM (poprzez OpenAI/Anthropic API) do:
* **Analizy kontekstowej API:** Model analizuje dokumentację Swagger/OpenAPI i sugeruje scenariusze ataków na logikę biznesową (np. manipulacja cenami, obchodzenie workflow).
* **Automatycznej deobfuskacji:** Wykorzystanie AI do analizy zaciemnionego kodu JavaScript w poszukiwaniu ukrytych funkcji i kluczy.

### 6. Headless Security Testing (Playwright)
Wykorzystanie Playwright do automatyzacji testów bezpieczeństwa w przeglądarce:
* **DOM-XSS Prober:** Automatyczne wstrzykiwanie payloadów w pola formularzy i monitorowanie zdarzeń DOM.
* **MFA Automation:** Symulacja przepływów logowania z ominięciem zabezpieczeń front-endowych.

### 7. Multi-Decoder Utility
Narzędzie `src/decoder_utils.py` do szybkiej analizy zakodowanych ciągów znaków. Obsługuje nowoczesne standardy webowe oraz klasyczne kodowanie:
* **JWT (JSON Web Tokens):** Automatyczna detekcja i dekodowanie Header/Payload.
* **Hash Identification:** Rozpoznawanie MD5, SHA-1, SHA-256 na podstawie długości.
* **Base64 / Base32 / Hex**
* **URL Encoding (w tym double-encoding)**
* **HTML Entities / ROT13**

### 8. Payload Enumerator
Skrypt `src/payload_enumerator.py` automatyzujący testowanie API poprzez masowe wysyłanie payloadów:
* **Automatyzacja:** Pętla generująca unikalne payloady Base64.
* **Data Extraction:** Analiza odpowiedzi pod kątem wycieku danych (e-mail) przy użyciu Regex.
* **Customizable:** Łatwa konfiguracja targetu i struktury żądania.

---

## 📈 Metodologia Ataku (Attack Workflow)



1.  **Reconnaissance:** Skanowanie portów (L4) i detekcja technologii (Wappalyzer/WhatWeb).
2.  **Mapping:** Analiza frontendu (React/Angular) pod kątem ukrytych tras (routes) i kluczy API.
3.  **Discovery:** Automatyczny audyt nagłówków i skanowanie OWASP Top 10.
4.  **Exploitation:** Manualna weryfikacja przy użyciu wtyczek Burp Suite.
5.  **Reporting:** Generowanie raportu z oceną CVSS 3.1.

---

## 💻 Instalacja

```bash
# Sklonuj repozytorium
git clone [https://github.com/twoj-user/RedOps-Web-Toolkit.git](https://github.com/twoj-user/RedOps-Web-Toolkit.git)

# Konfiguracja środowiska Kali
sudo apt update && sudo apt install nmap ffuf -y

# Instalacja zależności Python
pip install -r requirements.txt

# Uruchomienie pełnego skanu aplikacji .NET
python rwt.py --target [https://api.prod.local](https://api.prod.local) --scan-all --sonarqube-check