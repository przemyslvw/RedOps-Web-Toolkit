import requests
import base64
import re
import time
import sys

def generate_payload(index):
    """
    Generates a Base64 encoded payload.
    Example: 'user_{index}' -> Base64
    """
    data = f"user_{index}"
    encoded = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    return encoded

def extract_emails(text):
    """
    Extracts emails using regex from text.
    """
    # Simple regex for email extraction
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(email_pattern, text)))

def run_enumeration(target_url, delay=0.1):
    print(f"[*] Starting enumeration targeting: {target_url}")
    print("[*] Loop range: 1 to 100")
    
    with requests.Session() as session:
        for i in range(1, 101):
            try:
                # 1. Create Payload
                payload_val = generate_payload(i)
                
                # Prepare data - modify this structure based on target requirements
                # Here we simulate sending a JSON with the b64 payload
                json_data = {
                    "id": i,
                    "payload": payload_val
                }

                # 2. Send Request
                # Using POST as per typical API interactions, but could be GET
                response = session.post(target_url, json=json_data, timeout=5)

                # 3. Analyze Response
                status_code = response.status_code
                content_len = len(response.text)
                
                emails = extract_emails(response.text)
                
                # Output progress
                # standardized output allows easy grep-ing later
                msg = f"Req #{i:03d} | PL: {payload_val} | Status: {status_code} | Size: {content_len}"
                if emails:
                    msg += f" | [+] EMAILS FOUND: {emails}"
                
                print(msg)
                
                # Small delay to be polite (and avoid instant rate limits)
                time.sleep(delay)

            except requests.exceptions.RequestException as e:
                print(f"[!] Error on request #{i}: {e}")
            except KeyboardInterrupt:
                print("\n[!] Stopped by user.")
                break

if __name__ == "__main__":
    # Default target - safe echo server
    DEFAULT_TARGET = "http://httpbin.org/post"
    
    # Allow user to pass URL as argument
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    
    run_enumeration(target)
