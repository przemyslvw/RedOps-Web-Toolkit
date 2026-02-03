import base64
import urllib.parse
import html
import sys
import codecs

def try_decode(label, func, data):
    """Helper function to try a decoding method and print result if successful."""
    try:
        decoded = func(data)
        # Filter out empty results or identical results (unless it's a specific transformation like URL decode where it might remain same)
        if decoded and decoded != data:
            print(f"[{label}]: {decoded}")
    except Exception:
        pass

def robust_hex_decode(data):
    # Remove spaces or 0x prefix if present
    clean_data = data.replace(' ', '').replace('0x', '')
    return bytes.fromhex(clean_data).decode('utf-8')

def multi_decode(encoded_string):
    print(f"--- Decoding analysis for: '{encoded_string}' ---")

    # 1. Base64
    try_decode("Base64", lambda s: base64.b64decode(s).decode('utf-8'), encoded_string)

    # 2. Base32
    try_decode("Base32", lambda s: base64.b32decode(s, casefold=True).decode('utf-8'), encoded_string)
    
    # 3. Hex
    try_decode("Hex", robust_hex_decode, encoded_string)

    # 4. URL Decode (run it twice to check for double encoding)
    url_decoded = urllib.parse.unquote(encoded_string)
    if url_decoded != encoded_string:
        print(f"[URL Decode]: {url_decoded}")
        # Check double encoded
        url_decoded_2 = urllib.parse.unquote(url_decoded)
        if url_decoded_2 != url_decoded:
             print(f"[Double URL Decode]: {url_decoded_2}")

    # 5. HTML Entities
    try_decode("HTML Entities", html.unescape, encoded_string)
    
    # 6. ROT13
    try_decode("ROT13", lambda s: codecs.decode(s, 'rot_13'), encoded_string)

    # 7. Reverse
    print(f"[Reverse]: {encoded_string[::-1]}")

    # 8. JWT (JSON Web Token) Identification & Decoding
    if encoded_string.count('.') == 2:
        parts = encoded_string.split('.')
        # Check if parts look like base64
        if len(parts[0]) > 1 and len(parts[1]) > 1:
            print(f"\n[!] Potential JWT Detected:")
            # JWT parts are Base64Url encoded, which might need padding
            def decode_jwt_part(part):
                padded = part + '=' * (-len(part) % 4)
                try:
                    return base64.urlsafe_b64decode(padded).decode('utf-8')
                except:
                    return None
            
            header = decode_jwt_part(parts[0])
            payload = decode_jwt_part(parts[1])
            
            if header: print(f"    Header:  {header}")
            if payload: print(f"    Payload: {payload}")
            print(f"    Sig:     {parts[2]} (Hidden)")

    # 9. Hash Identification (Heuristic based on hex length)
    # Check if string is pure hex and of specific length
    if all(c in '0123456789abcdefABCDEF' for c in encoded_string):
        length = len(encoded_string)
        if length == 32:
            print(f"\n[i] Hash Identification: Possible MD5 / MD4 / NTLM ({length} chars)")
        elif length == 40:
            print(f"\n[i] Hash Identification: Possible SHA-1 ({length} chars)")
        elif length == 64:
            print(f"\n[i] Hash Identification: Possible SHA-256 ({length} chars)")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        # Default example if no argument provided
        print("Usage: python3 decoder_utils.py <string>")
        print("Example run:")
        user_input = "T3JkZXJfMTIz"
    
    multi_decode(user_input)
