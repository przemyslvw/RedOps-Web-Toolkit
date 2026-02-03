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

if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        # Default example if no argument provided
        print("Usage: python3 decoder_utils.py <string>")
        print("Example run:")
        user_input = "T3JkZXJfMTIz"
    
    multi_decode(user_input)
