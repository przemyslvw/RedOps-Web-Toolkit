import socket
import os
import struct
import threading
import time
import ipaddress
import sys
import ctypes

# Host to listen on - will be determined automatically
HOST = ''

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually connect, just used to determine routing
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = socket.inet_ntoa(header[8])
        self.dst = socket.inet_ntoa(header[9])

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    
    def get_protocol_name(self):
        return self.protocol_map.get(self.protocol_num, str(self.protocol_num))

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def udp_sender(subnet, message):
    time.sleep(1) # Wait for sniffer to start
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[*] Sending UDP probes to {subnet}...")
    # Iterate through all hosts in the subnet
    count = 0
    for ip in ipaddress.ip_network(subnet).hosts():
        try:
            # Send to a random high port that is likely closed
            sender.sendto(message.encode('utf-8'), (str(ip), 65212))
            count += 1
        except Exception as e:
            pass
    print(f"[*] Sent {count} probes.")

def start_scanner(subnet=None):
    local_ip = get_local_ip()
    if not subnet:
        # Assume /24 for simplicity if not provided
        try:
            network_prefix = ".".join(local_ip.split('.')[:-1]) + ".0/24"
            subnet = network_prefix
        except:
            print("[-] Could not determine subnet automatically. Please provide it as an argument.")
            sys.exit(1)
            
    print(f"[*] Detected local IP: {local_ip}")
    print(f"[*] Scanning subnet: {subnet}")

    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = None
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind(("", 0))
        
        # Include IP headers
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    except PermissionError:
        print("[-] Error: Raw sockets require root privileges. Please run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error setting up socket: {e}")
        sys.exit(1)

    # Start the sender thread
    message = "TEST_SCAN"
    t = threading.Thread(target=udp_sender, args=(subnet, message))
    t.start()

    try:
        active_hosts = set()
        # Scan for a timeout duration
        start_time = time.time()
        timeout = 5 # seconds after last probe roughly, but simple timeout here
        max_duration = 15 # total max duration
        
        print(f"[*] Sniffing started for {max_duration} seconds...")
        
        while time.time() - start_time < max_duration:
            try:
                sniffer.settimeout(1.0)
                raw_buffer = sniffer.recvfrom(65565)[0]
            except socket.timeout:
                continue
            
            # Parse IP header
            try:
                ip_header = IP(raw_buffer[0:20])
            except struct.error:
                continue
            
            # Check if it's ICMP
            if ip_header.protocol_num == 1:
                # Calculate where ICMP packet starts
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                
                try:
                    icmp_header = ICMP(buf)
                except struct.error:
                    continue
                
                # Type 3 = Destination Unreachable, Code 3 = Port Unreachable
                if icmp_header.type == 3 and icmp_header.code == 3:
                    # The ICMP packet contains the original IP header + 8 bytes of original payload
                    # We could verify the original destination was us, but for now simplest is:
                    # The SOURCE of this ICMP packet is the host that is UP.
                    
                    if str(ip_header.src) not in active_hosts:
                        # Verify it's in our target subnet
                        if ipaddress.ip_address(ip_header.src) in ipaddress.ip_network(subnet):
                            print(f"[+] Host Up: {ip_header.src}")
                            active_hosts.add(str(ip_header.src))

    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        if os.name == 'nt' and sniffer:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        if sniffer:
            sniffer.close()
        t.join()
        print(f"[*] Scan complete. Found {len(active_hosts)} hosts.")
        return sorted(list(active_hosts))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_subnet = sys.argv[1]
    else:
        target_subnet = None
    
    hosts = start_scanner(target_subnet)
    # The start_scanner already prints "Host Up" messages, so we don't need to reprint here
    # unless we want a final summary list.

