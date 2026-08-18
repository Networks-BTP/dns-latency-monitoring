import socket
import struct
import sys
import re
import random

def get_system_dns():
    """Reads the default upstream DNS server from /etc/resolv.conf"""
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    ip = line.split()[1]
                    # Skip local systemd-resolved stub if you want a true external DNS
                    if ip != "127.0.0.53":
                        return ip
    except Exception:
        pass
    return "1.1.1.1" # Fallback if reading fails

def build_dns_query(domain):
    # Generate a random 16-bit Transaction ID
    tx_id = random.randint(1, 65535)
    
    # Header: ID, Flags (Recursion Desired), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    
    # Encode domain: "example.com" -> \x07example\x03com\x00
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode('utf-8')
    qname += b"\x00"
    
    # QTYPE=1 (A Record), QCLASS=1 (IN)
    question = qname + struct.pack("!HH", 1, 1)
    
    return header + question, tx_id

def custom_resolve(domain, upstream_dns):
    query_packet, tx_id = build_dns_query(domain)
    
    # Direct UDP Socket bypassing OS libc cache
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    print(f"[*] Target Domain   : {domain}")
    print(f"[*] Upstream Server : {upstream_dns}:53")
    print(f"[*] Raw Packet Hex  : {query_packet.hex()}")
    
    sock.sendto(query_packet, (upstream_dns, 53))
    
    try:
        response, _ = sock.recvfrom(512)
        # Parse the last 4 bytes of the response for the IPv4 payload
        ip = socket.inet_ntoa(response[-4:])
        print(f"[+] Resolved IP     : {ip}\n")
    except socket.timeout:
        print("[-] Query timed out.\n")
    finally:
        sock.close()

if __name__ == "__main__":
    # Usage: python3 my_resolver.py <domain> [upstream_dns]
    target_domain = sys.argv[1] if len(sys.argv) > 1 else "cloudlab.us"
    
    # Allow passing a second argument for DNS, or fall back to system/default
    if len(sys.argv) > 2:
        upstream = sys.argv[2]
    else:
        upstream = get_system_dns()
        
    custom_resolve(target_domain, upstream)