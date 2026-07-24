#!/usr/bin/env python3
"""
LEIV-W-PROJECT  –  Cybersecurity Awareness & Whistleblower OPSEC Toolkit
Zero-dependency, cross-platform (Linux/Windows), pure Python standard library.
"""

import os
import re
import sys
import struct
import socket
import subprocess
import platform

# ----------------------------------------------------------------------
# Constants and helpers
# ----------------------------------------------------------------------
LEGAL_WARNING = (
    "\n[!] LEGAL & OPSEC NOTICE: Only use this tool on systems and networks\n"
    "    you own or have explicit permission to test. Unauthorised scanning\n"
    "    or sniffing may violate laws and compromise your anonymity.\n"
    "    Proceed responsibly and in accordance with the LEIV-W philosophy.\n"
)

class Col:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    banner = f"""
{Col.CYAN}{Col.BOLD}
 ██╗     ███████╗██╗██╗   ██╗    ██╗    ██╗-PROJECT
 ██║     ██╔════╝██║██║   ██║    ██║    ██║ CyberSec
 ██║     █████╗  ██║██║   ██║    ██║    ██║ Awareness
 ██║     ██╔══╝  ██║╚██╗ ██╔╝    ██║    ██║ Framework
 ███████╗███████╗██║ ╚████╔╝     ███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝      ╚══════╝╚══════╝
{Col.RESET}
{Col.GREEN}Zero-Dependency OPSEC Toolkit for Whistleblowers & Researchers{Col.RESET}
"""
    print(banner)

def print_section(title):
    print(f"\n{Col.BOLD}{Col.YELLOW}--- {title} ---{Col.RESET}")

def opsec_prompt():
    """Display legal warning and ask for confirmation."""
    print(LEGAL_WARNING)
    ans = input("Do you understand and wish to continue? [y/N]: ").strip().lower()
    if ans != 'y':
        print("Exiting.")
        sys.exit(0)

# ----------------------------------------------------------------------
# 1. Network Scanning (basic TCP connect scan)
# ----------------------------------------------------------------------
def port_scan():
    print_section("Network Port Scanner")
    opsec_prompt()
    target = input("Target IP or hostname: ").strip()
    ports_input = input("Port range (e.g. 20-100 or 80,443): ").strip()
    try:
        if '-' in ports_input:
            start, end = map(int, ports_input.split('-'))
            ports = range(start, end+1)
        else:
            ports = [int(p) for p in ports_input.split(',')]
    except ValueError:
        print(f"{Col.RED}Invalid port specification.{Col.RESET}")
        return

    print(f"\nScanning {target} ...\n")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except OSError:
                service = "unknown"
            print(f"{Col.GREEN}[OPEN]{Col.RESET} {port}/tcp ({service})")
            open_ports.append(port)
        sock.close()
    if not open_ports:
        print(f"{Col.RED}No open ports found.{Col.RESET}")
    print(f"\nScan complete. {len(open_ports)} open port(s).")

# ----------------------------------------------------------------------
# 2. Packet Sniffing (raw socket metadata capture)
# ----------------------------------------------------------------------
def parse_ip_header(packet):
    """Return (src_ip, dst_ip, protocol, header_length) from raw IP packet."""
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = ip_header[0]
    header_len = (version_ihl & 0xF) * 4
    ttl, proto, src, dst = ip_header[5], ip_header[6], ip_header[8], ip_header[9]
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return src_ip, dst_ip, proto, header_len

def packet_sniffer(count=10):
    print_section("Packet Sniffer (requires root/Administrator)")
    opsec_prompt()
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print(f"{Col.RED}Permission denied. Run as root/Administrator.{Col.RESET}")
        return
    except OSError as e:
        print(f"{Col.RED}Socket error (raw socket may not be available): {e}{Col.RESET}")
        return

    # Bind to all interfaces with fallback
    try:
        host = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        host = '0.0.0.0'
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if platform.system() == 'Windows':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"Sniffing {count} packets... Press Ctrl+C to stop early.\n")
    captured = 0
    try:
        while captured < count:
            raw_packet, addr = sniffer.recvfrom(65535)
            src_ip, dst_ip, proto, _ = parse_ip_header(raw_packet)
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'IP({proto})')
            extra = ""
            if proto in (6, 17):  # TCP or UDP, parse ports
                ip_header_len = (raw_packet[0] & 0x0F) * 4
                sport, dport = struct.unpack('!HH', raw_packet[ip_header_len:ip_header_len+4])
                extra = f"  {sport} -> {dport}"
            print(f"[{captured+1}] {Col.CYAN}{src_ip}{Col.RESET} -> {Col.MAGENTA}{dst_ip}{Col.RESET} "
                  f"| {proto_name}{extra}")
            captured += 1
    except KeyboardInterrupt:
        print("\nSniffing interrupted by user.")
    finally:
        if platform.system() == 'Windows':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()
    print("Done.")

# ----------------------------------------------------------------------
# 3. File Metadata Scrubbing (EXIF removal from JPEG without external tools)
# ----------------------------------------------------------------------
def scrub_jpeg_exif(filepath, output_path=None):
    """
    Remove EXIF (APP1) segment from a JPEG file.
    Works on standard JPEGs. Educational only – always back up originals.
    """
    SOI = b'\xff\xd8'
    APP1 = b'\xff\xe1'
    SOS = b'\xff\xda'

    if not output_path:
        base, ext = os.path.splitext(filepath)
        output_path = f"{base}_clean{ext}"

    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:2] != SOI:
        raise ValueError("Not a valid JPEG (missing SOI marker).")

    pos = 2
    cleaned = bytearray(data[:2])
    while pos < len(data):
        marker = data[pos:pos+2]
        if marker == APP1:
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            pos += 2 + length
        elif marker == SOS:
            cleaned.extend(data[pos:])
            break
        else:
            if marker[0] == 0xff and marker[1] not in (0x00, 0xff):
                length = struct.unpack('>H', data[pos+2:pos+4])[0]
                cleaned.extend(data[pos:pos+2+length])
                pos += 2 + length
            else:
                cleaned.append(data[pos])
                pos += 1

    with open(output_path, 'wb') as f:
        f.write(cleaned)
    return output_path

def metadata_scrubber():
    print_section("File Metadata Scrubber (JPEG EXIF removal)")
    print("This module removes EXIF data from JPEG images without external tools.")
    filepath = input("Path to JPEG file: ").strip()
    if not os.path.isfile(filepath):
        print(f"{Col.RED}File not found.{Col.RESET}")
        return
    try:
        out = scrub_jpeg_exif(filepath)
        print(f"{Col.GREEN}Cleaned file saved as: {out}{Col.RESET}")
        print("All APP1 (EXIF) segments have been stripped.")
    except Exception as e:
        print(f"{Col.RED}Error: {e}{Col.RESET}")

# ----------------------------------------------------------------------
# 4. VPN / Tor Leak Detection (routing table awareness)
# ----------------------------------------------------------------------
def vpn_tor_leak_detect():
    print_section("VPN / Tor Leak Detection")
    print("Analysing routing table for potential leaks...")
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.check_output("route print -4", shell=True, text=True)
        else:
            # Try 'ip route', fallback to 'netstat -rn'
            try:
                out = subprocess.check_output("ip route show", shell=True, text=True, stderr=subprocess.DEVNULL)
            except (subprocess.CalledProcessError, FileNotFoundError):
                out = subprocess.check_output("netstat -rn", shell=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"{Col.RED}Failed to retrieve routing table: {e}{Col.RESET}")
        return

    print("\nCurrent routing table:\n")
    print(out)
    if "tun" in out or "tap" in out or "ppp" in out:
        print(f"{Col.GREEN}VPN interface (tun/tap/ppp) detected.{Col.RESET}")
    else:
        print(f"{Col.YELLOW}No obvious VPN interface detected. Traffic may be exposed.{Col.RESET}")

    # Tor check
    tor_ports = [9050, 9150]
    tor_detected = False
    for port in tor_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex(('127.0.0.1', port)) == 0:
            print(f"{Col.GREEN}Tor SOCKS proxy available on 127.0.0.1:{port}{Col.RESET}")
            tor_detected = True
        sock.close()
    if not tor_detected:
        print(f"{Col.YELLOW}Tor proxy (9050/9150) not reachable. Ensure Tor is running if you use it.{Col.RESET}")

    print("\nDNS server check:")
    if system == "Windows":
        try:
            dns_out = subprocess.check_output("ipconfig /all | findstr /R \"DNS Servers\"", shell=True, text=True)
            print(dns_out)
        except subprocess.CalledProcessError:
            pass
    else:
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        print(line.strip())
        except FileNotFoundError:
            print("Could not read /etc/resolv.conf")
    print("If you see your ISP's DNS servers, a DNS leak exists when using VPN/Tor.")

# ----------------------------------------------------------------------
# 5. Text Anonymization (replace identifiers)
# ----------------------------------------------------------------------
def anonymize_text():
    print_section("Text Anonymizer")
    print("Enter/paste the text you want to anonymize. End with an empty line (Ctrl+D or Enter twice).")
    lines = []
    try:
        while True:
            line = input()
            if line == "":
                if not lines:
                    break
                else:
                    lines.append("")
                    continue
            lines.append(line)
    except EOFError:
        pass

    text = "\n".join(lines)
    if not text.strip():
        print("No text provided.")
        return

    patterns = {
        r'\b[\w.-]+@[\w.-]+\.\w{2,}\b': '[EMAIL]',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b': '[IP_ADDR]',
        r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})': '[IPv6]',
        r'\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b': '[PHONE]',
        r'@[A-Za-z0-9_]+': '[AT_HANDLE]',
    }
    for pattern, repl in patterns.items():
        text = re.sub(pattern, repl, text)

    text = re.sub(r'\b[A-Z][a-z]+\s[A-Z][a-z]+\b', '[FULL_NAME]', text)

    print(f"\n{Col.GREEN}Anonymized text:{Col.RESET}\n")
    print(text)

# ----------------------------------------------------------------------
# 6. Fingerprint Awareness (browser/device tracking demo)
# ----------------------------------------------------------------------
def fingerprint_demo():
    print_section("Browser / Device Fingerprint Awareness")
    print("This module demonstrates what a remote server can see when you connect.")
    print("Fetching your HTTP headers from httpbin.org ...\n")
    try:
        from urllib.request import urlopen, Request
        req = Request("https://httpbin.org/headers", headers={"User-Agent": "LEIV-W/1.0"})
        with urlopen(req, timeout=10) as resp:
            data = resp.read().decode()
            print(data)
    except Exception as e:
        print(f"{Col.RED}Could not reach httpbin.org: {e}{Col.RESET}")
    print("\nIn a browser, sites can also probe:")
    print(" - Screen resolution, colour depth")
    print(" - Installed fonts and plugins")
    print(" - Canvas/WebGL renderer strings")
    print(" - Timezone, language, and Do-Not-Track settings")
    print("Each bit of information makes your fingerprint more unique.")
    print("Use privacy-focused browsers (Tor Browser, Firefox with resistFingerprinting) to reduce tracking.")

# ----------------------------------------------------------------------
# 7. Recon Basics (HTTP headers, DNS, traceroute)
# ----------------------------------------------------------------------
def http_headers():
    target = input("URL (include http/https): ").strip()
    print(f"\nFetching headers from {target} ...")
    try:
        from urllib.request import urlopen, Request
        req = Request(target, headers={"User-Agent": "LEIV-W-Recon/1.0"})
        with urlopen(req, timeout=10) as resp:
            print(f"{Col.GREEN}Status: {resp.status} {resp.reason}{Col.RESET}")
            for header, value in resp.getheaders():
                print(f"{header}: {value}")
    except Exception as e:
        print(f"{Col.RED}Error: {e}{Col.RESET}")

def dns_lookup():
    domain = input("Domain name: ").strip()
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        print(f"\n{Col.GREEN}IP addresses for {domain}:{Col.RESET}")
        for res in set(r[4][0] for r in results):
            print(f"  {res}")
    except socket.gaierror as e:
        print(f"{Col.RED}DNS lookup failed: {e}{Col.RESET}")

def traceroute():
    target = input("Destination IP or hostname: ").strip()
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", target]
    else:
        cmd = ["traceroute", "-n", target]
    print(f"Running traceroute to {target} (this may take a minute)...\n")
    try:
        subprocess.call(cmd)
    except FileNotFoundError:
        print(f"{Col.RED}traceroute/tracert not found. Install it first.{Col.RESET}")

def recon_menu():
    while True:
        print(f"\n{Col.BOLD}Reconnaissance sub-menu:{Col.RESET}")
        print("1. HTTP Headers grab")
        print("2. DNS Lookup")
        print("3. Traceroute")
        print("0. Back to main menu")
        choice = input("Select: ").strip()
        if choice == '1':
            http_headers()
        elif choice == '2':
            dns_lookup()
        elif choice == '3':
            traceroute()
        elif choice == '0':
            break
        else:
            print(f"{Col.RED}Invalid choice.{Col.RESET}")

# ----------------------------------------------------------------------
# Main CLI menu
# ----------------------------------------------------------------------
def main_menu():
    while True:
        print(f"\n{Col.BOLD}{Col.CYAN}╔══════════════════════════════════╗")
        print(f"║      LEIV-W-PROJECT v1.0        ║")
        print(f"╚══════════════════════════════════╝{Col.RESET}")
        print("1. Network Port Scanning")
        print("2. Packet Sniffing (raw metadata)")
        print("3. File Metadata Scrubber (EXIF removal)")
        print("4. VPN / Tor Leak Detection")
        print("5. Text Anonymizer")
        print("6. Fingerprint Awareness Demo")
        print("7. Reconnaissance Basics (headers, DNS, traceroute)")
        print("0. Exit")
        choice = input(">>> ").strip()
        if choice == '1':
            port_scan()
        elif choice == '2':
            packet_sniffer()
        elif choice == '3':
            metadata_scrubber()
        elif choice == '4':
            vpn_tor_leak_detect()
        elif choice == '5':
            anonymize_text()
        elif choice == '6':
            fingerprint_demo()
        elif choice == '7':
            recon_menu()
        elif choice == '0':
            print(f"{Col.GREEN}Stay safe. Knowledge is the first shield.{Col.RESET}")
            break
        else:
            print(f"{Col.RED}Invalid option. Please try again.{Col.RESET}")

if __name__ == "__main__":
    print_banner()
    main_menu()
