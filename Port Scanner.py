# ============================================================
# Network Port Scanner
# Author: Sourabh (s0xandrew)
# Ethical Use Only — scan systems you own or have permission
# ============================================================

import socket           # Built-in Python — handles network connections
import datetime         # For timestamps in report
import sys              # For command line arguments
from concurrent.futures import ThreadPoolExecutor  # For fast parallel scanning

# ── CONFIGURATION ────────────────────────────────────────────
TARGET_HOST = "scanme.nmap.org"   # Legal target — maintained by nmap.org FOR scanning
OUTPUT_FILE = "port_scan_report.txt"
TIMEOUT = 1          # Seconds to wait per port before giving up
MAX_THREADS = 100    # Scan 100 ports simultaneously for speed

# ── COMMON PORTS + SERVICE NAMES ─────────────────────────────
# Dictionary mapping port numbers to their common service names
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    115:  "SFTP",
    135:  "MS RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    194:  "IRC",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# ── RESULTS STORAGE ──────────────────────────────────────────
open_ports = []    # List of open ports found
findings = []      # All output lines for report


def log(message):
    """Print to screen and save to findings."""
    print(message)
    findings.append(message)


def resolve_host(host):
    """
    Convert a hostname (like google.com) to an IP address.
    This is called DNS resolution.
    """
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        log(f"[ERROR] Cannot resolve host: {host}")
        sys.exit(1)


def grab_banner(ip, port):
    """
    Banner grabbing: connect to an open port and read the
    first message the service sends back.
    This often reveals software name and version —
    critical info for vulnerability assessment.
    """
    try:
        # Create a socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        # Some services need us to send something first
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        # Read the response (up to 1024 bytes)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        # Return first line only (most useful part)
        return banner.split("\n")[0] if banner else "No banner"

    except Exception:
        return "No banner"


def scan_port(ip, port):
    """
    Attempt to connect to a single port.
    If connection succeeds → port is OPEN.
    If connection refused/times out → port is CLOSED/FILTERED.
    
    This is called a TCP Connect Scan — the most basic
    and reliable port scanning technique.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        # connect_ex returns 0 if connection succeeded (port open)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            # Port is open — get service name and banner
            service = COMMON_PORTS.get(port, "Unknown Service")
            banner = grab_banner(ip, port)
            open_ports.append({
                "port": port,
                "service": service,
                "banner": banner
            })

    except Exception:
        pass  # Port is closed or filtered — skip silently


def scan_range(ip, start_port, end_port):
    """
    Scan a range of ports using multiple threads simultaneously.
    Without threading: scanning 1000 ports × 1 second = 1000 seconds.
    With 100 threads: scanning 1000 ports × 1 second = ~10 seconds.
    """
    log(f"\n[SCAN] Scanning ports {start_port}-{end_port} on {ip}")
    log(f"[SCAN] Using {MAX_THREADS} threads for speed")
    log(f"[SCAN] This may take 30-60 seconds...\n")

    # ThreadPoolExecutor runs scan_port() on many ports at once
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)


def print_results(ip):
    """Display all open ports found in a clean table format."""
    log(f"\n{'='*60}")
    log(f"[RESULTS] Open ports on {ip}:")
    log(f"{'='*60}")

    if not open_ports:
        log("[RESULTS] No open ports found in scanned range.")
        return

    # Sort results by port number
    open_ports.sort(key=lambda x: x["port"])

    log(f"{'PORT':<8} {'SERVICE':<20} {'BANNER'}")
    log(f"{'-'*8} {'-'*20} {'-'*30}")

    for entry in open_ports:
        log(f"{entry['port']:<8} {entry['service']:<20} {entry['banner'][:50]}")

    log(f"\n[RESULTS] Total open ports found: {len(open_ports)}")


def check_dangerous_ports():
    """
    Flag ports that are commonly exploited.
    This is basic threat intelligence built into the scanner.
    """
    dangerous = {
        23:  "Telnet — sends data in plaintext, easily intercepted!",
        21:  "FTP — sends credentials in plaintext!",
        3389:"RDP — common ransomware entry point!",
        445: "SMB — EternalBlue/WannaCry vector!",
        3306:"MySQL — exposed database, high risk!",
        6379:"Redis — often misconfigured, no auth by default!",
        27017:"MongoDB — often exposed without authentication!",
    }

    found_dangerous = False
    for port_info in open_ports:
        port = port_info["port"]
        if port in dangerous:
            if not found_dangerous:
                log(f"\n[⚠ RISK ASSESSMENT]")
                found_dangerous = True
            log(f"  [HIGH RISK] Port {port} open — {dangerous[port]}")

    if not found_dangerous:
        log("\n[RISK] No commonly dangerous ports found open.")


def save_report():
    """Save scan results to file."""
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(findings))
    print(f"\n[REPORT] Saved to {OUTPUT_FILE}")


# ── MAIN ─────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("   NETWORK PORT SCANNER")
    print("   By Sourabh (s0xandrew) | Ethical Use Only")
    print(f"   Target: {TARGET_HOST}")
    print("=" * 60)

    log(f"\n[INFO] Scan started: {datetime.datetime.now()}")

    # Step 1: Resolve hostname to IP
    log(f"\n[DNS] Resolving {TARGET_HOST}...")
    ip = resolve_host(TARGET_HOST)
    log(f"[DNS] Resolved to: {ip}")

    # Step 2: Scan ports 1-1024 (well-known ports range)
    scan_range(ip, 1, 1024)

    # Step 3: Print results table
    print_results(ip)

    # Step 4: Risk assessment
    check_dangerous_ports()

    # Step 5: Summary
    log(f"\n[INFO] Scan completed: {datetime.datetime.now()}")

    # Step 6: Save report
    save_report()


if __name__ == "__main__":
    main()

