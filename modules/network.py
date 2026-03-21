"""
modules/network.py
------------------
Network Scanning Module for ShadowScan v1.0
Covers: Port Scanner, Banner Grabber, Ping Sweep, Reverse DNS

Author  : Anveeksh Rao
GitHub  : github.com/anveeksh
Warning : For authorized testing and educational use only.
"""

import socket
import subprocess
import platform
import concurrent.futures
from datetime import datetime
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def run():
    print_module_header("Network Scanning")
    print("  [1]  Port Scanner")
    print("  [2]  Banner Grabber")
    print("  [3]  Ping Sweep")
    print("  [4]  Reverse DNS Lookup")
    print("  [0]  Back to Main Menu")
    print()
    choice = input("  Select option: ").strip()
    handlers = {"1": port_scan, "2": banner_grab, "3": ping_sweep, "4": reverse_dns}
    if choice in handlers:
        handlers[choice]()
    elif choice != "0":
        warn("Invalid option.")
    press_enter()


def _scan_port(args):
    host, port, timeout = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            try:
                service = socket.getservbyport(port)
            except OSError:
                pass
            return {"port": port, "service": service, "state": "open"}
    except Exception:
        pass
    return None


def port_scan():
    print_module_header("Port Scanner")
    target = input("  Enter IP or hostname: ").strip()
    if not target:
        error("No target entered.")
        return
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            info(f"Resolved: {target} → {ip}")
    except socket.gaierror:
        error(f"Cannot resolve: {target}")
        return
    print("  [1]  Common ports (top 30)")
    print("  [2]  Custom range")
    print("  [3]  Top 1000 ports")
    mode = input("\n  Select: ").strip()
    if mode == "1":
        ports, timeout = list(COMMON_PORTS.keys()), 0.5
    elif mode == "2":
        try:
            start = int(input("  Start port: ").strip())
            end   = int(input("  End port  : ").strip())
            ports, timeout = list(range(start, end + 1)), 0.3
        except ValueError:
            error("Invalid port range.")
            return
    elif mode == "3":
        ports, timeout = list(range(1, 1001)), 0.3
    else:
        warn("Invalid mode.")
        return
    info(f"\nTarget  : {target} ({ip})")
    info(f"Ports   : {len(ports)}")
    info(f"Started : {datetime.now().strftime('%H:%M:%S')}\n")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for result in executor.map(_scan_port, [(ip, p, timeout) for p in ports]):
            if result:
                success(f"Port {result['port']:<6} OPEN  [{result['service']}]")
                open_ports.append(result)
    open_ports.sort(key=lambda x: x["port"])
    print()
    info(f"Open ports found: {len(open_ports)}")
    if open_ports:
        path = save_results("port_scan", {"target": target, "ip": ip, "open_ports": open_ports})
        success(f"Results saved → {path}")
    else:
        warn("No open ports found.")


def banner_grab():
    print_module_header("Banner Grabber")
    target = input("  Enter IP or hostname: ").strip()
    try:
        port = int(input("  Enter port: ").strip())
    except ValueError:
        error("Port must be a number.")
        return
    info(f"Grabbing banner from {target}:{port}...\n")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        if port in (80, 443, 8080, 8443):
            s.send(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
        banner = s.recv(2048).decode(errors="ignore").strip()
        s.close()
        if banner:
            success(f"Banner received from {target}:{port}")
            print("\n  " + "─" * 50)
            for line in banner.splitlines():
                print(f"  {line}")
            print("  " + "─" * 50 + "\n")
            save_results("banner", {"target": target, "port": port, "banner": banner})
        else:
            warn("Connected but no banner received.")
    except ConnectionRefusedError:
        error(f"Port {port} is closed or filtered.")
    except socket.timeout:
        error("Connection timed out.")
    except Exception as e:
        error(f"Banner grab failed: {e}")


def _ping_host(ip):
    flag = "-c" if platform.system() != "Windows" else "-n"
    try:
        result = subprocess.run(
            ["ping", flag, "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
        )
        if result.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "N/A"
            return {"ip": ip, "hostname": hostname}
    except subprocess.TimeoutExpired:
        pass
    return None


def ping_sweep():
    print_module_header("Ping Sweep")
    subnet = input("  Enter subnet (e.g. 192.168.1): ").strip()
    if not subnet:
        error("No subnet entered.")
        return
    try:
        start = int(input("  Start host (e.g. 1)  : ").strip())
        end   = int(input("  End host   (e.g. 254): ").strip())
    except ValueError:
        error("Invalid range.")
        return
    ips = [f"{subnet}.{i}" for i in range(start, end + 1)]
    info(f"Sweeping {len(ips)} hosts with 50 threads\n")
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for result in executor.map(_ping_host, ips):
            if result:
                success(f"ALIVE: {result['ip']:<18} → {result['hostname']}")
                alive.append(result)
    print()
    info(f"Live hosts: {len(alive)}")
    if alive:
        path = save_results("ping_sweep", {"subnet": subnet, "alive": alive})
        success(f"Results saved → {path}")
    else:
        warn("No live hosts found.")


def reverse_dns():
    print_module_header("Reverse DNS Lookup")
    raw = input("  Enter IP(s) — comma-separated: ").strip()
    if not raw:
        error("No IP entered.")
        return
    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
    results = []
    for ip in ips:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            success(f"{ip:<18} → {hostname}")
            if aliases:
                info(f"  Aliases: {', '.join(aliases)}")
            results.append({"ip": ip, "hostname": hostname, "aliases": aliases})
        except socket.herror:
            warn(f"{ip:<18} → No PTR record found")
        except socket.gaierror:
            error(f"{ip:<18} → Invalid IP address")
    if results:
        path = save_results("reverse_dns", {"results": results})
        info(f"\nResults saved → {path}")
