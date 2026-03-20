import socket, subprocess, platform
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

def run():
    print_module_header("Network Scanning")
    print("  [1]  Port Scanner")
    print("  [2]  Banner Grabber")
    print("  [3]  Ping Sweep")
    print("  [4]  Reverse DNS Lookup")
    print("  [0]  Back")
    choice = input("\n  Select option: ").strip()

    if choice == "1":   port_scan()
    elif choice == "2": banner_grab()
    elif choice == "3": ping_sweep()
    elif choice == "4": reverse_dns()
    press_enter()

def port_scan():
    target = input("\n  Enter IP or hostname: ").strip()
    mode   = input("  Scan mode — [1] Common  [2] Custom range: ").strip()
    common = [21,22,23,25,53,80,110,143,443,445,
              3306,3389,5432,6379,8080,8443,8888,9200,27017]
    if mode == "2":
        start = int(input("  Start port: ").strip())
        end   = int(input("  End port:   ").strip())
        ports = list(range(start, end + 1))
    else:
        ports = common

    info(f"Scanning {target} — {len(ports)} ports...")
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                try:
                    svc = socket.getservbyport(port)
                except:
                    svc = "unknown"
                success(f"Port {port:<6} OPEN  [{svc}]")
                open_ports.append({"port": port, "service": svc})
            s.close()
        except Exception as e:
            error(f"Port {port}: {e}")

    if open_ports:
        path = save_results("port_scan", {"target": target, "open_ports": open_ports})
        info(f"{len(open_ports)} open ports saved → {path}")
    else:
        warn("No open ports found.")

def banner_grab():
    target = input("\n  Enter IP or hostname: ").strip()
    port   = int(input("  Enter port: ").strip())
    info(f"Grabbing banner from {target}:{port}...")
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        if banner:
            success(f"Banner received:")
            print(f"\n  {banner}\n")
            save_results("banner", {"target": target, "port": port, "banner": banner})
        else:
            warn("No banner received.")
    except Exception as e:
        error(f"Banner grab failed: {e}")

def ping_sweep():
    subnet = input("\n  Enter subnet (e.g. 192.168.1): ").strip()
    info(f"Pinging {subnet}.1 to {subnet}.254 ...")
    alive  = []
    flag   = "-c" if platform.system() != "Windows" else "-n"
    for i in range(1, 255):
        ip  = f"{subnet}.{i}"
        res = subprocess.run(["ping", flag, "1", "-W", "1", ip],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            success(f"Host alive: {ip}")
            alive.append(ip)
    if alive:
        path = save_results("ping_sweep", {"subnet": subnet, "alive": alive})
        info(f"{len(alive)} hosts found → {path}")
    else:
        warn("No live hosts found.")

def reverse_dns():
    ip = input("\n  Enter IP address: ").strip()
    info(f"Resolving {ip}...")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        success(f"{ip} → {hostname}")
        save_results("reverse_dns", {"ip": ip, "hostname": hostname})
    except Exception as e:
        error(f"Reverse DNS failed: {e}")
