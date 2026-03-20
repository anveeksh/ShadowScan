import whois, socket, dns.resolver
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

def run():
    print_module_header("Recon & OSINT")
    print("  [1]  WHOIS Lookup")
    print("  [2]  DNS Enumeration")
    print("  [3]  Subdomain Scanner")
    print("  [0]  Back")
    choice = input("\n  Select option: ").strip()

    if choice == "1":   whois_lookup()
    elif choice == "2": dns_enum()
    elif choice == "3": subdomain_scan()
    press_enter()

def whois_lookup():
    target = input("\n  Enter domain (e.g. example.com): ").strip()
    info(f"Running WHOIS on {target}...")
    try:
        w = whois.whois(target)
        data = {
            "domain":     target,
            "registrar":  str(w.registrar),
            "created":    str(w.creation_date),
            "expires":    str(w.expiration_date),
            "name_servers": str(w.name_servers),
            "emails":     str(w.emails),
            "country":    str(w.country),
        }
        for k, v in data.items():
            success(f"{k:<15}: {v}")
        path = save_results("whois", data)
        info(f"Results saved → {path}")
    except Exception as e:
        error(f"WHOIS failed: {e}")

def dns_enum():
    target = input("\n  Enter domain: ").strip()
    info(f"Enumerating DNS records for {target}...")
    results = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = dns.resolver.resolve(target, rtype)
            records = [r.to_text() for r in answers]
            results[rtype] = records
            success(f"{rtype:<6}: {', '.join(records)}")
        except Exception:
            results[rtype] = []
    path = save_results("dns_enum", results)
    info(f"Results saved → {path}")

def subdomain_scan():
    target  = input("\n  Enter domain: ").strip()
    wordlist = ["www","mail","ftp","admin","api","dev","test",
                "staging","vpn","blog","shop","portal","app","cdn"]
    info(f"Scanning subdomains for {target}...")
    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            success(f"Found: {fqdn} → {ip}")
            found.append({"subdomain": fqdn, "ip": ip})
        except socket.gaierror:
            pass
    if not found:
        warn("No subdomains found.")
    else:
        path = save_results("subdomains", found)
        info(f"{len(found)} subdomains saved → {path}")
