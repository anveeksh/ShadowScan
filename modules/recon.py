"""
modules/recon.py
----------------
Reconnaissance & OSINT Module for ShadowScan v1.0
Covers: WHOIS Lookup, DNS Enumeration, Subdomain Scanner

Author  : Anveeksh Rao
GitHub  : github.com/anveeksh
Warning : For authorized testing and educational use only.
"""

import whois
import socket
import dns.resolver
import concurrent.futures
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "administrator", "backend", "panel", "dashboard",
    "api", "api2", "v1", "v2", "rest", "graphql",
    "dev", "development", "staging", "stage", "uat", "qa",
    "test", "testing", "sandbox", "demo", "preview",
    "vpn", "remote", "rdp", "ssh", "sftp",
    "blog", "shop", "store", "portal", "app", "apps",
    "cdn", "static", "assets", "media", "images",
    "secure", "login", "auth", "sso", "oauth",
    "internal", "intranet", "corp", "private",
    "backup", "old", "legacy", "archive",
    "monitor", "status", "health", "metrics",
    "git", "gitlab", "ci", "jenkins", "jira", "confluence",
    "mx", "ns1", "ns2", "ns3", "dns",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]


def run():
    print_module_header("Recon & OSINT")
    print("  [1]  WHOIS Lookup")
    print("  [2]  DNS Enumeration")
    print("  [3]  Subdomain Scanner")
    print("  [0]  Back to Main Menu")
    print()
    choice = input("  Select option: ").strip()
    handlers = {"1": whois_lookup, "2": dns_enum, "3": subdomain_scan}
    if choice in handlers:
        handlers[choice]()
    elif choice != "0":
        warn("Invalid option.")
    press_enter()


def whois_lookup():
    print_module_header("WHOIS Lookup")
    target = input("  Enter domain (e.g. example.com): ").strip().lower()
    if not target:
        error("No domain entered.")
        return
    info(f"Querying WHOIS for: {target}\n")
    try:
        w = whois.whois(target)
        fields = {
            "Domain Name" : w.domain_name,
            "Registrar"   : w.registrar,
            "WHOIS Server": w.whois_server,
            "Created"     : w.creation_date,
            "Expires"     : w.expiration_date,
            "Updated"     : w.updated_date,
            "Status"      : w.status,
            "Name Servers": w.name_servers,
            "Emails"      : w.emails,
            "Organization": w.org,
            "Country"     : w.country,
        }
        data = {}
        for label, value in fields.items():
            if value:
                display = value if isinstance(value, str) else str(value)
                success(f"{label:<16}: {display}")
                data[label] = display
        try:
            ip = socket.gethostbyname(target)
            success(f"{'Resolved IP':<16}: {ip}")
            data["Resolved IP"] = ip
        except socket.gaierror:
            warn("Could not resolve IP address.")
        path = save_results("whois", {"domain": target, "data": data})
        info(f"\nResults saved → {path}")
    except Exception as e:
        error(f"WHOIS query failed: {e}")


def dns_enum():
    print_module_header("DNS Enumeration")
    target = input("  Enter domain (e.g. example.com): ").strip().lower()
    if not target:
        error("No domain entered.")
        return
    info(f"Enumerating DNS records for: {target}")
    info(f"Record types: {', '.join(DNS_RECORD_TYPES)}\n")
    results = {}
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            records = [r.to_text() for r in answers]
            results[rtype] = records
            for r in records:
                success(f"{rtype:<6} → {r}")
        except dns.resolver.NXDOMAIN:
            error(f"Domain {target} does not exist.")
            return
        except dns.resolver.NoAnswer:
            info(f"{rtype:<6} → No records found")
            results[rtype] = []
        except Exception as e:
            warn(f"{rtype:<6} → {e}")
            results[rtype] = []
    path = save_results("dns_enum", {"domain": target, "records": results})
    info(f"\nResults saved → {path}")


def _check_subdomain(args):
    sub, target = args
    fqdn = f"{sub}.{target}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip}
    except socket.gaierror:
        return None


def subdomain_scan():
    print_module_header("Subdomain Scanner")
    target = input("  Enter domain (e.g. example.com): ").strip().lower()
    if not target:
        error("No domain entered.")
        return
    custom = input("  Custom wordlist path (or ENTER for built-in): ").strip()
    if custom:
        try:
            with open(custom, "r", errors="ignore") as f:
                wordlist = [w.strip() for w in f if w.strip()]
            info(f"Loaded {len(wordlist)} subdomains from {custom}")
        except FileNotFoundError:
            error(f"File not found: {custom}")
            return
    else:
        wordlist = SUBDOMAIN_WORDLIST
        info(f"Using built-in wordlist ({len(wordlist)} subdomains)")
    info(f"Target  : {target}")
    info(f"Threads : 20\n")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for result in executor.map(_check_subdomain, [(s, target) for s in wordlist]):
            if result:
                success(f"Found: {result['subdomain']:<40} → {result['ip']}")
                found.append(result)
    print()
    info(f"Total found: {len(found)} subdomains")
    if found:
        path = save_results("subdomains", {"domain": target, "found": found})
        success(f"Results saved → {path}")
    else:
        warn("No subdomains discovered.")
