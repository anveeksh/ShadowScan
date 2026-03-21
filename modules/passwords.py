"""
modules/passwords.py
--------------------
Password & Hash Security Module for ShadowScan v1.0
Covers: Hash Generation, Identification, Dictionary Attack,
        Strength Analysis, Secure Password Generation

Author  : Anveeksh Rao
GitHub  : github.com/anveeksh
Warning : For authorized testing and educational use only.
"""

import hashlib
import hmac
import os
import re
import secrets
import string
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

HASH_SIGNATURES = [
    (r"^\$2[ayb]\$.{56}$",   "bcrypt"),
    (r"^\$argon2",            "Argon2"),
    (r"^\$6\$.{8,16}\$.{86}$","SHA-512 crypt"),
    (r"^[a-f0-9]{128}$",      "SHA-512"),
    (r"^[a-f0-9]{96}$",       "SHA-384"),
    (r"^[a-f0-9]{64}$",       "SHA-256"),
    (r"^[a-f0-9]{56}$",       "SHA-224"),
    (r"^[a-f0-9]{40}$",       "SHA-1"),
    (r"^[a-f0-9]{32}$",       "MD5 / NTLM"),
    (r"^[A-Z0-9]{32}$",       "NTLM"),
    (r"^[a-f0-9]{16}$",       "MySQL (old)"),
    (r"^[a-f0-9]{8}$",        "CRC-32"),
]

SUPPORTED_ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]

BUILTIN_WORDLIST = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "passw0rd", "shadow",
    "123123", "654321", "superman", "michael", "football",
    "welcome", "admin", "admin123", "root", "toor",
    "pass", "test", "guest", "login", "changeme",
    "secret", "default", "1234", "12345", "123456789",
]


def run():
    print_module_header("Password & Hash Tools")
    print("  [1]  Hash Generator")
    print("  [2]  Hash Identifier")
    print("  [3]  Dictionary Attack")
    print("  [4]  Password Strength Analyzer")
    print("  [5]  Secure Password Generator")
    print("  [0]  Back to Main Menu")
    print()
    choice = input("  Select option: ").strip()
    handlers = {"1": hash_generator, "2": hash_identifier,
                "3": dict_attack, "4": strength_checker, "5": pass_generator}
    if choice in handlers:
        handlers[choice]()
    elif choice != "0":
        warn("Invalid option.")
    press_enter()


def hash_generator():
    print_module_header("Hash Generator")
    text = input("  Enter text to hash: ").strip()
    if not text:
        error("No input provided.")
        return
    salt = input("  Add salt? (leave blank to skip): ").strip()
    salted = text + salt if salt else text
    info(f"\nInput : {text}")
    if salt:
        info(f"Salt  : {salt}")
    print()
    results = {}
    for algo in SUPPORTED_ALGOS:
        h = hashlib.new(algo, salted.encode("utf-8")).hexdigest()
        results[algo] = h
        success(f"{algo.upper():<10}: {h}")
    if salt:
        hmac_h = hmac.new(salt.encode(), text.encode(), hashlib.sha256).hexdigest()
        results["hmac-sha256"] = hmac_h
        success(f"{'HMAC-SHA256':<10}: {hmac_h}")
    path = save_results("hashes", {"input": text, "salt": salt, "hashes": results})
    info(f"\nResults saved → {path}")


def hash_identifier():
    print_module_header("Hash Identifier")
    h = input("  Enter hash: ").strip()
    if not h:
        error("No hash provided.")
        return
    info(f"Hash   : {h}")
    info(f"Length : {len(h)} characters\n")
    matched = False
    for pattern, name in HASH_SIGNATURES:
        if re.match(pattern, h, re.IGNORECASE):
            success(f"Identified as: {name}")
            matched = True
            break
    if not matched:
        warn(f"Unknown hash type (length: {len(h)})")
    if all(c in "0123456789abcdefABCDEF" for c in h):
        info("Charset: Hexadecimal")


def dict_attack():
    print_module_header("Dictionary Attack")
    hash_input = input("  Enter hash to crack: ").strip().lower()
    if not hash_input:
        error("No hash provided.")
        return
    algo = input(f"  Algorithm ({'/'.join(SUPPORTED_ALGOS)}): ").strip().lower()
    if algo not in SUPPORTED_ALGOS:
        error(f"Unsupported algorithm.")
        return
    wordlist_path = input("  Wordlist path (ENTER for built-in): ").strip()
    if wordlist_path:
        if not os.path.exists(wordlist_path):
            error(f"File not found: {wordlist_path}")
            return
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip()]
        info(f"Loaded {len(words):,} words")
    else:
        words = BUILTIN_WORDLIST
        warn(f"Using built-in wordlist ({len(words)} words) — use rockyou.txt for real attacks.")
    info(f"\nHash : {hash_input}")
    info(f"Algo : {algo.upper()}")
    info(f"Words: {len(words):,}\n")
    for i, word in enumerate(words, 1):
        try:
            if hashlib.new(algo, word.encode("utf-8")).hexdigest() == hash_input:
                success(f"PASSWORD CRACKED → '{word}'")
                success(f"Attempts: {i:,} / {len(words):,}")
                save_results("cracked", {"hash": hash_input, "algorithm": algo,
                                          "password": word, "attempts": i})
                return
        except ValueError as e:
            error(f"Algorithm error: {e}")
            return
    warn(f"Not found after {len(words):,} attempts. Try rockyou.txt")


def strength_checker():
    print_module_header("Password Strength Analyzer")
    pwd = input("  Enter password to analyze: ").strip()
    if not pwd:
        error("No password provided.")
        return
    print()
    score = 0
    checks = [
        ("Length >= 8",       len(pwd) >= 8),
        ("Length >= 12",      len(pwd) >= 12),
        ("Length >= 16",      len(pwd) >= 16),
        ("Uppercase letters", bool(re.search(r"[A-Z]", pwd))),
        ("Lowercase letters", bool(re.search(r"[a-z]", pwd))),
        ("Digits",            bool(re.search(r"\d", pwd))),
        ("Special chars",     bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd))),
        ("No common pattern", not bool(re.search(
            r"(password|123456|qwerty|admin|letmein|welcome)", pwd, re.IGNORECASE))),
    ]
    for check, passed in checks:
        if passed:
            score += 1
            success(f"✔  {check}")
        else:
            warn(f"✘  {check}")
    charset = sum([
        26 if re.search(r"[a-z]", pwd) else 0,
        26 if re.search(r"[A-Z]", pwd) else 0,
        10 if re.search(r"\d", pwd) else 0,
        32 if re.search(r"[^a-zA-Z0-9]", pwd) else 0,
    ])
    entropy = len(pwd) * (charset.bit_length() if charset else 0)
    rating = ("💪 Very Strong" if score >= 8 else "✅ Strong" if score >= 6
              else "⚠️  Moderate" if score >= 4 else "❌ Weak" if score >= 2
              else "💀 Very Weak")
    print(f"\n  Score   : {score}/8")
    print(f"  Entropy : ~{entropy} bits")
    print(f"  Rating  : {rating}\n")


def pass_generator():
    print_module_header("Secure Password Generator")
    try:
        length = int(input("  Password length (recommended 16+): ").strip())
        count  = int(input("  How many to generate?             : ").strip())
    except ValueError:
        error("Enter valid numbers.")
        return
    use_upper   = input("  Include uppercase?  (y/n): ").strip().lower() == "y"
    use_digits  = input("  Include digits?     (y/n): ").strip().lower() == "y"
    use_special = input("  Include special?    (y/n): ").strip().lower() == "y"
    chars = string.ascii_lowercase
    if use_upper:   chars += string.ascii_uppercase
    if use_digits:  chars += string.digits
    if use_special: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    print()
    generated = []
    for i in range(count):
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        success(f"[{i+1:02d}] {pwd}")
        generated.append(pwd)
    path = save_results("passwords", {"length": length, "count": count, "passwords": generated})
    info(f"\nSaved → {path}")
    warn("Store in a password manager — never in plaintext.")
