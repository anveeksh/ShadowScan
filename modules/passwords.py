import hashlib, bcrypt, os, string, random
from utils.banner import print_module_header, success, error, info, warn
from utils.helpers import save_results, press_enter

def run():
    print_module_header("Password & Hash Tools")
    print("  [1]  Hash Generator")
    print("  [2]  Hash Identifier")
    print("  [3]  Dictionary Attack (Hash Cracker)")
    print("  [4]  Password Strength Checker")
    print("  [5]  Random Password Generator")
    print("  [0]  Back")
    choice = input("\n  Select option: ").strip()

    if choice == "1":   hash_generator()
    elif choice == "2": hash_identifier()
    elif choice == "3": dict_attack()
    elif choice == "4": strength_checker()
    elif choice == "5": pass_generator()
    press_enter()

def hash_generator():
    text = input("\n  Enter text to hash: ").strip()
    algos = ["md5","sha1","sha224","sha256","sha384","sha512"]
    results = {}
    for algo in algos:
        h = hashlib.new(algo, text.encode()).hexdigest()
        results[algo] = h
        success(f"{algo:<8}: {h}")
    path = save_results("hashes", results)
    info(f"Hashes saved → {path}")

def hash_identifier():
    h = input("\n  Enter hash to identify: ").strip()
    length_map = {
        32:  "MD5",
        40:  "SHA-1",
        56:  "SHA-224",
        64:  "SHA-256",
        96:  "SHA-384",
        128: "SHA-512",
        60:  "bcrypt",
    }
    length = len(h)
    if h.startswith("$2b$") or h.startswith("$2a$"):
        success(f"Identified: bcrypt")
    elif length in length_map:
        success(f"Identified: {length_map[length]} (length {length})")
    else:
        warn(f"Unknown hash type (length {length})")

def dict_attack():
    hash_input = input("\n  Enter hash to crack: ").strip()
    algo       = input("  Algorithm (md5/sha1/sha256): ").strip().lower()
    wordlist   = input("  Path to wordlist (or press ENTER for built-in): ").strip()

    if wordlist and os.path.exists(wordlist):
        with open(wordlist, "r", errors="ignore") as f:
            words = [w.strip() for w in f.readlines()]
    else:
        words = ["password","123456","admin","letmein","welcome",
                 "monkey","dragon","master","abc123","qwerty",
                 "password1","iloveyou","sunshine","princess","shadow"]
        warn("Using built-in wordlist (15 words)")

    info(f"Cracking with {len(words)} words...")
    for word in words:
        try:
            h = hashlib.new(algo, word.encode()).hexdigest()
            if h == hash_input:
                success(f"Password FOUND: {word}")
                save_results("cracked", {"hash": hash_input, "password": word, "algo": algo})
                return
        except Exception as e:
            error(f"Error: {e}")
            return
    warn("Password not found in wordlist.")

def strength_checker():
    pwd = input("\n  Enter password to check: ").strip()
    score  = 0
    checks = {
        "Length >= 8":        len(pwd) >= 8,
        "Length >= 12":       len(pwd) >= 12,
        "Uppercase letter":   any(c.isupper() for c in pwd),
        "Lowercase letter":   any(c.islower() for c in pwd),
        "Digit":              any(c.isdigit() for c in pwd),
        "Special character":  any(c in string.punctuation for c in pwd),
    }
    for check, passed in checks.items():
        if passed:
            score += 1
            success(f"{check}")
        else:
            warn(f"{check}")

    rating = {6: "💪 Very Strong", 5: "✅ Strong",
              4: "⚠️  Moderate",   3: "❌ Weak", 2: "❌ Very Weak"}
    print(f"\n  Rating: {rating.get(score, '❌ Very Weak')} (score {score}/6)")

def pass_generator():
    length = int(input("\n  Password length (e.g. 16): ").strip())
    use_upper   = input("  Include uppercase? (y/n): ").strip().lower() == "y"
    use_digits  = input("  Include digits?    (y/n): ").strip().lower() == "y"
    use_special = input("  Include special?   (y/n): ").strip().lower() == "y"

    chars = string.ascii_lowercase
    if use_upper:   chars += string.ascii_uppercase
    if use_digits:  chars += string.digits
    if use_special: chars += string.punctuation

    pwd = "".join(random.choices(chars, k=length))
    success(f"Generated password: {pwd}")
    save_results("generated_password", {"password": pwd, "length": length})
