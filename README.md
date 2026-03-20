<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/maintained-yes-brightgreen?style=for-the-badge"/>
</p>

<h1 align="center">
  <br>
  🔐 ShadowScan
  <br>
</h1>

<h4 align="center">A modular, terminal-based offensive security toolkit for penetration testers and security researchers.</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#disclaimer">Disclaimer</a> •
  <a href="#license">License</a>
</p>

---

## 📌 Overview

**ShadowScan** is an open-source, multi-module offensive security framework designed for penetration testers, CTF players, and security researchers. It provides a clean, color-coded terminal interface with four core testing modules — Recon & OSINT, Web Application Testing, Network Scanning, and Password & Hash Tools — all accessible from a single interactive menu.

Built with Python 3, ShadowScan is fully compatible with **macOS** and **Linux** and requires no external dependencies beyond pip.

---

## ✨ Features

| Module | Capabilities |
|---|---|
| 🕵️ **Recon & OSINT** | WHOIS Lookup, DNS Enumeration, Subdomain Scanner |
| 🌐 **Web App Testing** | SQLi Tester, XSS Scanner, IDOR Fuzzer, Directory Bruteforcer |
| 🌍 **Network Scanning** | Port Scanner, Banner Grabber, Ping Sweep, Reverse DNS |
| 🔑 **Password & Hash Tools** | Hash Generator, Hash Identifier, Dictionary Attack, Strength Checker, Password Generator |

- ✅ Interactive color-coded terminal UI (zphisher-style)
- ✅ Auto-saves all results to `results/` as JSON
- ✅ Modular architecture — easy to extend with new modules
- ✅ Works on macOS and Linux with no sudo required
- ✅ Built for CTF competitions, lab environments, and academic research

---

## 🖥️ Preview

```
 ____  __              __              _____                
/ ___// /_  ____ _____/ /___ _      __/ ___/_________ _____ 
\__ \/ __ \/ __ `/ __  / __ \ | /| / /\__ \/ ___/ __ `/ __ \
___/ / / / / /_/ / /_/ / /_/ / |/ |/ /___/ / /__/ /_/ / / / /
/____/_/ /_/\__,_/\__,_/\____/|__/|__//____/\___/\__,_/_/ /_/

  =============================================
   Multi-Module Offensive Security Toolkit
   By Anveeksh Rao | github.com/anveeksh
  =============================================

  ╔══════════════════════════════════════════╗
  ║         ShadowScan v1.0 — Main Menu      ║
  ╠══════════════════════════════════════════╣
  ║  [1]  Recon & OSINT                      ║
  ║  [2]  Web App Testing                    ║
  ║  [3]  Network Scanning                   ║
  ║  [4]  Password & Hash Tools              ║
  ║  [0]  Exit                               ║
  ╚══════════════════════════════════════════╝
```

---

## ⚙️ Installation

### Requirements
- Python 3.8 or higher
- macOS or Linux (Windows not officially supported)
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/anveeksh/ShadowScan.git
cd ShadowScan

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run ShadowScan
python3 shadowscan.py
```

---

## 🚀 Usage

```bash
python3 shadowscan.py
```

Navigate the menu using the number keys. All results are automatically saved to the `results/` directory in JSON format with timestamps.

### Example — Hash Generator
```
Select option: 4     # Password & Hash Tools
Select option: 1     # Hash Generator
Enter text: shadowscan

[✔] md5     : 7f3a1b2c...
[✔] sha1    : a3f9d2e1...
[✔] sha256  : 1e4d7f2b...
[*] Hashes saved → results/hashes_20260320_143201.json
```

### Example — Port Scanner
```
Select option: 3     # Network Scanning
Select option: 1     # Port Scanner
Enter IP: 192.168.1.1
Scan mode: 1         # Common ports

[✔] Port 22     OPEN  [ssh]
[✔] Port 80     OPEN  [http]
[✔] Port 443    OPEN  [https]
```

---

## 📁 Project Structure

```
ShadowScan/
├── shadowscan.py          # Main entry point
├── modules/
│   ├── recon.py           # Recon & OSINT module
│   ├── webapp.py          # Web App Testing module
│   ├── network.py         # Network Scanning module
│   └── passwords.py       # Password & Hash Tools module
├── utils/
│   ├── banner.py          # UI banner, menu, color helpers
│   └── helpers.py         # Result saving, screen utilities
├── results/               # Auto-generated scan results (JSON)
├── logs/                  # Session logs
├── requirements.txt
└── README.md
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests for web testing |
| `python-whois` | WHOIS domain lookups |
| `dnspython` | DNS record enumeration |
| `colorama` | Cross-platform terminal colors |
| `pyfiglet` | ASCII banner generation |
| `tabulate` | Clean table formatting |
| `bcrypt` | Password hashing |

---

## 🗺️ Roadmap

- [ ] v1.1 — Add CVE lookup module
- [ ] v1.2 — Add SSL/TLS certificate analyzer
- [ ] v1.3 — Add API security testing module
- [ ] v1.4 — HTML report generation
- [ ] v2.0 — Plugin system for community modules

---

## ⚠️ Disclaimer

> **ShadowScan is designed strictly for educational purposes, authorized penetration testing, and security research in controlled lab environments.**
>
> Unauthorized use of this tool against systems you do not own or have explicit written permission to test is **illegal** and punishable under computer crime laws including the CFAA (US), Computer Misuse Act (UK), and equivalent legislation worldwide.
>
> The author assumes **no liability** for misuse or damage caused by this tool. Always obtain proper authorization before testing any system.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Anveeksh Rao (Ish)**
MS Cybersecurity — Northeastern University, Khoury College of Computer Sciences
Vulnerability Researcher @ CACTi Lab

[![Portfolio](https://img.shields.io/badge/Portfolio-anveekshmrao.com-blue?style=flat-square)](https://anveekshmrao.com)
[![GitHub](https://img.shields.io/badge/GitHub-anveeksh-black?style=flat-square&logo=github)](https://github.com/anveeksh)

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -m 'Add new module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

---

<p align="center">Made with ❤️ by <a href="https://anveekshmrao.com">Anveeksh Rao</a> | For educational use only</p>
