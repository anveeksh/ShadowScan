from pyfiglet import figlet_format
from colorama import Fore, Style, init
init(autoreset=True)

def print_banner():
    print(Fore.RED + figlet_format("ShadowScan", font="slant"))
    print(Fore.YELLOW + "  " + "="*45)
    print(Fore.CYAN   + "   Multi-Module Offensive Security Toolkit")
    print(Fore.GREEN  + "   By Anveeksh Rao | github.com/anveeksh")
    print(Fore.YELLOW + "  " + "="*45)
    print(Style.RESET_ALL)

def print_menu():
    print(Fore.YELLOW + "\n  ╔══════════════════════════════════════════╗")
    print(Fore.YELLOW +   "  ║         ShadowScan v1.0 — Main Menu      ║")
    print(Fore.YELLOW +   "  ╠══════════════════════════════════════════╣")
    print(Fore.CYAN   +   "  ║  [1]  Recon & OSINT                      ║")
    print(Fore.CYAN   +   "  ║  [2]  Web App Testing                    ║")
    print(Fore.CYAN   +   "  ║  [3]  Network Scanning                   ║")
    print(Fore.CYAN   +   "  ║  [4]  Password & Hash Tools              ║")
    print(Fore.RED    +   "  ║  [0]  Exit                               ║")
    print(Fore.YELLOW +   "  ╚══════════════════════════════════════════╝")

def print_module_header(title):
    print(Fore.MAGENTA + f"\n  ══════════════════════════════════════════")
    print(Fore.MAGENTA + f"   🔍 {title}")
    print(Fore.MAGENTA + f"  ══════════════════════════════════════════\n")

def success(msg): print(Fore.GREEN  + f"  [✔] {msg}")
def error(msg):   print(Fore.RED    + f"  [✘] {msg}")
def info(msg):    print(Fore.CYAN   + f"  [*] {msg}")
def warn(msg):    print(Fore.YELLOW + f"  [!] {msg}")
