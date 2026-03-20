#!/usr/bin/env python3
import sys
from colorama import init
from utils.banner import print_banner, print_menu, info
from utils.helpers import clear_screen
from modules import recon, webapp, network, passwords

init(autoreset=True)

def main():
    while True:
        clear_screen()
        print_banner()
        print_menu()

        choice = input("\n  Enter option: ").strip()

        if choice == "1":
            clear_screen()
            recon.run()
        elif choice == "2":
            clear_screen()
            webapp.run()
        elif choice == "3":
            clear_screen()
            network.run()
        elif choice == "4":
            clear_screen()
            passwords.run()
        elif choice == "0":
            clear_screen()
            info("Exiting ShadowScan. Stay ethical. 👋")
            sys.exit(0)
        else:
            info("Invalid option. Try again.")

if __name__ == "__main__":
    main()
