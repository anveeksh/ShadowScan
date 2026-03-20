import os, json
from datetime import datetime

def save_results(module_name, data):
    os.makedirs("results", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"results/{module_name}_{ts}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def clear_screen():
    os.system("clear")

def press_enter():
    input("\n  Press ENTER to return to menu...")
