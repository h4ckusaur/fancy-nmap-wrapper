#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style, init
import pyfiglet
import argparse
import logging
from pathlib import Path
from prettytable import PrettyTable

# Initialize colorama
init(autoreset=True)

# Global lock for thread-safe writes
lock = threading.Lock()

# Default config
DEFAULT_CONFIG = {
    "thread_count": 10,
    "enable_json": False,
    "output_directory": "scan_results",
    "udp_ports": [
        53, 161, 162, 67, 68, 69, 123, 137, 138, 139, 500, 514, 520, 623, 1701,
        1900, 4500, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
        49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169,
        49170
    ],
    "nmap_flags_tcp": "-sT -sC -sV -A -Pn -p1-65535",
    "nmap_flags_udp": "-sU --top-ports 50"
}

CONFIG_FILE = "config.json"

# Global to collect summary info
summary_data = []

# Mapping Colorama colors to tqdm-compatible colors
COLORAMA_TO_TQDM = {
    Fore.BLACK: "BLACK",
    Fore.RED: "RED",
    Fore.GREEN: "GREEN",
    Fore.YELLOW: "YELLOW",
    Fore.BLUE: "BLUE",
    Fore.MAGENTA: "MAGENTA",
    Fore.CYAN: "CYAN",
    Fore.WHITE: "WHITE",
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"{Fore.YELLOW}[!] Config file created: {CONFIG_FILE}. Please review and restart.")
        sys.exit(1)
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

config = load_config()

# Setup logging
logging.basicConfig(filename='scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Create output directory
Path(config["output_directory"]).mkdir(parents=True, exist_ok=True)

# ASCII banner
def show_banner():
    banner = pyfiglet.figlet_format("Fancy Nmap Wrapper")
    print(Fore.CYAN + banner)
    print(Fore.GREEN + "Multi-Mode Network Scanner with Style!")
    print(Fore.YELLOW + "=" * 60)

def get_scan_type():
    while True:
        print(Fore.CYAN + "\nSelect scan type:")
        print("1. Internal")
        print("2. External")
        choice = input(Fore.YELLOW + "Choose an option: ").strip()
        if choice == '1':
            return "internal"
        elif choice == '2':
            return "external"
        else:
            print(Fore.RED + "Invalid selection. Try again.")

# Ping sweep function
def ping_host(host):
    result = subprocess.run(["ping", "-c", "1", "-W", "1", host],
                            stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        return host
    return None

def discovery(subnets):
    print(Fore.CYAN + "\n=== Starting Host Discovery (Ping Sweep) ===\n")
    targets_file = os.path.join(config["output_directory"], "targets.txt")

    all_hosts = []
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            all_hosts.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            print(Fore.RED + f"Invalid subnet: {subnet}")
            return

    reachable = []
    with ThreadPoolExecutor(max_workers=config["thread_count"]) as executor:
        futures = {executor.submit(ping_host, host): host for host in all_hosts}
        pbar = tqdm(as_completed(futures), total=len(futures),
                    desc="Discovery Progress", colour="CYAN", ncols=80)
        for future in pbar:
            result = future.result()
            if result:
                reachable.append(result)
        pbar.close()
        print() # Ensure user input is visible following the scan

    with open(targets_file, 'w') as f:
        for ip in reachable:
            f.write(ip + "\n")

    print(Fore.GREEN + f"\n[+] Discovery complete. {len(reachable)} hosts reachable.")
    logging.info(f"Discovery complete: {len(reachable)} hosts found.")
    summary_data.append({
        "Scan Type": "Discovery",
        "Details": f"Subnets: {', '.join(subnets)}",
        "Files": [targets_file]
    })

# TCP scan
def tcp_scan(ip, scan_type):
    outfile = os.path.join(config["output_directory"], f"portscan_{scan_type}_tcp_{ip}.txt")
    cmd = f"nmap {config['nmap_flags_tcp']} {ip}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    with lock:
        with open(outfile, 'w') as f:
            f.write(result.stdout)
    return {"ip": ip, "type": "tcp", "output": result.stdout, "file": outfile}

# UDP scan
def udp_scan(ip, scan_type):
    outfile = os.path.join(config["output_directory"], f"portscan_{scan_type}_udp_{ip}.txt")
    udp_ports = ",".join(map(str, config["udp_ports"]))
    cmd = f"nmap -sU -p {udp_ports} {ip}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    with lock:
        with open(outfile, 'w') as f:
            f.write(result.stdout)
    return {"ip": ip, "type": "udp", "output": result.stdout, "file": outfile}

def scan_targets(scan_func, scan_type, scan_label, color):
    targets_file = os.path.join(config["output_directory"], "targets.txt")
    if not os.path.exists(targets_file):
        print(Fore.RED + "[!] No targets found. Run discovery first.")
        return []

    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f]

    print(color + f"\n=== Starting {scan_label} ===\n")
    results = []
    tqdm_color = COLORAMA_TO_TQDM.get(color, "CYAN")
    with ThreadPoolExecutor(max_workers=config["thread_count"]) as executor:
        futures = {executor.submit(scan_func, ip, scan_type): ip for ip in targets}
        pbar = tqdm(as_completed(futures), total=len(futures),
                    desc=f"{scan_label} Progress", colour=tqdm_color, ncols=80)
        for future in pbar:
            results.append(future.result())
        pbar.close()
        print() # Ensure user input is visible following the scan

    files_created = [r["file"] for r in results]

    if config["enable_json"]:
        json_file = os.path.join(config["output_directory"], f"results_{scan_type}_{scan_label.lower()}.json")
        with open(json_file, 'w') as jf:
            json.dump(results, jf, indent=4)
        files_created.append(json_file)

    summary_data.append({
        "Scan Type": scan_label,
        "Details": f"Mode: {scan_type} | Hosts: {len(targets)}",
        "Files": files_created
    })

    return results

# Collect scan choices interactively
def collect_scan_choices():
    selected_scans = []

    while True:
        print(Fore.CYAN + "\nAvailable scan options:")
        print("1. Discovery (Ping Sweep)")
        print("2. TCP Scan (single run)")
        print("3. UDP Scan (single run)")
        print("4. Done selecting scans")

        choice = input(Fore.YELLOW + "Select an option: ").strip()

        if choice == '1':
            if any(scan['type'] == 'discovery' for scan in selected_scans):
                print(Fore.RED + "[!] Only one discovery scan is allowed.")
            else:
                subnets = input(Fore.YELLOW + "Enter subnets for discovery (comma-separated): ").strip()
                selected_scans.append({"type": "discovery", "subnets": [s.strip() for s in subnets.split(",")]})
                print(Fore.GREEN + "[+] Discovery scan added.")

        elif choice == '2':
            mode = get_scan_type()
            selected_scans.append({"type": "tcp", "mode": mode})
            print(Fore.GREEN + f"[+] TCP scan ({mode}) added.")

        elif choice == '3':
            mode = get_scan_type()
            selected_scans.append({"type": "udp", "mode": mode})
            print(Fore.GREEN + f"[+] UDP scan ({mode}) added.")

        elif choice == '4':
            break
        else:
            print(Fore.RED + "Invalid option. Try again.")
            continue

        # Show current selections
        print(Fore.MAGENTA + "\n=== Current Scan Selections ===")
        for idx, scan in enumerate(selected_scans, start=1):
            if scan["type"] == "discovery":
                print(f"{idx}. Discovery | Subnets: {', '.join(scan['subnets'])}")
            else:
                print(f"{idx}. {scan['type'].upper()} | Mode: {scan['mode']}")
        print(Fore.MAGENTA + "================================\n")

        more = input(Fore.YELLOW + "Would you like to add more scans? (y/n): ").strip().lower()
        if more != 'y':
            break

    return selected_scans

# Run selected scans in correct order
def run_selected_scans(scan_choices):
    print(Fore.CYAN + "\n=== Preparing to Run Selected Scans ===")
    discovery_scan = next((s for s in scan_choices if s['type'] == 'discovery'), None)
    other_scans = [s for s in scan_choices if s['type'] != 'discovery']

    if discovery_scan:
        print(Fore.YELLOW + "[!] Discovery must complete before other scans can start.")
        discovery(discovery_scan['subnets'])

    for scan in other_scans:
        if scan['type'] == 'tcp':
            scan_targets(tcp_scan, scan['mode'], "TCP Scan", Fore.BLUE)
        elif scan['type'] == 'udp':
            scan_targets(udp_scan, scan['mode'], "UDP Scan", Fore.MAGENTA)

    print(Fore.GREEN + "\n[+] All selected scans have completed.\n")
    show_summary_report()

def show_summary_report():
    print(Fore.CYAN + "\n=== Scan Summary Report ===\n")
    table = PrettyTable()
    table.field_names = ["Scan Type", "Details", "Files Created"]
    for entry in summary_data:
        files_display = "\n".join(entry["Files"])
        table.add_row([entry["Scan Type"], entry["Details"], files_display])
    print(table)
    print(Fore.YELLOW + "\n[+] Summary report complete.\n")
    
def parse_args():
    parser = argparse.ArgumentParser(description="Fancy Scanner")
    parser.add_argument("--json", action="store_true", help="Enable JSON output")
    args = parser.parse_args()
    if args.json:
        config["enable_json"] = True

def main_menu():
    while True:
        show_banner()
        print(Fore.CYAN + "1. Configure and Run Scans")
        print("2. View Config")
        print("3. Exit")
        choice = input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == '1':
            scan_choices = collect_scan_choices()
            if scan_choices:
                run_selected_scans(scan_choices)
        elif choice == '2':
            print(json.dumps(config, indent=4))
        elif choice == '3':
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "Invalid option. Try again.")

if __name__ == "__main__":
    parse_args()
    main_menu()
