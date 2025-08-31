#!/usr/bin/env python3
"""
fnw.py - Fancy Nmap Wrapper.

Multi-mode network scanner supporting:
- TCP and UDP scans
- Host discovery via ping sweep
- Interactive scan selection
- Optional JSON output of results
- Dynamic NSE support for UDP ports where applicable
"""

import os
import sys
import json
import subprocess
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, init
import pyfiglet
import argparse
import logging
from pathlib import Path
from prettytable import PrettyTable
import time

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
        53,
        161,
        162,
        67,
        68,
        69,
        123,
        137,
        138,
        139,
        500,
        514,
        520,
        623,
        1701,
        1900,
        4500,
        49152,
        49153,
        49154,
        49155,
        49156,
        49157,
        49158,
        49159,
        49160,
        49161,
        49162,
        49163,
        49164,
        49165,
        49166,
        49167,
        49168,
        49169,
        49170,
    ],
    "nmap_flags_tcp": "-sT -sC -sV -A -Pn -p1-65535",
    "nmap_flags_udp": "-sU --top-ports 50",
}

CONFIG_FILE = "config.json"

# Global to collect summary info
summary_data = []

# Mapping Colorama colors to tqdm-compatible colours
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

# Map UDP ports to NSE scripts (extend as desired)
UDP_NSE_SCRIPTS = {
    53: "dns-recursion,dns-nsid",
    69: "tftp-enum",
    123: "ntp-info,ntp-monlist",
    161: "snmp-info,snmp-interfaces",
    500: "ike-version",
    1900: "upnp-info",
    5353: "mdns-info",  # if mdns is included in udp_ports
}


def load_config():
    """Load configuration from config.json or create default config file."""
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(
            f"{Fore.YELLOW}[!] Config file created: {CONFIG_FILE}. "
            "Please review and restart."
        )
        sys.exit(1)
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


config = load_config()

# Setup logging
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Ensure output directory exists
Path(config["output_directory"]).mkdir(parents=True, exist_ok=True)


def show_banner():
    """Display the ASCII banner and basic header text."""
    banner = pyfiglet.figlet_format("Fancy Nmap Wrapper")
    print(Fore.CYAN + banner)
    print(Fore.GREEN + "Multi-Mode Network Scanner with Style!")
    print(Fore.YELLOW + "=" * 60)


def get_scan_type():
    """
    Ask user to choose between internal or external scanning mode.

    Returns:
        str: "internal" or "external".
    """
    while True:
        print(Fore.CYAN + "\nSelect scan type:")
        print("1. Internal")
        print("2. External")
        choice = input(Fore.YELLOW + "Choose an option: ").strip()
        if choice == "1":
            return "internal"
        if choice == "2":
            return "external"
        print(Fore.RED + "Invalid selection. Try again.")


def ping_host(host):
    """
    Ping a host once to determine reachability.

    Args:
        host (str): IP address string.

    Returns:
        str|None: host on success, None on failure.
    """
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", host], stdout=subprocess.DEVNULL
    )
    return host if result.returncode == 0 else None


def write_command_header(filepath, cmd):
    """Prepend the executed command as a header to the output file."""
    header = (
        "===== Executed Command =====\n" f"{cmd}\n" "============================\n\n"
    )
    return header


def handle_blacklist(targets_file):
    """
    Create a list of blacklisted IPs and subnets.

    Args:
        targets_file (str): file to write discovery output.
    """
    blacklist_file = None
    for path in [config["output_directory"], os.getcwd()]:
        candidate = os.path.join(path, "blacklist.txt")
        if os.path.exists(candidate):
            blacklist_file = candidate
            print(Fore.YELLOW + f"[!] Found existing blacklist at {candidate}")
            break

    blacklist_entries = []
    if blacklist_file:
        with open(blacklist_file, "r") as f:
            blacklist_entries = [line.strip() for line in f if line.strip()]
    else:
        choice = (
            input(Fore.YELLOW + "No blacklist.txt found. Create one? (y/n): ")
            .strip()
            .lower()
        )
        if choice == "y":
            blacklist_file = os.path.join(config["output_directory"], "blacklist.txt")
            while True:
                entry = input(Fore.YELLOW + "Enter IP or CIDR to blacklist: ").strip()
                if entry:
                    blacklist_entries.append(entry)
                    with open(blacklist_file, "a") as bf:
                        bf.write(entry + "\n")
                if (
                    input(Fore.YELLOW + "Done entering blacklist entries? (y/n): ")
                    .strip()
                    .lower()
                    == "y"
                ):
                    break
    if os.path.exists(targets_file):
        with open(targets_file, "r") as f:
            blacklist_entries += [line.strip() for line in f if line.strip()]
    return blacklist_entries


def is_blacklisted(ip, blacklist_entries):
    """
    Determine whether an ip is blacklisted and prevent a scan against it.

    Args:
        ip (str): ip or CIDR string.
        blacklist_entries (list[str]): blacklisted entries.
    """
    ip_obj = ipaddress.ip_address(ip)
    for entry in blacklist_entries:
        try:
            if "/" in entry and ip_obj in ipaddress.ip_network(entry, strict=False):
                return True
            if ip == entry:
                return True
        except Exception:
            continue
    return False


def discovery(subnets):
    """
    Perform a ping sweep on a list of subnets to discover reachable hosts.

    Args:
        subnets (list[str]): list of CIDR subnet strings.
    """
    print(Fore.CYAN + "\n=== Starting Host Discovery (Ping Sweep) ===\n")

    targets_file = os.path.join(config["output_directory"], "targets.txt")
    open(targets_file, "a").close()
    blacklist_entries = handle_blacklist(targets_file)
    all_hosts = []
    for subnet in subnets:
        try:
            all_hosts.extend(
                [str(ip) for ip in ipaddress.ip_network(subnet, strict=False).hosts()]
            )
        except Exception:
            print(Fore.RED + f"Invalid subnet: {subnet}")
            return

    reachable = []
    with ThreadPoolExecutor(max_workers=config["thread_count"]) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in all_hosts}
        pbar = tqdm(
            as_completed(futures),
            total=len(futures),
            desc="Discovery Progress",
            colour="CYAN",
            ncols=80,
        )
        for future in pbar:
            result = future.result()
            if result and not is_blacklisted(result, blacklist_entries):
                reachable.append(result)
        pbar.close()
        print()

    with open(targets_file, "a") as f:
        for ip in reachable:
            f.write(ip + "\n")

    print(Fore.GREEN + f"\n[+] Discovery complete. {len(reachable)} hosts reachable.")
    logging.info(f"Discovery complete: {len(reachable)} hosts found.")
    summary_data.append(
        {
            "Scan Type": "Discovery",
            "Details": f"Subnets: {', '.join(subnets)}",
            "Files": [targets_file],
        }
    )


def tcp_scan(ip, scan_type):
    """
    Run a TCP scan against a single IP using configured nmap flags.

    Args:
        ip (str): Target IP.
        scan_type (str): 'internal' or 'external'.

    Returns:
        dict: Scan result metadata including output file path.
    """
    outfile = os.path.join(
        config["output_directory"], f"portscan_{scan_type}_tcp_{ip}.txt"
    )
    cmd = f"nmap {config.get('nmap_flags_tcp', DEFAULT_CONFIG['nmap_flags_tcp'])} {ip}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    with lock:
        open(outfile, "w").write(
            write_command_header(outfile, cmd) + result.stderr + result.stdout
        )
    return {"ip": ip, "type": "tcp", "output": result.stdout, "file": outfile}


def udp_scan(ip, scan_type):
    """
    Perform a UDP port scan using nmap.

    Args:
        ip (str): Target IP.
        scan_type (str): 'internal' or 'external'.

    Returns:
        dict: Scan result metadata including output file path.
    """
    outfile = os.path.join(
        config["output_directory"], f"portscan_{scan_type}_udp_{ip}.txt"
    )
    udp_ports = ",".join(map(str, config.get("udp_ports", DEFAULT_CONFIG["udp_ports"])))
    scripts_set = [
        s
        for port in config.get("udp_ports", [])
        if port in UDP_NSE_SCRIPTS
        for s in UDP_NSE_SCRIPTS[port].split(",")
    ]
    scripts_arg = (
        f"--script {','.join(sorted(set(scripts_set)))}" if scripts_set else ""
    )
    cmd = (
        f"nmap "
        f"{config.get('nmap_flags_udp', DEFAULT_CONFIG['nmap_flags_udp'])} "
        f"-p {udp_ports} {scripts_arg} {ip}"
    ).strip()
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    with lock:
        open(outfile, "w").write(
            write_command_header(outfile, cmd) + result.stderr + result.stdout
        )
    return {"ip": ip, "type": "udp", "output": result.stdout, "file": outfile}


def scan_targets_parallel_separate(scan_type):
    """
    Perform tcp / udp scans concurrently.

    Args:
        scan_type (str): 'internal' or 'external'.
        scan_label (str): 'TCP' or 'UDP'
        color (str): color based on scan_label.

    Returns:
        dict: Scan result metadata including output file path.
    """
    targets_file = next(
        (
            os.path.join(p, "targets.txt")
            for p in [config["output_directory"], os.getcwd()]
            if os.path.exists(os.path.join(p, "targets.txt"))
        ),
        None,
    )
    if not targets_file:
        print(Fore.RED + "[!] No targets found. Run discovery first.")
        return []

    with open(targets_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    results = []
    with ThreadPoolExecutor(max_workers=config["thread_count"] * 2) as executor:
        tcp_futures = [executor.submit(tcp_scan, ip, scan_type) for ip in targets]
        udp_futures = [executor.submit(udp_scan, ip, scan_type) for ip in targets]

        tcp_bar = tqdm(
            total=len(tcp_futures),
            desc="TCP Scan",
            colour="BLUE",
            position=0,
            leave=True,
            ncols=80,
        )
        udp_bar = tqdm(
            total=len(udp_futures),
            desc="UDP Scan",
            colour="MAGENTA",
            position=1,
            leave=True,
            ncols=80,
        )

        tcp_done = set()
        udp_done = set()

        while len(tcp_done) < len(tcp_futures) or len(udp_done) < len(udp_futures):
            # Check TCP futures
            for future in tcp_futures:
                if future.done() and future not in tcp_done:
                    try:
                        results.append(future.result())
                    except Exception as e:
                        print(Fore.RED + f"[!] Error in TCP scan: {e}")
                    tcp_done.add(future)
                    tcp_bar.update(1)

            # Check UDP futures
            for future in udp_futures:
                if future.done() and future not in udp_done:
                    try:
                        results.append(future.result())
                    except Exception as e:
                        print(Fore.RED + f"[!] Error in UDP scan: {e}")
                    udp_done.add(future)
                    udp_bar.update(1)

            time.sleep(0.2)  # smooth updates without hogging CPU

        tcp_bar.close()
        udp_bar.close()

    # JSON output if enabled
    if config.get("enable_json"):
        json_file = os.path.join(
            config["output_directory"], f"results_{scan_type}_tcp_udp.json"
        )
        with open(json_file, "w") as jf:
            json.dump(results, jf, indent=4)

    summary_data.append(
        {
            "Scan Type": "TCP/UDP",
            "Details": f"Mode: {scan_type} | Hosts: {len(targets)}",
            "Files": [r["file"] for r in results],
        }
    )

    return results


def get_targets_file():
    """
    Interactively collect scans the user wants to run.

    Returns:
        str|None: A valid file to store discovery output, or None
            to indicate the user is okay removing the existing
            targets file and creating a new one.
    """
    targets_file = None
    for path in [config["output_directory"], os.getcwd()]:
        candidate = os.path.join(path, "targets.txt")
        if os.path.exists(candidate):
            targets_file = candidate
            print(
                Fore.YELLOW + f"[!] Found existing targets.txt at {candidate} "
                f"This file must be removed to continue. Otherwise you may "
                f"perform TCP or UDP scans now."
            )
            choice = (
                input(Fore.YELLOW + "Remove your current targets.txt? ").strip().lower()
            )
            if choice == "y":
                os.remove(candidate)
                targets_file = None
                break
            else:
                print(Fore.GREEN + "Reusing existing targets.txt for now.")
                break
    return targets_file


def collect_scan_choices(targets_file):
    """
    Interactively collect scans the user wants to run.

    Args:
        targets_file (str): File to store discovery output.

    Returns:
        list[dict]: Selected scans where each dict describes the scan.
    """
    selected_scans = []

    while True:
        print(Fore.CYAN + "\nAvailable scan options:")
        print("1. Discovery (Ping Sweep)")
        print("2. TCP Scan (single run)")
        print("3. UDP Scan (single run)")
        print("4. Done selecting scans")

        choice = input(Fore.YELLOW + "Select an option: ").strip()
        if choice == "1":
            if not targets_file:
                if any(scan.get("type") == "discovery" for scan in selected_scans):
                    print(Fore.RED + "[!] Only one discovery scan is allowed.")
                else:
                    subnets = input(
                        Fore.YELLOW + "Enter subnets for discovery (comma-separated): "
                    ).strip()
                    selected_scans.append(
                        {
                            "type": "discovery",
                            "subnets": [s.strip() for s in subnets.split(",")],
                        }
                    )
                    print(Fore.GREEN + "[+] Discovery scan added.")
            else:
                print(
                    Fore.YELLOW + "[!] Discovery scan skipped. Feel free to add TCP "
                    "or UDP scans using your pre-existing targets.txt file."
                )
        elif choice == "2":
            mode = get_scan_type()
            selected_scans.append({"type": "tcp", "mode": mode})
            print(Fore.GREEN + f"[+] TCP scan ({mode}) added.")
        elif choice == "3":
            mode = get_scan_type()
            selected_scans.append({"type": "udp", "mode": mode})
            print(Fore.GREEN + f"[+] UDP scan ({mode}) added.")
        elif choice == "4":
            break
        else:
            print(Fore.RED + "Invalid option. Try again.")
            continue

        print(Fore.MAGENTA + "\n=== Current Scan Selections ===")
        for idx, scan in enumerate(selected_scans, start=1):
            if scan.get("type") == "discovery":
                print(f"{idx}. Discovery | Subnets: {', '.join(scan['subnets'])}")
            else:
                print(f"{idx}. {scan['type'].upper()} | Mode: {scan['mode']}")
        print(Fore.MAGENTA + "================================\n")

        more = None
        while more != "y" and more != "n":
            more = (
                input(Fore.YELLOW + "Would you like to add more scans? (y/n): ")
                .strip()
                .lower()
            )
        if more == "n":
            break

    return selected_scans


def run_selected_scans(scan_choices, targets_file):
    """
    Execute selected scans in the proper order.

    Args:
        scan_choices (list[dict]): result from collect_scan_choices().
    """
    ready = None
    while ready is None:
        ready = (
            input(
                Fore.RED + "Ready to initiate scans. Press [ENTER] to proceed, "
                "or q to return to the main menu. "
            )
            .strip()
            .lower()
        )
        if ready == "":
            break
        if ready == "q":
            main_menu()
        ready = None
    print(Fore.CYAN + "\n=== Executing Selected Scans ===")
    discovery_scan = next(
        (s for s in scan_choices if s.get("type") == "discovery"), None
    )
    other_scans = [s for s in scan_choices if s.get("type") != "discovery"]

    if discovery_scan:
        print(Fore.YELLOW + "[!] Discovery must complete before other scans can start.")
        discovery(discovery_scan["subnets"])

    for scan in other_scans:
        scan_type_mode = scan.get("mode")

        # Run TCP and UDP concurrently with separate progress bars
        scan_targets_parallel_separate(scan_type_mode)

    print(Fore.GREEN + "\n[+] All selected scans have completed.\n")
    show_summary_report()


def show_summary_report():
    """Print a PrettyTable summary of scans completed and files written."""
    print(Fore.CYAN + "\n=== Scan Summary Report ===\n")
    table = PrettyTable()
    table.field_names = ["Scan Type", "Details", "Files Created"]
    for entry in summary_data:
        files_display = "\n".join(entry.get("Files", []))
        table.add_row([entry.get("Scan Type"), entry.get("Details"), files_display])
    print(table)
    print(Fore.YELLOW + "\n[+] Summary report complete.\n")


def parse_args():
    """Parse CLI args and set config flags (currently --json)."""
    parser = argparse.ArgumentParser(description="Fancy Scanner")
    parser.add_argument("--json", action="store_true", help="Enable JSON output")
    args = parser.parse_args()
    if args.json:
        config["enable_json"] = True


def main_menu():
    """Present the interactive main menu to the user."""
    while True:
        show_banner()
        print(Fore.CYAN + "1. Configure and Run Scans")
        print("2. View Config")
        print("3. Exit")
        choice = input(Fore.YELLOW + "Choose an option: ").strip()
        targets_file = get_targets_file()

        if choice == "1":
            scan_choices = collect_scan_choices(targets_file)
            if scan_choices:
                run_selected_scans(scan_choices, targets_file)
        elif choice == "2":
            print(json.dumps(config, indent=4))
        elif choice == "3":
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "Invalid option. Try again.")


if __name__ == "__main__":
    parse_args()
    main_menu()
