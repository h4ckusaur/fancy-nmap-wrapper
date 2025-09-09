#!/usr/bin/env python3
"""
fnw.py - Fancy Nmap Wrapper.

Multi-mode network scanner supporting:
- TCP and UDP scans with concurrent execution
- Host discovery via ping sweep
- Interactive scan selection and management
- Optional JSON output of results
"""

import os
import sys
import json
import subprocess
import ipaddress
import threading
import tty
import termios
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Union
from tqdm import tqdm
from colorama import Fore, init
import pyfiglet
from nmap_flags import validate_nmap_flags

# Initialize colorama
init(autoreset=True)

# Global lock for thread-safe writes
lock = threading.Lock()


def handle_keyboard_interrupt():
    """Centralized KeyboardInterrupt handler for consistent exit behavior."""
    print(Fore.LIGHTCYAN_EX + "\nThanks for using the tool. :)")
    raise SystemExit(0)


def safe_input_wrapper(input_func, *args, **kwargs):
    """Centralized wrapper for keyboard interrupt handling."""
    try:
        return input_func(*args, **kwargs)
    except KeyboardInterrupt:
        handle_keyboard_interrupt()


# Default configuration
DEFAULT_CONFIG = {
    "thread_count": 10,
    "enable_json": False,
    "output_directory": "scan_results",
    "tcp_ports_full_scan": "1-65535",
    "udp_ports_full_scan": "1-65535",
    "tcp_ports": [],
    "udp_ports": [],
    "nmap_flags_tcp": {"default": ["-sT", "-sC", "-sV", "-A", "-Pn"], "custom": []},
    "nmap_flags_udp": {
        "default": ["-sU", "-Pn", "-v", "-p 1-65535"],
        "custom": [],
    },
}

# UDP NSE scripts for specific ports
UDP_NSE_SCRIPTS = {
    # DNS
    53: (
        "dns-recursion,dns-zone-transfer,dns-brute,dns-cache-snoop,"
        "dns-check-zone,dns-client-subnet-scan,dns-fuzz,dns-ip6-arpa-scan,"
        "dns-nsec3-enum,dns-nsec-enum,dns-nsid,dns-random-srcport,"
        "dns-random-txid,dns-service-discovery,dns-srv-enum,dns-update,"
        "dns-zeustracker,fcrdns"
    ),
    # SNMP
    161: (
        "snmp-info,snmp-brute,snmp-hh3c-logins,snmp-interfaces,"
        "snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,"
        "snmp-win32-services,snmp-win32-shares,snmp-win32-software,"
        "snmp-win32-users"
    ),
    162: "snmp-info",
    # DHCP
    67: "dhcp-discover,broadcast-dhcp-discover",
    68: "dhcp-discover,broadcast-dhcp6-discover",
    # TFTP
    69: "tftp-enum,tftp-version",
    # NTP
    123: "ntp-info,ntp-monlist",
    # NetBIOS/SMB
    137: "nbstat,broadcast-netbios-master-browser",
    138: "nbstat",
    139: (
        "smb-enum-shares,smb-enum-users,smb-brute,smb-enum-domains,"
        "smb-enum-groups,smb-enum-processes,smb-enum-services,"
        "smb-enum-sessions,smb-flood,smb-ls,smb-mbenum,smb-os-discovery,"
        "smb-print-text,smb-protocols,smb-psexec,smb-security-mode,"
        "smb-server-stats,smb-system-info,smb2-capabilities,"
        "smb2-security-mode,smb2-time,smb2-vuln-uptime"
    ),
    445: (
        "smb-enum-shares,smb-enum-users,smb-brute,smb-enum-domains,"
        "smb-enum-groups,smb-enum-processes,smb-enum-services,"
        "smb-enum-sessions,smb-flood,smb-ls,smb-mbenum,smb-os-discovery,"
        "smb-print-text,smb-protocols,smb-psexec,smb-security-mode,"
        "smb-server-stats,smb-system-info,smb2-capabilities,"
        "smb2-security-mode,smb2-time,smb2-vuln-uptime,"
        "smb-vuln-conficker,smb-vuln-cve2009-3103,smb-vuln-cve-2017-7494,"
        "smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,"
        "smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,"
        "smb-vuln-regsvc-dos,smb-vuln-webexec,smb-webexec-exploit,"
        "smb-double-pulsar-backdoor"
    ),
    # RPC
    135: "msrpc-enum,rpcinfo,rpc-grind",
    # LDAP
    389: "ldap-brute,ldap-novell-getpass,ldap-rootdse,ldap-search",
    # Kerberos
    88: "krb5-enum-users",
    # IPMI
    623: "ipmi-cipher-zero,ipmi-version,ipmi-brute",
    # MSSQL
    1434: (
        "ms-sql-info,ms-sql-brute,ms-sql-config,ms-sql-dac,ms-sql-dump-hashes,"
        "ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-info,ms-sql-ntlm-info,"
        "ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell,broadcast-ms-sql-discover"
    ),
    # UPnP
    1900: "upnp-info,broadcast-upnp-info",
    # mDNS
    5353: "dns-service-discovery,broadcast-dns-service-discovery",
    # LLMNR
    5355: "llmnr-resolve",
    # SIP
    5060: "sip-brute,sip-call-spoof,sip-enum-users,sip-methods",
    # CoAP
    5683: "coap-resources",
    # MQTT
    1883: "mqtt-subscribe",
    # Modbus
    502: "modbus-discover",
    # BACnet
    47808: "bacnet-info",
    # RTSP
    554: "rtsp-methods,rtsp-url-brute",
    # WSD
    3702: "wsdd-discover,broadcast-wsdd-discover",
    # Bitcoin
    8333: "bitcoin-getaddr,bitcoin-info,bitcoinrpc-info",
    # Deluge
    58846: "deluge-rpc-brute",
    # XML-RPC
    80: "xmlrpc-methods",
    443: "xmlrpc-methods",
    # Metasploit
    3790: "metasploit-msgrpc-brute,metasploit-xmlrpc-brute",
    # Nessus
    8834: "nessus-xmlrpc-brute",
    # NNTP
    119: "nntp-ntlm-info",
    # RPCAP
    2002: "rpcap-brute,rpcap-info",
    # Fox
    1911: "fox-info",
    # Omron
    9600: "omron-info",
    # PCWorx
    1962: "pcworx-info",
    # Profinet
    34964: "profinet-cm-lookup,multicast-profinet-discovery",
}

# Global summary data
summary_data = []

# Environment variable for flags file path
FLAGS_ENV_VAR = "FNW_FLAGS_FILE_PATH"

# Signal handlers removed - using KeyboardInterrupt exceptions instead


def safe_input_loop(
    prompt_func, validation_func, error_msg="Invalid input. Please try again."
):
    """Handle input loops interrupts properly."""
    while True:
        result = prompt_func()
        if validation_func(result):
            return result
        else:
            print(Fore.RED + error_msg)


def get_single_key() -> str:
    """Get a single keypress without requiring Enter."""
    try:
        # Save terminal settings
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            # Set terminal to raw mode
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)

            # Check for Ctrl+C (ASCII 3) or empty string (EOF/interrupt)
            if not ch or ord(ch) == 3:
                raise KeyboardInterrupt

        finally:
            # Restore terminal settings
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch
    except (OSError, AttributeError):
        # Fallback for systems without termios support
        return input().strip()


def smart_input(
    prompt: str, allow_empty: bool = False, single_key: bool = False
) -> str:
    """Enhanced input function with arrow key support and better error handling."""
    if single_key:
        try:
            print(prompt, end="", flush=True)
            return get_single_key()
        except KeyboardInterrupt:
            handle_keyboard_interrupt()
            # This line should never be reached, but just in case
            raise SystemExit(0)

    try:
        # Try to enable readline for enhanced input features
        import readline

        # Configure readline for better word deletion
        readline.parse_and_bind('bind "^W" kill-word')  # Ctrl+W for word deletion
        readline.parse_and_bind('bind "^U" kill-whole-line')  # Ctrl+U to clear line
        readline.parse_and_bind(
            'bind "^K" kill-line'
        )  # Ctrl+K to kill from cursor to end

    except ImportError:
        # readline not available, fall back to basic input
        pass

    while True:
        try:
            user_input = input(prompt).strip()
            if user_input or allow_empty:
                return user_input
            else:
                print(Fore.RED + "[!] Input cannot be empty. Please try again.")
        except KeyboardInterrupt:
            handle_keyboard_interrupt()
            # This line should never be reached, but just in case
            raise SystemExit(0)


def get_flags_file_path() -> Optional[str]:
    """Get the flags file path from environment variable."""
    return os.environ.get(FLAGS_ENV_VAR)


def set_flags_file_path(file_path: str) -> None:
    """Set the flags file path in environment variable."""
    os.environ[FLAGS_ENV_VAR] = file_path
    print(
        Fore.GREEN
        + f"[+] Stored flags file path in environment variable: {FLAGS_ENV_VAR}"
    )
    print(Fore.CYAN + f"    Path: {file_path}")


def unset_flags_file_path() -> None:
    """Unset the flags file path environment variable."""
    if FLAGS_ENV_VAR in os.environ:
        del os.environ[FLAGS_ENV_VAR]
        print(Fore.GREEN + f"[+] Cleared environment variable: {FLAGS_ENV_VAR}")


def load_saved_flags() -> Dict:
    """Load saved flag combinations from file."""
    flags_file = get_flags_file_path()
    if not flags_file or not os.path.exists(flags_file):
        return {}

    try:
        with open(flags_file, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(Fore.RED + f"[!] Error loading flags file: {e}")
        return {}


def save_flags(flags_data: Dict) -> bool:
    """Save flag combinations to file."""
    flags_file = get_flags_file_path()
    if not flags_file:
        return False

    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(flags_file), exist_ok=True)

        with open(flags_file, "w") as f:
            json.dump(flags_data, f, indent=2)
        return True
    except IOError as e:
        print(Fore.RED + f"[!] Error saving flags file: {e}")
        return False


def add_flag_combination(scan_type: str, name: str, flags: str) -> None:
    """Add a new flag combination to the saved flags."""
    flags_data = load_saved_flags()

    if scan_type not in flags_data:
        flags_data[scan_type] = {}

    flags_data[scan_type][name] = flags
    save_flags(flags_data)


def get_saved_flag_combinations(scan_type: str) -> Dict[str, str]:
    """Get saved flag combinations for a specific scan type."""
    flags_data = load_saved_flags()
    return flags_data.get(scan_type, {})


def prompt_to_configure_flags_file() -> bool:
    """Prompt user to configure flags file for persistent storage."""
    print(Fore.CYAN + "\n=== Flag Storage Setup ===")
    print(
        "Would you like to set up persistent storage for your custom flag combinations?"
    )
    print("This will allow you to save and reuse flag combinations across sessions.")

    while True:
        choice = smart_input(
            Fore.YELLOW + "Set up flag storage? (y/n): ", single_key=True
        ).lower()
        if choice in ["y", "n"]:
            break
        print(Fore.RED + "Please enter 'y' or 'n'")

    if choice == "y":
        while True:
            file_path = smart_input(
                Fore.YELLOW + "Enter path for flags file (e.g., ~/.fnw/flags.json): "
            ).strip()
            if file_path:
                # Expand user home directory if needed
                if file_path.startswith("~/"):
                    file_path = os.path.expanduser(file_path)
                set_flags_file_path(file_path)
                return True
            else:
                print(Fore.RED + "Path cannot be empty.")
    return False


def prompt_to_save_flags(scan_type: str, flags: str) -> None:
    """Prompt user to save new flag combination if it doesn't already exist."""
    flags_file = get_flags_file_path()

    # If no flags file is configured, ask if user wants to set it up
    if not flags_file:
        if prompt_to_configure_flags_file():
            flags_file = get_flags_file_path()
        else:
            return

    # Check if this exact flag combination already exists
    saved_flags = get_saved_flag_combinations(scan_type)
    if flags in saved_flags.values():
        # Flags already exist, no need to prompt
        return

    print(
        Fore.CYAN
        + f"\nWould you like to save this {scan_type.upper()} flag combination?"
    )
    print(Fore.YELLOW + f"Flags: {flags}")

    while True:
        choice = smart_input(
            Fore.YELLOW + "Save flags? (y/n): ", single_key=True
        ).lower()
        if choice in ["y", "n"]:
            break
        print(Fore.RED + "Please enter 'y' or 'n'")

    if choice == "y":
        name = smart_input(
            Fore.YELLOW + "Enter a name for this flag combination: "
        ).strip()
        if name:
            add_flag_combination(scan_type, name, flags)
            print(Fore.GREEN + f"[+] Saved {scan_type.upper()} flags as '{name}'")


def get_custom_flags_with_validation(scan_type: str) -> Optional[str]:
    """Get custom flags from user with validation and warning system."""
    print(Fore.CYAN + f"\n=== Custom {scan_type.upper()} Flags Input ===")

    # Check for existing saved flags
    saved_flags = get_saved_flag_combinations(scan_type)
    if saved_flags:
        print(Fore.YELLOW + "Choose an option:")
        print("1. Use existing saved flag combination")
        print("2. Enter new custom flags")
        print("3. Cancel")

        while True:
            choice = smart_input(
                Fore.YELLOW + "Choose option: ", single_key=True
            ).strip()
            if choice == "1":
                # Show saved flag combinations
                print(Fore.CYAN + f"\nSaved {scan_type.upper()} flag combinations:")
                flag_names = list(saved_flags.keys())
                for i, name in enumerate(flag_names, 1):
                    print(f"{i}. {name} ({saved_flags[name]})")

                while True:
                    try:
                        selection = smart_input(
                            Fore.YELLOW
                            + f"Choose saved {scan_type.upper()} flags "
                            + f"(1-{len(flag_names)}): "
                        ).strip()
                        index = int(selection) - 1
                        if 0 <= index < len(flag_names):
                            selected_name = flag_names[index]
                            selected_flags = saved_flags[selected_name]
                            print(
                                Fore.GREEN + f"[+] Using saved flags: {selected_name}"
                            )
                            return selected_flags
                        else:
                            print(Fore.RED + "Invalid choice.")
                    except ValueError:
                        print(Fore.RED + "Please enter a valid number.")
            elif choice == "2":
                break  # Continue to new flag input
            elif choice == "3":
                return None
            else:
                print(Fore.RED + "Please enter 1, 2, or 3.")

    # Enter new custom flags
    print(
        Fore.YELLOW
        + "Enter space-separated nmap flags. Type 'd' when done, 'c' to cancel."
    )
    print(Fore.CYAN + "Example: -sV -sC -A -Pn")

    all_flags = []

    while True:
        flag_input = smart_input(
            Fore.YELLOW + "Enter flags (or 'd' for done, 'c' to cancel): "
        ).strip()

        if flag_input.lower() == "d":
            if not all_flags:
                print(
                    Fore.RED
                    + "No flags entered. Please enter at least one flag or "
                    + "'c' to cancel."
                )
                continue
            break
        elif flag_input.lower() == "c":
            return None
        elif not flag_input:
            print(
                Fore.RED
                + "Empty input. Please enter flags, 'd' for done, or 'c' to cancel."
            )
            continue

        # Validate the flags
        flags_list = flag_input.split()
        valid_flags, invalid_flags, warnings = validate_nmap_flags(
            flags_list, scan_type
        )

        # Add valid flags to our collection
        all_flags.extend(valid_flags)

        # Show warnings for invalid flags
        if invalid_flags:
            print(Fore.RED + f"[!] Invalid flags: {', '.join(invalid_flags)}")

        # Show compatibility warnings
        for warning in warnings:
            print(Fore.YELLOW + f"[!] {warning}")

        # Show current valid flags
        if all_flags:
            print(Fore.GREEN + f"[+] Current valid flags: {' '.join(all_flags)}")

    # Return the final validated flags
    final_flags = " ".join(all_flags)
    print(Fore.GREEN + f"[+] Final {scan_type.upper()} flags: {final_flags}")
    return final_flags


def load_config() -> Dict:
    """Load configuration from config.json or create default."""
    config_file = "config.json"
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                # Merge with defaults for any missing keys
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
        except (json.JSONDecodeError, IOError) as e:
            print(Fore.RED + f"[!] Error loading config: {e}")
            print(Fore.YELLOW + "[!] Using default configuration.")

    return DEFAULT_CONFIG.copy()


def save_config(config: Dict) -> None:
    """Save configuration to config.json."""
    try:
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        print(Fore.RED + f"[!] Error saving config: {e}")


def show_banner():
    """Display the application banner."""
    banner = pyfiglet.figlet_format("FNW", font="slant")
    print()
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "Fancy Nmap Wrapper - Advanced Network Scanner")
    print(Fore.YELLOW + "=" * 60)


class Scan:
    """Base class for all scan types."""

    def __init__(self, scan_type: str, mode: str = "internal"):
        """Initialize the scan."""
        self.scan_type = scan_type
        self.mode = mode
        self.targets = []
        self.files_created = []
        self.scan_manager: Optional["ScanManager"] = None  # Will be set by ScanManager
        self.subnet = None

    def execute(self, config: Dict) -> List[Dict]:
        """Execute the scan. Override in subclasses."""
        raise NotImplementedError

    def display_info(self) -> str:
        """Display scan information. Override in subclasses."""
        raise NotImplementedError


class DiscoveryScan(Scan):
    """Host discovery via ping sweep."""

    def __init__(
        self, subnets: List[str], subnet_categorization: Optional[Dict[str, str]] = None
    ):
        """Initialize the discovery scan."""
        super().__init__("discovery")
        self.subnets = subnets
        self.subnet_categorization = subnet_categorization or {}

    def execute(self, config: Dict) -> List[str]:
        """Execute discovery scan and return list of reachable hosts."""
        print(Fore.CYAN + "\n=== Starting Host Discovery (Ping Sweep) ===\n")

        targets_file = os.path.join(config["output_directory"], "targets.txt")

        # Read existing targets if file exists
        existing_targets = set()
        if os.path.exists(targets_file):
            try:
                with open(targets_file, "r") as f:
                    existing_targets = {line.strip() for line in f if line.strip()}
            except IOError:
                pass

        # Generate all host IPs from subnets
        all_hosts = []
        for subnet in self.subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                all_hosts.extend([str(ip) for ip in network.hosts()])
            except Exception as e:
                print(Fore.RED + f"Invalid subnet {subnet}: {e}")
                continue

        # Ping sweep with progress bar
        reachable = []
        with ThreadPoolExecutor(max_workers=config["thread_count"]) as executor:
            futures = {executor.submit(self._ping_host, ip): ip for ip in all_hosts}

            with tqdm(
                total=len(futures),
                desc="Discovery Progress",
                colour="CYAN",
                ncols=80,
            ) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        reachable.append(result)
                    pbar.update(1)

        # Merge with existing targets and write back
        all_targets = existing_targets.union(set(reachable))

        # Ensure output directory exists
        os.makedirs(config["output_directory"], exist_ok=True)

        # Write all targets back to file
        with open(targets_file, "w") as f:
            for ip in sorted(all_targets):
                f.write(ip + "\n")

        # Show results
        if reachable:
            print(
                Fore.GREEN
                + f"\n[+] Discovery complete. {len(reachable)} new hosts found."
            )
            if existing_targets:
                print(
                    Fore.YELLOW
                    + f"[*] Combined with {len(existing_targets)} existing targets."
                )
                print(Fore.YELLOW + f"[*] Total targets: {len(all_targets)}")
        else:
            print(Fore.YELLOW + "\n[!] No new hosts discovered.")

        # Update targets list
        self.targets = list(all_targets)

        return self.targets

    def _ping_host(self, host: str) -> Optional[str]:
        """Ping a host once to determine reachability."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return host if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def display_info(self) -> str:
        """Display discovery scan information."""
        return (
            f"Discovery Scan | Subnets: {', '.join(self.subnets)} | "
            f"Targets: {len(self.targets)}"
        )


class TCPScan(Scan):
    """TCP port scan."""

    def __init__(
        self,
        mode: str = "internal",
        nmap_flags: Optional[str] = None,
        ports: Optional[Union[str, List[int]]] = None,
        subnet: Optional[str] = None,
    ):
        """Initialize the TCP scan."""
        super().__init__("tcp", mode)
        self.nmap_flags = nmap_flags or " ".join(
            DEFAULT_CONFIG["nmap_flags_tcp"]["default"]
        )
        self.ports = ports
        self.subnet = subnet

    def execute(self, config: Dict) -> List[Dict]:
        """Execute TCP scan (now handled by ScanManager for concurrent execution)."""
        # This method is kept for compatibility but execution is now handled by
        # ScanManager
        return []

    def _scan_host(self, target: str, config: Dict) -> Optional[Dict]:
        """Scan a single host with TCP scan."""
        # Use individual target IP in filename for better organization
        output_file = os.path.join(
            config["output_directory"], f"portscan_{self.mode}_tcp_{target}.txt"
        )

        # Track this flag combination for the target
        if hasattr(self, "scan_manager") and self.scan_manager:
            self.scan_manager.add_scan_combination(target, "tcp", self.nmap_flags)

        # Build port specification
        if self.ports:
            if isinstance(self.ports, list):
                port_spec = f"-p {','.join(map(str, self.ports))}"
            else:
                port_spec = f"-p {self.ports}"
        else:
            port_spec = f"-p {DEFAULT_CONFIG['tcp_ports_full_scan']}"

        cmd = f"nmap {self.nmap_flags} {port_spec} {target}".strip()
        header = self._write_command_header(output_file, cmd)

        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=300
            )

            # Check for TCP scan failure conditions with improved regex
            import re

            failure_patterns = [
                r"Host seems down",
                r"Scan timed out after \d+(?:\.\d{1,3})? minutes?",
                r"Scan timed out",
            ]

            for pattern in failure_patterns:
                if re.search(pattern, result.stdout):
                    # Mark this IP as failed to cancel remaining scans
                    if hasattr(self, "scan_manager") and self.scan_manager:
                        self.scan_manager.mark_ip_failed(target)

                    print(
                        Fore.RED
                        + f"[!] TCP scan failed for {target}: "
                        + "Host seems down or scan timed out"
                    )
                    return {
                        "target": target,
                        "error": "Host seems down or scan timed out",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "returncode": result.returncode,
                    }

            # Check if file already exists (multiple flag combinations)
            file_exists = os.path.exists(output_file)
            mode = "a" if file_exists else "w"

            with open(output_file, mode) as f:
                if file_exists:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"Additional scan with flags: {self.nmap_flags}\n")
                    f.write(f"{'='*60}\n\n")
                f.write(header)
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\nSTDERR:\n{result.stderr}")

            if not file_exists:
                self.files_created.append(output_file)

            return {
                "target": target,
                "file": output_file,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }

        except subprocess.TimeoutExpired:
            # Mark this IP as failed to cancel remaining scans
            if hasattr(self, "scan_manager") and self.scan_manager:
                self.scan_manager.mark_ip_failed(target)

            with open(output_file, "w") as f:
                f.write(header)
                f.write("Scan timed out after 5 minutes.\n")
            self.files_created.append(output_file)
            return {"target": target, "file": output_file, "error": "Timeout"}
        except Exception as e:
            return {"target": target, "error": str(e)}

    def _write_command_header(self, filepath: str, cmd: str) -> str:
        """Write command header to output file."""
        header = (
            "===== Executed Command =====\n"
            f"{cmd}\n"
            "============================\n\n"
        )
        return header

    def display_info(self) -> str:
        """Display TCP scan information."""
        subnet_info = f" | Subnet: {self.subnet}" if self.subnet else ""
        return (
            f"TCP Scan | Mode: {self.mode} | Flags: {self.nmap_flags} | "
            f"Targets: {len(self.targets)}{subnet_info}"
        )


class UDPScan(Scan):
    """UDP port scan."""

    def __init__(
        self,
        mode: str = "internal",
        nmap_flags: Optional[str] = None,
        ports: Optional[Union[str, List[int]]] = None,
        subnet: Optional[str] = None,
    ):
        """Initialize the UDP scan."""
        super().__init__("udp", mode)
        self.nmap_flags = nmap_flags or " ".join(
            DEFAULT_CONFIG["nmap_flags_udp"]["default"]
        )
        self.ports = ports
        self.subnet = subnet

    def execute(self, config: Dict) -> List[Dict]:
        """Execute UDP scan (now handled by ScanManager for concurrent execution)."""
        # This method is kept for compatibility but execution is now handled by
        # ScanManager
        return []

    def _scan_host(self, target: str, config: Dict) -> Optional[Dict]:
        """Scan a single host with UDP scan using two-phase approach."""
        # Use individual target IP in filename for better organization
        output_file = os.path.join(
            config["output_directory"], f"portscan_{self.mode}_udp_{target}.txt"
        )

        # Track this flag combination for the target
        if hasattr(self, "scan_manager") and self.scan_manager:
            self.scan_manager.add_scan_combination(target, "udp", self.nmap_flags)

        # If no specific ports are provided and we have -p 1-65535 in flags,
        # do simple scan
        if not self.ports and "-p 1-65535" in self.nmap_flags:
            print(
                Fore.CYAN + f"[*] Simple UDP scan for {target} "
                f"(all ports, no scripts)"
            )
            return self._execute_simple_udp_scan(target, config, output_file)

        # Phase 1: Execute initial scan without NSE scripts to identify non-closed ports
        print(Fore.CYAN + f"[*] Phase 1: Initial UDP scan for {target}")
        initial_ports = self._execute_initial_udp_scan(target, config)

        if not initial_ports:
            print(Fore.YELLOW + f"[!] No non-closed UDP ports found for {target}")
            return {
                "target": target,
                "error": "No non-closed ports found",
                "stdout": "",
                "stderr": "No non-closed ports found",
                "returncode": -1,
            }

        print(
            Fore.GREEN
            + f"[+] Found {len(initial_ports)} non-closed ports: {initial_ports}"
        )

        # Phase 2: Execute NSE script scans for each non-closed port
        print(Fore.CYAN + f"[*] Phase 2: NSE script scans for {target}")
        results = self._execute_nse_scans_for_ports(target, initial_ports, config)

        # Filter results to only keep those with "open" ports
        open_results = [
            r for r in results if r and "open" in r.get("stdout", "").lower()
        ]

        if not open_results:
            print(Fore.YELLOW + f"[!] No open UDP ports found for {target}")
            return {
                "target": target,
                "error": "No open ports found",
                "stdout": "",
                "stderr": "No open ports found",
                "returncode": -1,
            }

        # Write combined results to file
        self._write_combined_udp_results(output_file, open_results, target)

        if not os.path.exists(output_file):
            self.files_created.append(output_file)

        return {
            "target": target,
            "file": output_file,
            "stdout": "\n".join([r.get("stdout", "") for r in open_results]),
            "stderr": "\n".join(
                [r.get("stderr", "") for r in open_results if r.get("stderr")]
            ),
            "returncode": 0,
            "ports_scanned": len(initial_ports),
            "open_ports_found": len(open_results),
        }

    def _execute_initial_udp_scan(self, target: str, config: Dict) -> List[int]:
        """Execute initial UDP scan without NSE scripts to identify non-closed ports."""
        # Get list of ports to scan
        ports_to_scan = self._get_ports_to_scan()

        if not ports_to_scan:
            return []

        # Build port specification
        port_spec = f"-p {','.join(map(str, ports_to_scan))}"

        # Build command without NSE scripts
        cmd = f"nmap {self.nmap_flags} {port_spec} {target}".strip()

        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=300
            )

            # Check for UDP scan failure condition
            import re

            ignored_states_pattern = (
                r"All (\d+) scanned ports on ([^\s]+) are in ignored states"
            )
            match = re.search(ignored_states_pattern, result.stdout)

            if match:
                num_ports = match.group(1)
                ip_addr = match.group(2)

                # Mark this IP as failed to cancel remaining scans
                if hasattr(self, "scan_manager") and self.scan_manager:
                    self.scan_manager.mark_ip_failed(target)

                print(
                    Fore.RED
                    + f"[!] Initial UDP scan failed for {ip_addr}: "
                    + f"All {num_ports} scanned ports are in ignored states"
                )
                return []

            # Parse results to find non-closed ports
            non_closed_ports = self._parse_udp_scan_results(
                result.stdout, ports_to_scan
            )
            return non_closed_ports

        except subprocess.TimeoutExpired:
            print(Fore.RED + f"[!] Initial UDP scan timed out for {target}")
            return []
        except Exception as e:
            print(Fore.RED + f"[!] Initial UDP scan error for {target}: {e}")
            return []

    def _parse_udp_scan_results(
        self, stdout: str, ports_scanned: List[int]
    ) -> List[int]:
        """Parse UDP scan results to find non-closed ports."""
        import re

        non_closed_ports = []

        # Look for port status lines in the output
        # Format: "PORT     STATE         SERVICE"
        #         "53/udp   open|filtered|open|filtered  domain"
        port_status_pattern = r"(\d+)/udp\s+(open|filtered|open\|filtered)"

        for line in stdout.split("\n"):
            match = re.search(port_status_pattern, line)
            if match:
                port = int(match.group(1))
                status = match.group(2)

                # Include ports that are not "closed"
                if port in ports_scanned and status not in ["closed"]:
                    non_closed_ports.append(port)

        return non_closed_ports

    def _execute_nse_scans_for_ports(
        self, target: str, ports: List[int], config: Dict
    ) -> List[Optional[Dict]]:
        """Execute NSE script scans for specific ports using ThreadPoolExecutor."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []

        with ThreadPoolExecutor(max_workers=len(ports)) as executor:
            # Submit individual port scans
            future_to_port = {
                executor.submit(self._scan_single_port, target, port, config): port
                for port in ports
            }

            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(Fore.RED + f"[!] Error scanning port {port} on {target}: {e}")
                    results.append(None)

        return results

    def _execute_simple_udp_scan(
        self, target: str, config: Dict, output_file: str
    ) -> Optional[Dict]:
        """Execute a simple UDP scan without NSE scripts for all ports."""
        # Build command for simple UDP scan
        cmd = f"nmap {self.nmap_flags} {target}".strip()

        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=300
            )

            # Check for UDP scan failure condition
            import re

            ignored_states_pattern = (
                r"All (\d+) scanned ports on ([^\s]+) are in ignored states"
            )
            match = re.search(ignored_states_pattern, result.stdout)

            if match:
                num_ports = match.group(1)
                ip_addr = match.group(2)

                # Mark this IP as failed to cancel remaining scans
                if hasattr(self, "scan_manager") and self.scan_manager:
                    self.scan_manager.mark_ip_failed(target)

                print(
                    Fore.RED
                    + f"[!] UDP scan failed for {ip_addr}: "
                    + f"All {num_ports} scanned ports are in ignored states"
                )
                return {
                    "target": target,
                    "error": f"All {num_ports} scanned ports are in ignored states",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                }

            # Write output to file
            with open(output_file, "w") as f:
                f.write(f"Command: {cmd}\n")
                f.write(f"Target: {target}\n")
                f.write(f"Return code: {result.returncode}\n")
                f.write("=" * 50 + "\n")
                f.write("STDOUT:\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\nSTDERR:\n")
                    f.write(result.stderr)

            print(Fore.GREEN + f"[+] UDP scan completed for {target}")
            print(Fore.YELLOW + f"[*] Results saved to: {output_file}")

            return {
                "target": target,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": cmd,
                "output_file": output_file,
            }

        except subprocess.TimeoutExpired:
            print(Fore.RED + f"[!] UDP scan timed out for {target}")
            return {
                "target": target,
                "error": "Scan timed out",
                "stdout": "",
                "stderr": "Scan timed out after 300 seconds",
                "returncode": -1,
            }
        except Exception as e:
            print(Fore.RED + f"[!] UDP scan failed for {target}: {e}")
            return {
                "target": target,
                "error": str(e),
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
            }

    def _get_ports_to_scan(self) -> List[int]:
        """Get list of ports to scan based on configuration."""
        if self.ports:
            # Parse specified ports
            port_list = []
            if isinstance(self.ports, list):
                port_list = self.ports
            else:
                # Parse string format like "53,161,500-510"
                for port_spec in str(self.ports).split(","):
                    port_spec = port_spec.strip()
                    if "-" in port_spec:
                        # Port range
                        start, end = map(int, port_spec.split("-"))
                        port_list.extend(range(start, end + 1))
                    else:
                        # Single port
                        port_list.append(int(port_spec))

            # Filter to only include ports that have NSE scripts
            return [port for port in port_list if port in UDP_NSE_SCRIPTS]
        else:
            # Use all ports that have NSE scripts
            return list(UDP_NSE_SCRIPTS.keys())

    def _scan_single_port(self, target: str, port: int, config: Dict) -> Optional[Dict]:
        """Scan a single port with its specific NSE scripts."""
        # Get scripts for this specific port
        scripts = UDP_NSE_SCRIPTS.get(port, "")
        if not scripts:
            return None

        # Build command for this specific port only
        port_spec = f"-p {port}"
        scripts_arg = f"--script {scripts}"

        cmd = f"nmap {self.nmap_flags} {port_spec} {scripts_arg} {target}".strip()

        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=300
            )

            # Check for UDP scan failure condition
            import re

            ignored_states_pattern = (
                r"All (\d+) scanned ports on ([^\s]+) are in ignored states"
            )
            match = re.search(ignored_states_pattern, result.stdout)

            if match:
                num_ports = match.group(1)
                ip_addr = match.group(2)

                # Mark this IP as failed to cancel remaining scans
                if hasattr(self, "scan_manager") and self.scan_manager:
                    self.scan_manager.mark_ip_failed(target)

                print(
                    Fore.RED
                    + f"[!] UDP scan failed for {ip_addr} port {port}: "
                    + f"All {num_ports} scanned ports are in ignored states"
                )
                return None

            # Only return result if it contains "open"
            if "open" in result.stdout.lower():
                return {
                    "port": port,
                    "scripts": scripts,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "command": cmd,
                }
            else:
                return None

        except subprocess.TimeoutExpired:
            print(Fore.RED + f"[!] UDP scan timed out for {target} port {port}")
            return None
        except Exception as e:
            print(Fore.RED + f"[!] UDP scan error for {target} port {port}: {e}")
            return None

    def _write_combined_udp_results(
        self, output_file: str, results: List[Dict], target: str
    ):
        """Write combined results from all port scans to output file."""
        # Check if file already exists (multiple flag combinations)
        file_exists = os.path.exists(output_file)
        mode = "a" if file_exists else "w"

        with open(output_file, mode) as f:
            if file_exists:
                f.write(f"\n{'='*60}\n")
                f.write(f"Additional scan with flags: {self.nmap_flags}\n")
                f.write(f"{'='*60}\n\n")

            # Write header
            f.write(f"UDP Port Scan Results for {target}\n")
            f.write(f"Scan executed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Flags used: {self.nmap_flags}\n")
            f.write(f"Total ports scanned: {len(results)}\n")
            f.write(f"Open ports found: {len(results)}\n")
            f.write("=" * 60 + "\n\n")

            # Write results for each port
            for result in results:
                if result:
                    f.write(f"--- Port {result['port']} ---\n")
                    f.write(f"Scripts: {result['scripts']}\n")
                    f.write(f"Command: {result['command']}\n")
                    f.write("-" * 40 + "\n")
                    f.write(result["stdout"])
                    if result.get("stderr"):
                        f.write(f"\n--- STDERR ---\n{result['stderr']}")
                    f.write("\n" + "=" * 60 + "\n\n")

    def _write_command_header(self, filepath: str, cmd: str) -> str:
        """Write command header to output file."""
        header = (
            "===== Executed Command =====\n"
            f"{cmd}\n"
            "============================\n\n"
        )
        return header

    def display_info(self) -> str:
        """Display UDP scan information."""
        subnet_info = f" | Subnet: {self.subnet}" if self.subnet else ""
        return (
            f"UDP Scan | Mode: {self.mode} | Flags: {self.nmap_flags} | "
            f"Targets: {len(self.targets)}{subnet_info}"
        )


class ScanManager:
    """Manages scan execution and target management."""

    def __init__(self, config: Dict):
        """Initialize the scan manager."""
        self.config = config
        self.scans = []
        self.categorized_targets = {}
        self.existing_targets = []
        self.previously_categorized_subnets = (
            {}
        )  # Track subnets that were categorized but removed
        self.categorizations_file = os.path.join(
            config["output_directory"], "categorizations.json"
        )
        self.scan_combinations = {}  # (ip, protocol) -> [flag_combinations]
        self.failed_ips = set()  # Track IPs that have failed to cancel remaining scans
        self.load_categorizations()

    def add_scan(self, scan: Scan) -> None:
        """Add a scan to the manager."""
        if len(self.scans) >= 20:
            print(Fore.RED + "[!] Maximum scan limit (20) reached.")
            return
        self.scans.append(scan)
        print(Fore.GREEN + f"[+] {scan.scan_type.title()} scan added.")

    def remove_scan(self, index: int) -> bool:
        """Remove a scan by index."""
        if 0 <= index < len(self.scans):
            removed = self.scans.pop(index)
            print(Fore.YELLOW + f"[!] Removed: {removed.display_info()}")
            return True
        return False

    def add_scan_combination(self, ip: str, protocol: str, flags: str) -> None:
        """Add a flag combination for a specific IP and protocol."""
        key = (ip, protocol)
        if key not in self.scan_combinations:
            self.scan_combinations[key] = []

        if flags not in self.scan_combinations[key]:
            self.scan_combinations[key].append(flags)
            print(
                Fore.CYAN + f"[+] Added flag combination for {ip} ({protocol}): {flags}"
            )

    def get_scan_combinations(self, ip: str, protocol: str) -> List[str]:
        """Get all flag combinations for a specific IP and protocol."""
        key = (ip, protocol)
        return self.scan_combinations.get(key, [])

    def mark_ip_failed(self, ip: str) -> None:
        """Mark an IP as failed to cancel remaining scans for it."""
        self.failed_ips.add(ip)
        print(
            Fore.YELLOW
            + f"[!] Marking {ip} as failed - cancelling remaining scans for this IP"
        )

    def is_ip_failed(self, ip: str) -> bool:
        """Check if an IP has been marked as failed."""
        return ip in self.failed_ips

    def _ping_host(self, host: str) -> Optional[str]:
        """Ping a host once to determine reachability."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return host if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def list_scans(self) -> None:
        """List all configured scans."""
        if not self.scans:
            print(Fore.YELLOW + "[!] No scans configured.")
            return

        # Calculate the maximum length of scan info strings
        max_length = 0
        scan_strings = []
        for i, scan in enumerate(self.scans, 1):
            scan_info = f"{i}. {scan.display_info()}"
            scan_strings.append(scan_info)
            max_length = max(max_length, len(scan_info))

        # Add some padding and ensure minimum width
        box_width = max(max_length + 4, 80)
        title = "Configured Scans"
        title_padding = (box_width - len(title)) // 2

        print(Fore.CYAN + "\n┌" + "─" * box_width + "┐")
        print(
            Fore.CYAN
            + "│"
            + " " * title_padding
            + title
            + " " * (box_width - title_padding - len(title))
            + "│"
        )
        print(Fore.CYAN + "├" + "─" * box_width + "┤")
        for scan_string in scan_strings:
            # Pad the line to fit in the box
            padded_info = scan_string.ljust(box_width - 2)
            print(Fore.CYAN + f"│ {padded_info} │")
        print(Fore.CYAN + "└" + "─" * box_width + "┘")

    def categorize_targets_by_subnet(self, targets: List[str]) -> Dict[str, Dict]:
        """Categorize targets by subnet and determine if internal/external."""
        subnet_targets = {}

        for target in targets:
            try:
                ip = ipaddress.ip_address(target)
                # Create /24 subnet for the IP
                subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnet_str = str(subnet)

                if subnet_str not in subnet_targets:
                    subnet_targets[subnet_str] = {
                        "targets": set(),
                        "mode": None,
                        "count": 0,
                    }

                subnet_targets[subnet_str]["targets"].add(target)
                subnet_targets[subnet_str]["count"] = len(
                    subnet_targets[subnet_str]["targets"]
                )

            except ValueError:
                continue

        return subnet_targets

    def get_subnet_scan_mode(self, subnet: str) -> str:
        """Get the scan mode for a subnet (internal/external)."""
        if subnet in self.categorized_targets:
            return self.categorized_targets[subnet]["mode"]
        return "internal"  # Default to internal

    def was_subnet_previously_categorized(self, subnet: str) -> tuple[bool, str]:
        """Check if a subnet was previously categorized and return the mode if so."""
        if subnet in self.previously_categorized_subnets:
            return True, self.previously_categorized_subnets[subnet]
        return False, ""

    def preserve_subnet_categorization(self, subnet: str, mode: str) -> None:
        """Preserve a subnet's categorization when it's removed."""
        self.previously_categorized_subnets[subnet] = mode

    def load_categorizations(self) -> None:
        """Load subnet categorizations from JSON file."""
        if os.path.exists(self.categorizations_file):
            try:
                with open(self.categorizations_file, "r") as f:
                    categorizations = json.load(f)
                    # Update previously categorized subnets with persistent
                    # categorizations
                    self.previously_categorized_subnets.update(categorizations)
            except (json.JSONDecodeError, IOError) as e:
                print(Fore.YELLOW + f"[!] Warning: Could not load categorizations: {e}")

    def save_categorization(self, subnet: str, mode: str) -> None:
        """Save a subnet categorization to JSON file."""
        try:
            # Load existing categorizations
            categorizations = {}
            if os.path.exists(self.categorizations_file):
                with open(self.categorizations_file, "r") as f:
                    categorizations = json.load(f)

            # Update with new categorization
            categorizations[subnet] = mode

            # Save back to file
            with open(self.categorizations_file, "w") as f:
                json.dump(categorizations, f, indent=4)

        except (json.JSONDecodeError, IOError) as e:
            print(Fore.RED + f"[!] Error saving categorization: {e}")

    def get_persistent_categorization(self, subnet: str) -> Optional[str]:
        """Get the persistent categorization for a subnet."""
        if subnet in self.previously_categorized_subnets:
            return self.previously_categorized_subnets[subnet]
        return None

    def load_existing_targets(self) -> bool:
        """Load and categorize existing targets from targets.txt."""
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            return False

        try:
            with open(targets_file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]

            if targets:
                self.existing_targets = targets
                new_categorized = self.categorize_targets_by_subnet(targets)

                # Preserve existing mode categorizations - this is crucial for
                # session persistence
                if self.categorized_targets:
                    for subnet, info in new_categorized.items():
                        if (
                            subnet in self.categorized_targets
                            and self.categorized_targets[subnet]["mode"] is not None
                        ):
                            new_categorized[subnet]["mode"] = self.categorized_targets[
                                subnet
                            ]["mode"]
                            print(
                                Fore.GREEN
                                + "[+] Preserved existing categorization for "
                                + f"{subnet}: {
                                    self.categorized_targets[subnet]['mode']}"
                            )

                # Also check previously categorized subnets for any subnets that
                # were removed but had categorizations
                for subnet, info in new_categorized.items():
                    if subnet in self.previously_categorized_subnets:
                        new_categorized[subnet]["mode"] = (
                            self.previously_categorized_subnets[subnet]
                        )
                        print(
                            Fore.GREEN
                            + f"[+] Restored previous categorization for {subnet}: "
                            + f"{self.previously_categorized_subnets[subnet]}"
                        )
                        # Remove from previously categorized since we're using it again
                        del self.previously_categorized_subnets[subnet]

                # Check for persistent categorizations from JSON file
                for subnet, info in new_categorized.items():
                    persistent_mode = self.get_persistent_categorization(subnet)
                    if persistent_mode and info["mode"] is None:
                        new_categorized[subnet]["mode"] = persistent_mode
                        print(
                            Fore.GREEN
                            + f"[+] Applied persistent categorization for {subnet}: "
                            + f"{persistent_mode}"
                        )

                self.categorized_targets = new_categorized
                return True
        except IOError:
            pass

        return False

    def _update_target_counts_after_discovery(self) -> None:
        """Update target counts after discovery while preserving mode categorization."""
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            return

        try:
            with open(targets_file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]

            if targets:
                # Group targets by subnet
                subnet_targets = {}
                for target in targets:
                    try:
                        ip = ipaddress.ip_address(target)
                        subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
                        subnet_str = str(subnet)

                        if subnet_str not in subnet_targets:
                            subnet_targets[subnet_str] = []
                        subnet_targets[subnet_str].append(target)
                    except ValueError:
                        continue

                # Update counts and targets while preserving modes
                for subnet, ips in subnet_targets.items():
                    if subnet in self.categorized_targets:
                        # Preserve existing mode, update targets and count
                        self.categorized_targets[subnet]["targets"] = set(ips)
                        self.categorized_targets[subnet]["count"] = len(ips)
                    else:
                        # New subnet, create entry with default mode
                        self.categorized_targets[subnet] = {
                            "targets": set(ips),
                            "mode": None,  # Will need to be set by user
                            "count": len(ips),
                        }

        except IOError:
            pass

    def execute_all_scans(self) -> None:
        """Execute all configured scans in the proper order."""
        if not self.scans:
            print(Fore.RED + "[!] No scans configured.")
            return

        print(Fore.CYAN + "\n=== Executing All Scans ===")

        # Execute discovery scans first
        discovery_scans = [s for s in self.scans if isinstance(s, DiscoveryScan)]
        for scan in discovery_scans:
            # Store the subnet categorization before executing
            if hasattr(scan, "subnet_categorization"):
                for subnet, mode in scan.subnet_categorization.items():
                    if subnet not in self.categorized_targets:
                        self.categorized_targets[subnet] = {
                            "targets": set(),
                            "mode": mode,
                            "count": 0,
                        }
                    self.categorized_targets[subnet]["mode"] = mode

            scan.execute(self.config)
            # Update targets count but preserve mode categorization
            self._update_target_counts_after_discovery()
            # Remove discovery scan after completion
            self.scans.remove(scan)
            print(
                Fore.YELLOW + "[!] Discovery scan completed and removed from scan list."
            )

        # Execute TCP/UDP scans concurrently with separate progress bars
        tcp_scans = [s for s in self.scans if isinstance(s, TCPScan)]
        udp_scans = [s for s in self.scans if isinstance(s, UDPScan)]

        # Check if we have any scans to execute
        if not tcp_scans and not udp_scans:
            print(Fore.YELLOW + "[!] No TCP or UDP scans configured.")
            return

        # Perform ping sweep once for all targets
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            print(Fore.RED + "[!] No targets.txt found. Run discovery scan first.")
            return

        with open(targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

        if not targets:
            print(Fore.RED + "[!] No targets found in targets.txt.")
            return

        # Filter targets with ping sweep (only once)
        reachable_targets = self._filter_targets_with_ping(targets)
        if not reachable_targets:
            print(
                Fore.RED + "[!] No reachable targets found. No scans will be executed."
            )
            return

        # Start both scan types concurrently with filtered targets
        import threading

        tcp_thread = None
        udp_thread = None
        scans_executed = False

        if tcp_scans:
            tcp_thread = threading.Thread(
                target=self._execute_tcp_scans_with_targets,
                args=(tcp_scans, reachable_targets),
            )
            tcp_thread.start()
            scans_executed = True

        if udp_scans:
            udp_thread = threading.Thread(
                target=self._execute_udp_scans_with_targets,
                args=(udp_scans, reachable_targets),
            )
            udp_thread.start()
            scans_executed = True

        # Wait for both to complete
        if tcp_thread:
            tcp_thread.join()
        if udp_thread:
            udp_thread.join()

        # Only print completion message if scans were actually executed
        if scans_executed:
            print(Fore.GREEN + "\n[+] All scans completed.")

    def _filter_targets_with_ping(self, targets: List[str]) -> List[str]:
        """Filter targets with a quick ping sweep to remove non-responsive IPs."""
        if not targets:
            return []

        print(
            Fore.CYAN + f"[*] Performing quick ping sweep on {len(targets)} targets..."
        )

        # Use ThreadPoolExecutor for concurrent pings
        reachable_targets = []
        with ThreadPoolExecutor(max_workers=min(len(targets), 20)) as executor:
            futures = {
                executor.submit(self._ping_host, target): target for target in targets
            }

            for future in as_completed(futures):
                result = future.result()
                if result:  # If ping was successful
                    reachable_targets.append(result)

        unreachable_count = len(targets) - len(reachable_targets)
        if unreachable_count > 0:
            print(
                Fore.YELLOW
                + f"[*] {unreachable_count} targets did not respond to ping "
                + "and will be skipped"
            )

        if not reachable_targets:
            print(
                Fore.RED
                + "[!] No targets responded to ping. No scans will be executed."
            )
            return []

        print(
            Fore.GREEN
            + f"[+] {len(reachable_targets)} targets are reachable and will be scanned"
        )
        return reachable_targets

    def _execute_tcp_scans_with_targets(
        self, scans: List[Scan], targets: List[str]
    ) -> None:
        """Execute TCP scans concurrently with one thread per IP.

        Pre-filtered targets are used to reduce the number of scans.
        """
        if not targets:
            return

        # Create tasks for each scan and target combination
        all_tasks = []
        actual_targets = set()  # Track actual targets being scanned

        for scan in scans:
            if scan.subnet and scan.subnet in self.categorized_targets:
                # Scan all targets in the designated subnet
                subnet_targets = list(self.categorized_targets[scan.subnet]["targets"])
                actual_targets.update(subnet_targets)
                for target in subnet_targets:
                    all_tasks.append((scan, target))
            else:
                # If no subnet specified, scan all targets but this shouldn't
                # happen in normal operation
                print(
                    Fore.YELLOW
                    + f"[!] Warning: Scan {scan} has no subnet specified, "
                    + "scanning all targets"
                )
                actual_targets.update(targets)
                for target in targets:
                    all_tasks.append((scan, target))

        if not all_tasks:
            print(Fore.YELLOW + "[!] No valid targets found for TCP scans.")
            return

        # Report accurate scan and target counts
        unique_scans = len(set(scan.subnet for scan in scans if scan.subnet))
        print(
            Fore.CYAN
            + f"\n[*] Executing {len(scans)} TCP scan(s) against "
            + f"{len(actual_targets)} targets..."
        )
        if unique_scans != len(scans):
            print(
                Fore.YELLOW
                + f"[*] Note: {len(scans)} scan configurations targeting "
                + f"{unique_scans} unique subnets"
            )
        else:
            print(
                Fore.YELLOW + f"[*] Each scan targets its designated subnet with "
                f"{len(actual_targets)} total targets"
            )

        # Execute all tasks concurrently - one thread per IP address
        with ThreadPoolExecutor(
            max_workers=len(set(target for _, target in all_tasks))
        ) as executor:
            futures = {
                executor.submit(self._execute_scan_task, scan, target): (scan, target)
                for scan, target in all_tasks
            }

            with tqdm(
                total=len(futures),
                desc="TCP Scanning",
                colour="GREEN",
                ncols=100,
                position=0,
                leave=False,
                bar_format=(
                    "{l_bar}{bar}| {n_fmt}/{total_fmt} "
                    "[{elapsed}<{remaining}, {rate_fmt}]"
                ),
            ) as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        scan, target = futures[future]

                        if result and result.get("skipped"):
                            print(
                                Fore.YELLOW
                                + f"[!] Skipped scan for {target} (IP marked as failed)"
                            )

                        pbar.set_postfix({"Mode": scan.mode, "Target": target})
                        pbar.update(1)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error in TCP scan: {e}")
                        pbar.update(1)

    def _execute_tcp_scans(self, scans: List[Scan]) -> None:
        """Execute TCP scans concurrently with one thread per IP (legacy method)."""
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            print(Fore.RED + "[!] No targets.txt found. Run discovery scan first.")
            return

        with open(targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

        if not targets:
            print(Fore.RED + "[!] No targets found in targets.txt.")
            return

        # Use the new method with pre-filtered targets
        self._execute_tcp_scans_with_targets(scans, targets)

    def _execute_udp_scans_with_targets(
        self, scans: List[Scan], targets: List[str]
    ) -> None:
        """Execute UDP scans concurrently with one thread per IP.

        Pre-filtered targets are used to reduce the number of scans.
        """
        if not targets:
            return

        # Create tasks for each scan and target combination
        all_tasks = []
        actual_targets = set()  # Track actual targets being scanned

        for scan in scans:
            if scan.subnet and scan.subnet in self.categorized_targets:
                # Scan all targets in the designated subnet
                subnet_targets = list(self.categorized_targets[scan.subnet]["targets"])
                actual_targets.update(subnet_targets)
                for target in subnet_targets:
                    all_tasks.append((scan, target))
            else:
                # If no subnet specified, scan all targets but this shouldn't
                # happen in normal operation
                print(
                    Fore.YELLOW
                    + f"[!] Warning: Scan {scan} has no subnet specified, "
                    + "scanning all targets"
                )
                actual_targets.update(targets)
                for target in targets:
                    all_tasks.append((scan, target))

        if not all_tasks:
            print(Fore.YELLOW + "[!] No valid targets found for UDP scans.")
            return

        # Report accurate scan and target counts
        unique_scans = len(set(scan.subnet for scan in scans if scan.subnet))
        print(
            Fore.CYAN
            + f"\n[*] Executing {len(scans)} UDP scan(s) against {len(actual_targets)}"
            " total targets..."
        )
        if unique_scans != len(scans):
            print(
                Fore.YELLOW
                + f"[*] Note: {len(scans)} scan configurations targeting "
                + f"{unique_scans} unique subnets"
            )
        else:
            print(
                Fore.YELLOW + f"[*] Each scan targets its designated subnet with "
                f"{len(actual_targets)} total targets"
            )

        # Execute all tasks concurrently - one thread per IP address
        with ThreadPoolExecutor(
            max_workers=len(set(target for _, target in all_tasks))
        ) as executor:
            futures = {
                executor.submit(self._execute_scan_task, scan, target): (scan, target)
                for scan, target in all_tasks
            }

            with tqdm(
                total=len(futures),
                desc="UDP Scanning",
                colour="BLUE",
                ncols=100,
                position=1,
                leave=False,
                bar_format=(
                    "{l_bar}{bar}| {n_fmt}/{total_fmt} "
                    "[{elapsed}<{remaining}, {rate_fmt}]"
                ),
            ) as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        scan, target = futures[future]

                        if result and result.get("skipped"):
                            print(
                                Fore.YELLOW
                                + f"[!] Skipped scan for {target} (IP marked as failed)"
                            )

                        pbar.set_postfix({"Mode": scan.mode, "Target": target})
                        pbar.update(1)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error in UDP scan: {e}")
                        pbar.update(1)

    def _execute_udp_scans(self, scans: List[Scan]) -> None:
        """Execute UDP scans concurrently with one thread per IP (legacy method)."""
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            print(Fore.RED + "[!] No targets.txt found. Run discovery scan first.")
            return

        with open(targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

        if not targets:
            print(Fore.RED + "[!] No targets found in targets.txt.")
            return

        # Use the new method with pre-filtered targets
        self._execute_udp_scans_with_targets(scans, targets)

    def _execute_scan_task(self, scan: Scan, target: str) -> Optional[Dict]:
        """Execute a single scan task."""
        # Check if this IP has already failed - skip if so
        if self.is_ip_failed(target):
            return {
                "target": target,
                "error": "Skipped - IP marked as failed",
                "skipped": True,
            }

        # Set scan_manager reference for tracking combinations
        scan.scan_manager = self

        if isinstance(scan, TCPScan):
            return scan._scan_host(target, self.config)
        elif isinstance(scan, UDPScan):
            return scan._scan_host(target, self.config)
        return {"target": target, "error": "Unknown scan type"}


class UserInterface:
    """Handles user interaction and menu management."""

    def __init__(self):
        """Initialize the user interface."""
        self.config = load_config()
        self.scan_manager = ScanManager(self.config)
        # Load existing targets if available
        self.scan_manager.load_existing_targets()

    def main_menu(self) -> None:
        """Display the main menu."""
        while True:
            show_banner()
            print(Fore.CYAN + "\n=== Main Menu ===")
            print("1. Configure and Run Scans")
            print("2. View Configuration")
            print("3. Update Configuration")
            print("4. Advanced Configuration Management")
            print("5. Flag Management")
            print("6. Add IPs Manually")
            print("7. Exit")

            choice = smart_input(
                Fore.YELLOW + "Choose an option: ", single_key=True
            ).strip()

            if choice == "1":
                self.configure_and_run_scans()
            elif choice == "2":
                self.view_configuration()
            elif choice == "3":
                self.update_configuration()
            elif choice == "4":
                self.advanced_configuration_management()
            elif choice == "5":
                self.flag_management()
            elif choice == "6":
                self.add_ips_manually()
            elif choice == "7":
                print(Fore.LIGHTCYAN_EX + "Thanks for using the tool. :)")
                break
            else:
                print(Fore.RED + "Invalid option. Try again.")

    def configure_and_run_scans(self) -> None:
        """Configure and run scans."""
        while True:
            print(Fore.CYAN + "\n=== Configure and Run Scans ===")

            # Check for existing targets.txt each time
            targets_file = os.path.join(self.config["output_directory"], "targets.txt")
            if os.path.exists(targets_file):
                try:
                    with open(targets_file, "r") as f:
                        existing_targets = [line.strip() for line in f if line.strip()]
                    if existing_targets:
                        print(
                            Fore.YELLOW + f"[*] Found existing targets.txt with "
                            f"{len(existing_targets)} targets"
                        )
                        # Reload categorized targets
                        self.scan_manager.load_existing_targets()
                except IOError:
                    pass

            print("1. Add Discovery Scan")
            print("2. Quick Scan (Full TCP/UDP Scan)")
            print("3. Advanced Scanning")
            print("4. Back to Main Menu")

            choice = smart_input(
                Fore.YELLOW + "Choose an option: ", single_key=True
            ).strip()

            if choice == "1":
                self.add_discovery_scan()
            elif choice == "2":
                self.quick_scan()
            elif choice == "3":
                self.advanced_scanning()
            elif choice == "4":
                break
            else:
                print(Fore.RED + "Invalid option. Try again.")

    def quick_scan(self) -> None:
        """Run a comprehensive scan with all available flag combinations."""
        print(Fore.CYAN + "\n=== Quick Scan (Multi-Flag Combination Scan) ===")

        # Continuously check for targets.txt file
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        max_attempts = 10
        attempt = 0

        while attempt < max_attempts:
            if os.path.exists(targets_file):
                try:
                    with open(targets_file, "r") as f:
                        targets = [line.strip() for line in f if line.strip()]

                    if targets:
                        print(
                            Fore.GREEN
                            + f"[+] Found {len(targets)} targets for scanning"
                        )
                        break
                    else:
                        print(
                            Fore.YELLOW + f"[*] targets.txt exists but is empty. "
                            f"Attempt {attempt + 1}/{max_attempts}"
                        )
                except IOError:
                    print(
                        Fore.YELLOW + f"[*] Error reading targets.txt. Attempt "
                        f"{attempt + 1}/{max_attempts}"
                    )
            else:
                print(
                    Fore.YELLOW + f"[*] Waiting for targets.txt file... Attempt "
                    f"{attempt + 1}/{max_attempts}"
                )
                print(
                    Fore.CYAN + "[*] You can manually create this file or run a "
                    "Discovery Scan"
                )

            if attempt < max_attempts - 1:
                print(
                    Fore.CYAN + "[*] Press Enter to check again, or Ctrl+C "
                    "to cancel..."
                )
                try:
                    input()
                    attempt += 1
                except KeyboardInterrupt:
                    print(Fore.LIGHTCYAN_EX + "\nCancelled Quick Scan.")
                    return
            else:
                attempt += 1

        if attempt >= max_attempts:
            print(
                Fore.RED
                + "[!] Maximum attempts reached. Please ensure targets.txt exists "
                "and contains valid targets."
            )
            return

        # Load existing categorizations
        self.scan_manager.load_existing_targets()

        if not self.scan_manager.categorized_targets:
            print(
                Fore.RED
                + "[!] No categorized subnets found. Please run discovery scan first."
            )
            return

        # Collect all available flag combinations
        tcp_combinations = self._get_all_tcp_flag_combinations()
        udp_combinations = self._get_all_udp_flag_combinations()

        # Generate dynamic message based on available combinations
        scan_message = self._generate_scan_message(tcp_combinations, udp_combinations)
        print(Fore.CYAN + f"\n[*] {scan_message}")

        # Create scans for each combination and subnet
        total_scans = 0
        for subnet, info in self.scan_manager.categorized_targets.items():
            if info["mode"] is not None:
                # Create TCP scans for each flag combination
                for flags in tcp_combinations:
                    tcp_scan = TCPScan(
                        mode=info["mode"], nmap_flags=flags, subnet=subnet
                    )
                    self.scan_manager.add_scan(tcp_scan)
                    total_scans += 1

                # Create UDP scans for each flag combination
                for flags in udp_combinations:
                    udp_scan = UDPScan(
                        mode=info["mode"], nmap_flags=flags, subnet=subnet
                    )
                    self.scan_manager.add_scan(udp_scan)
                    total_scans += 1

        print(
            Fore.GREEN + f"[+] Created {total_scans} total scans across "
            f"{len(self.scan_manager.categorized_targets)} subnets"
        )
        print(Fore.YELLOW + f"[*] TCP combinations: {len(tcp_combinations)}")
        print(Fore.YELLOW + f"[*] UDP combinations: {len(udp_combinations)}")

        # Execute the scans
        result = self.run_scans()
        if result == "main_menu":
            return

    def _get_all_tcp_flag_combinations(self) -> List[str]:
        """Get all available TCP flag combinations."""
        combinations = []

        # Add default flags
        default_flags = " ".join(self.config["nmap_flags_tcp"]["default"])
        combinations.append(default_flags)

        # Add custom flags from config
        for custom_flags in self.config["nmap_flags_tcp"]["custom"]:
            if custom_flags and custom_flags not in combinations:
                combinations.append(custom_flags)

        # Add saved flag combinations
        saved_flags = get_saved_flag_combinations("tcp")
        for flags in saved_flags.values():
            if flags and flags not in combinations:
                combinations.append(flags)

        return combinations

    def _get_all_udp_flag_combinations(self) -> List[str]:
        """Get all available UDP flag combinations."""
        combinations = []

        # Add default flags
        default_flags = " ".join(self.config["nmap_flags_udp"]["default"])
        combinations.append(default_flags)

        # Add custom flags from config
        for custom_flags in self.config["nmap_flags_udp"]["custom"]:
            if custom_flags and custom_flags not in combinations:
                combinations.append(custom_flags)

        # Add saved flag combinations
        saved_flags = get_saved_flag_combinations("udp")
        for flags in saved_flags.values():
            if flags and flags not in combinations:
                combinations.append(flags)

        return combinations

    def _generate_scan_message(
        self, tcp_combinations: List[str], udp_combinations: List[str]
    ) -> str:
        """Generate dynamic scan message based on available flag combinations."""
        has_default = len(tcp_combinations) > 0 or len(udp_combinations) > 0
        has_saved = bool(
            get_saved_flag_combinations("tcp") or get_saved_flag_combinations("udp")
        )

        # Check if custom flags exist in config
        has_config_custom = bool(self.config["nmap_flags_tcp"]["custom"]) or bool(
            self.config["nmap_flags_udp"]["custom"]
        )

        # Determine message components
        components = []
        if has_default:
            components.append("default")
        if has_config_custom:
            components.append("custom")
        if has_saved:
            components.append("persistent json")

        if not components:
            return "Scanning with defaults"
        elif len(components) == 1:
            return f"Scanning with {components[0]}"
        elif len(components) == 2:
            return f"Scanning with {components[0]} and {components[1]}"
        else:
            return f"Scanning with {', '.join(components[:-1])}, and {components[-1]}"

    def advanced_scanning(self) -> None:
        """Advanced scanning options for TCP/UDP scan configuration."""
        while True:
            print(Fore.CYAN + "\n=== Advanced Scanning ===")

            if self.scan_manager.scans:
                print("1. Run Scans")
                print("2. Add TCP Scan")
                print("3. Add UDP Scan")
                print("4. View Current Scans")
                print("5. Remove Scans")
                print("6. Back to Previous Menu")
            else:
                print("1. Add TCP Scan")
                print("2. Add UDP Scan")
                print("3. Back to Previous Menu")

            choice = smart_input(
                Fore.YELLOW + "Choose an option: ", single_key=True
            ).strip()

            if choice == "1" and self.scan_manager.scans:
                result = self.run_scans()
                if result == "main_menu":
                    return  # Return to main menu
            elif choice == "1" and not self.scan_manager.scans:
                self.add_tcp_scan()
            elif choice == "2" and self.scan_manager.scans:
                self.add_tcp_scan()
            elif choice == "2" and not self.scan_manager.scans:
                self.add_udp_scan()
            elif choice == "3" and self.scan_manager.scans:
                self.add_udp_scan()
            elif choice == "4" and self.scan_manager.scans:
                self.scan_manager.list_scans()
            elif choice == "5" and self.scan_manager.scans:
                self.remove_scans()
            elif choice == "6" and self.scan_manager.scans:
                break
            elif choice == "3" and not self.scan_manager.scans:
                break
            else:
                print(Fore.RED + "Invalid option. Try again.")

    def add_discovery_scan(self) -> None:
        """Add a discovery scan."""
        print(Fore.CYAN + "\n=== Add Discovery Scan ===")

        # Initialize subnets list first
        selected_subnets = []

        # Check for existing targets.txt
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        existing_targets = []
        if os.path.exists(targets_file):
            with open(targets_file, "r") as f:
                existing_targets = [line.strip() for line in f if line.strip()]

            if existing_targets:
                # Load existing targets into scan manager so categorizations can
                # be preserved
                self.scan_manager.load_existing_targets()

                print(
                    Fore.YELLOW + f"[!] Found existing targets.txt with "
                    f"{len(existing_targets)} targets:"
                )
                for i, ip in enumerate(existing_targets, 1):
                    print(f"  {i}. {ip}")

                print(Fore.CYAN + "\nWhat would you like to do?")
                print("1. Remove existing targets and start fresh")
                print("2. Add discovery scan for new subnets (keep existing)")
                print("3. Cancel and return to previous menu")

                choice = smart_input(
                    Fore.YELLOW + "Choose an option: ", single_key=True
                ).strip()

                if choice == "1":
                    # Preserve categorizations before removing targets
                    if self.scan_manager.categorized_targets:
                        for (
                            subnet,
                            info,
                        ) in self.scan_manager.categorized_targets.items():
                            if info["mode"] is not None:
                                # Save to persistent JSON storage
                                self.scan_manager.save_categorization(
                                    subnet, info["mode"]
                                )
                                # Also preserve in memory for this session
                                self.scan_manager.preserve_subnet_categorization(
                                    subnet, info["mode"]
                                )
                                print(
                                    Fore.GREEN + f"[+] Preserved categorization for "
                                    f"{subnet}: {info['mode']}"
                                )

                    os.remove(targets_file)
                    print(Fore.GREEN + "[+] Existing targets removed.")
                    existing_targets = []
                    # Clear the current categorized targets since we're starting
                    # fresh
                    self.scan_manager.categorized_targets = {}

                elif choice == "2":
                    print(
                        Fore.GREEN
                        + "[+] Keeping existing targets. New discovery scan will add "
                        "to them."
                    )
                    # Categorize existing targets by subnet and add them to
                    # selected_subnets
                    existing_subnets = self._categorize_existing_targets(
                        existing_targets
                    )
                    selected_subnets.extend(existing_subnets)
                    print(
                        Fore.GREEN
                        + f"[+] Added {len(existing_subnets)} existing subnets to "
                        "discovery scan"
                    )

                    # Ask if user wants to skip discovery
                    print(
                        Fore.CYAN
                        + "\nWould you like to skip discovery and use the existing "
                        "targets?"
                    )
                    print("1. Skip discovery (use existing targets)")
                    print("2. Continue with discovery scan")

                    skip_choice = smart_input(
                        Fore.YELLOW + "Choose option: ", single_key=True
                    ).strip()
                    if skip_choice == "1":
                        print(
                            Fore.GREEN
                            + "[+] Skipping discovery. Existing targets are ready for "
                            "TCP/UDP scans."
                        )
                        return
                    elif skip_choice == "2":
                        print(
                            Fore.GREEN + "[+] Continuing with discovery scan setup..."
                        )
                    else:
                        print(
                            Fore.RED
                            + "Invalid choice. Continuing with discovery scan setup..."
                        )
                elif choice == "3":
                    return
                else:
                    print(Fore.RED + "Invalid option.")
                    return

        # Remove the duplicate initialization

        # Get subnets from user
        while True:
            print(
                Fore.CYAN
                + f"\nCurrent subnets: {', '.join(selected_subnets) if selected_subnets
                                        else 'None'}"
            )
            if selected_subnets:
                print(Fore.GREEN + f"Total subnets: {len(selected_subnets)}")
            print(Fore.CYAN + "Options:")
            print("1. Add subnet")
            print("2. Remove subnet")
            print("3. Update subnet categorization")
            print("4. Proceed with current subnets")
            print("5. Cancel and return to previous menu")

            option = smart_input(
                Fore.YELLOW + "Choose an option: ", single_key=True
            ).strip()

            if option == "1":
                # Add subnet
                subnet_input = smart_input(
                    Fore.YELLOW + "Enter subnet (e.g., 192.168.1.0/24): "
                ).strip()

                if subnet_input.lower() == "back":
                    continue

                # Validate subnet
                try:
                    ipaddress.ip_network(subnet_input, strict=False)
                    if subnet_input not in selected_subnets:
                        # Check if this subnet was previously categorized
                        was_categorized, previous_mode = (
                            self.scan_manager.was_subnet_previously_categorized(
                                subnet_input
                            )
                        )

                        # Check for persistent categorization from JSON file
                        persistent_mode = (
                            self.scan_manager.get_persistent_categorization(
                                subnet_input
                            )
                        )

                        if was_categorized or persistent_mode:
                            # Use the most recent categorization
                            previous_mode = previous_mode or persistent_mode
                            print(
                                Fore.CYAN
                                + f"\n[!] Subnet {subnet_input} was previously "
                                f"categorized as '{previous_mode}'"
                            )
                            print("Would you like to:")
                            print("1. Preserve the previous categorization")
                            print("2. Choose a new categorization")

                            while True:
                                preserve_choice = smart_input(
                                    Fore.YELLOW + "Choose option: ", single_key=True
                                ).strip()
                                if preserve_choice == "1":
                                    # Preserve previous categorization
                                    if (
                                        subnet_input
                                        not in self.scan_manager.categorized_targets
                                    ):
                                        self.scan_manager.categorized_targets[
                                            subnet_input
                                        ] = {
                                            "targets": set(),
                                            "mode": previous_mode,
                                            "count": 0,
                                        }
                                    else:
                                        self.scan_manager.categorized_targets[
                                            subnet_input
                                        ]["mode"] = previous_mode

                                    # Remove from previously categorized since we're
                                    # using it again
                                    del (
                                        self.scan_manager.previously_categorized_subnets
                                    )[subnet_input]

                                    # Add to selected subnets
                                    selected_subnets.append(subnet_input)

                                    print(
                                        Fore.GREEN
                                        + f"[+] Added subnet: {subnet_input} with "
                                        f"preserved categorization: {previous_mode}"
                                    )
                                    break
                                elif preserve_choice == "2":
                                    # User wants to choose new categorization
                                    print(
                                        Fore.CYAN
                                        + f"\nCategorize subnet {subnet_input}:"
                                    )
                                    print("1. Internal")
                                    print("2. External")

                                    while True:
                                        try:
                                            mode_choice = smart_input(
                                                Fore.YELLOW + "Choose category: "
                                            ).strip()
                                            if mode_choice == "1":
                                                mode = "internal"
                                                break
                                            elif mode_choice == "2":
                                                mode = "external"
                                                break
                                            else:
                                                print(
                                                    Fore.RED
                                                    + "Invalid choice. Please enter "
                                                    "1 or 2."
                                                )
                                        except KeyboardInterrupt:
                                            handle_keyboard_interrupt()

                                    # Set the new categorization
                                    if (
                                        subnet_input
                                        not in self.scan_manager.categorized_targets
                                    ):
                                        self.scan_manager.categorized_targets[
                                            subnet_input
                                        ] = {"targets": set(), "mode": mode, "count": 0}
                                    else:
                                        self.scan_manager.categorized_targets[
                                            subnet_input
                                        ]["mode"] = mode

                                    # Save categorization to persistent storage
                                    self.scan_manager.save_categorization(
                                        subnet_input, mode
                                    )

                                    # Remove from previously categorized since we're
                                    # using it again
                                    del (
                                        self.scan_manager.previously_categorized_subnets
                                    )[subnet_input]

                                    # Add to selected subnets
                                    selected_subnets.append(subnet_input)

                                    print(
                                        Fore.GREEN
                                        + f"[+] Added subnet: {subnet_input} with new "
                                        f"categorization: {mode}"
                                    )
                                    break
                                else:
                                    print(
                                        Fore.RED
                                        + "Invalid choice. Please enter 1 or 2."
                                    )
                        else:
                            # New subnet, no previous categorization
                            selected_subnets.append(subnet_input)
                            print(Fore.GREEN + f"[+] Added subnet: {subnet_input}")
                    else:
                        print(Fore.YELLOW + f"[!] Subnet {subnet_input} already added.")
                except ValueError:
                    print(Fore.RED + f"Invalid subnet: {subnet_input}")
                    print(
                        Fore.YELLOW + "Please use CIDR notation (e.g., 192.168.1.0/24)"
                    )
                    continue

            elif option == "2":
                # Remove subnet
                if not selected_subnets:
                    print(Fore.YELLOW + "[!] No subnets to remove.")
                    continue

                print(Fore.CYAN + "Select subnet to remove:")
                for i, subnet in enumerate(selected_subnets, 1):
                    print(f"{i}. {subnet}")

                remove_choice = int(
                    smart_input(Fore.YELLOW + "Enter subnet number to remove: ").strip()
                )
                if 1 <= remove_choice <= len(selected_subnets):
                    removed = selected_subnets.pop(remove_choice - 1)

                    # Preserve categorization if this subnet was categorized
                    if (
                        removed in self.scan_manager.categorized_targets
                        and self.scan_manager.categorized_targets[removed]["mode"]
                        is not None
                    ):
                        mode = self.scan_manager.categorized_targets[removed]["mode"]
                        self.scan_manager.preserve_subnet_categorization(removed, mode)
                        print(
                            Fore.GREEN
                            + f"[+] Removed subnet: {removed} (categorization "
                            f"preserved: {mode})"
                        )
                    else:
                        print(Fore.GREEN + f"[+] Removed subnet: {removed}")
                else:
                    print(Fore.RED + "Invalid subnet number.")

            elif option == "3":
                # Update subnet categorization
                if not selected_subnets:
                    print(Fore.YELLOW + "[!] No subnets to update.")
                    continue

                print(Fore.CYAN + "Select subnet to update categorization:")
                for i, subnet in enumerate(selected_subnets, 1):
                    current_mode = "None"
                    if subnet in self.scan_manager.categorized_targets:
                        current_mode = (
                            self.scan_manager.categorized_targets[subnet]["mode"]
                            or "None"
                        )
                    print(f"{i}. {subnet} (Current: {current_mode})")

                update_choice = int(
                    smart_input(Fore.YELLOW + "Enter subnet number to update: ").strip()
                )
                if 1 <= update_choice <= len(selected_subnets):
                    subnet_to_update = selected_subnets[update_choice - 1]

                    print(
                        Fore.CYAN
                        + f"\nUpdate categorization for subnet {subnet_to_update}:"
                    )
                    print("1. Internal")
                    print("2. External")

                    while True:
                        mode_choice = smart_input(
                            Fore.YELLOW + "Choose new category: "
                        ).strip()
                        if mode_choice == "1":
                            new_mode = "internal"
                            break
                        elif mode_choice == "2":
                            new_mode = "external"
                            break
                        else:
                            print(Fore.RED + "Invalid choice. Please enter 1 or 2.")

                        # Update the categorization
                        if (
                            subnet_to_update
                            not in self.scan_manager.categorized_targets
                        ):
                            self.scan_manager.categorized_targets[subnet_to_update] = {
                                "targets": set(),
                                "mode": new_mode,
                                "count": 0,
                            }
                        else:
                            self.scan_manager.categorized_targets[subnet_to_update][
                                "mode"
                            ] = new_mode

                        # Save to persistent storage
                        self.scan_manager.save_categorization(
                            subnet_to_update, new_mode
                        )

                        print(
                            Fore.GREEN
                            + f"[+] Updated categorization for {subnet_to_update} "
                            f"to: {new_mode}"
                        )
                    else:
                        print(Fore.RED + "Invalid subnet number.")

            elif option == "4":
                # Proceed with current subnets
                if not selected_subnets:
                    print(
                        Fore.RED + "[!] No subnets selected. Please add subnets first."
                    )
                    continue

                print(
                    Fore.GREEN
                    + f"Proceeding with subnets: {', '.join(selected_subnets)}"
                )

                # Check if subnets are already categorized
                already_categorized = []
                needs_categorization = []

                for subnet in selected_subnets:
                    # Check if subnet is currently categorized
                    if (
                        subnet in self.scan_manager.categorized_targets
                        and self.scan_manager.categorized_targets[subnet]["mode"]
                        is not None
                    ):
                        already_categorized.append(subnet)
                    # Check if subnet was previously categorized
                    elif self.scan_manager.was_subnet_previously_categorized(subnet)[0]:
                        already_categorized.append(subnet)
                    else:
                        needs_categorization.append(subnet)

                # Only categorize subnets that haven't been categorized yet
                classified_subnets = []

                # Add already categorized subnets
                for subnet in already_categorized:
                    # Check if it's currently categorized
                    if (
                        subnet in self.scan_manager.categorized_targets
                        and self.scan_manager.categorized_targets[subnet]["mode"]
                        is not None
                    ):
                        mode = self.scan_manager.categorized_targets[subnet]["mode"]
                        classified_subnets.append((subnet, mode))
                        print(
                            Fore.GREEN + f"[+] {subnet} already categorized as {mode}"
                        )
                    # Check if it was previously categorized
                    elif self.scan_manager.was_subnet_previously_categorized(subnet)[0]:
                        was_categorized, previous_mode = (
                            self.scan_manager.was_subnet_previously_categorized(subnet)
                        )
                        classified_subnets.append((subnet, previous_mode))
                        print(
                            Fore.GREEN
                            + f"[+] {subnet} restored previous categorization: "
                            f"{previous_mode}"
                        )
                        # Remove from previously categorized since we're using it again
                        del self.scan_manager.previously_categorized_subnets[subnet]
                    else:
                        # This shouldn't happen, but just in case
                        needs_categorization.append(subnet)

                # Categorize uncategorized subnets
                for subnet in needs_categorization:
                    print(Fore.CYAN + f"\nCategorize subnet {subnet}:")
                    print("1. Internal")
                    print("2. External")

                    while True:
                        mode_choice = smart_input(
                            Fore.YELLOW + "Choose category: "
                        ).strip()
                        if mode_choice == "1":
                            mode = "internal"
                            break
                        elif mode_choice == "2":
                            mode = "external"
                            break
                        else:
                            print(Fore.RED + "Invalid choice. Please enter 1 or 2.")

                    classified_subnets.append((subnet, mode))
                    print(Fore.GREEN + f"[+] Classified {subnet} as {mode}")

                # Create subnet categorization dictionary
                subnet_categorization = {
                    subnet: mode for subnet, mode in classified_subnets
                }

                # Create and add discovery scan with subnet categorization
                discovery_scan = DiscoveryScan(selected_subnets, subnet_categorization)
                self.scan_manager.add_scan(discovery_scan)

                # Store the classification information for future use and save to
                # persistent storage
                for subnet, mode in classified_subnets:
                    if subnet not in self.scan_manager.categorized_targets:
                        self.scan_manager.categorized_targets[subnet] = {
                            "targets": set(),
                            "mode": mode,
                            "count": 0,
                        }
                    else:
                        self.scan_manager.categorized_targets[subnet]["mode"] = mode

                    # Save categorization to persistent storage
                    self.scan_manager.save_categorization(subnet, mode)

                break

            elif option == "4":
                # Proceed with current subnets
                if not selected_subnets:
                    print(
                        Fore.RED + "[!] No subnets selected. Please add subnets first."
                    )
                    continue

                print(
                    Fore.GREEN
                    + f"Proceeding with subnets: {', '.join(selected_subnets)}"
                )

                # Check if subnets are already categorized
                already_categorized = []
                needs_categorization = []

                for subnet in selected_subnets:
                    # Check if subnet is currently categorized
                    if (
                        subnet in self.scan_manager.categorized_targets
                        and self.scan_manager.categorized_targets[subnet]["mode"]
                        is not None
                    ):
                        already_categorized.append(subnet)
                    # Check if subnet was previously categorized
                    elif self.scan_manager.was_subnet_previously_categorized(subnet)[0]:
                        already_categorized.append(subnet)
                    else:
                        needs_categorization.append(subnet)

                # Only categorize subnets that haven't been categorized yet
                classified_subnets = []

                # Add already categorized subnets
                for subnet in already_categorized:
                    # Check if it's currently categorized
                    if (
                        subnet in self.scan_manager.categorized_targets
                        and self.scan_manager.categorized_targets[subnet]["mode"]
                        is not None
                    ):
                        mode = self.scan_manager.categorized_targets[subnet]["mode"]
                        classified_subnets.append((subnet, mode))
                        print(
                            Fore.GREEN + f"[+] {subnet} already categorized as {mode}"
                        )
                    # Check if it was previously categorized
                    elif self.scan_manager.was_subnet_previously_categorized(subnet)[0]:
                        was_categorized, previous_mode = (
                            self.scan_manager.was_subnet_previously_categorized(subnet)
                        )
                        classified_subnets.append((subnet, previous_mode))
                        print(
                            Fore.GREEN
                            + f"[+] {subnet} restored previous categorization: "
                            f"{previous_mode}"
                        )
                        # Remove from previously categorized since we're using it again
                        del self.scan_manager.previously_categorized_subnets[subnet]
                    else:
                        # This shouldn't happen, but just in case
                        needs_categorization.append(subnet)

                # Categorize uncategorized subnets
                for subnet in needs_categorization:
                    print(Fore.CYAN + f"\nCategorize subnet {subnet}:")
                    print("1. Internal")
                    print("2. External")

                    while True:
                        mode_choice = smart_input(
                            Fore.YELLOW + "Choose category: "
                        ).strip()
                        if mode_choice == "1":
                            mode = "internal"
                            break
                        elif mode_choice == "2":
                            mode = "external"
                            break
                        else:
                            print(Fore.RED + "Invalid choice. Please enter 1 or 2.")

                    classified_subnets.append((subnet, mode))
                    print(Fore.GREEN + f"[+] Classified {subnet} as {mode}")

                # Create subnet categorization dictionary
                subnet_categorization = {
                    subnet: mode for subnet, mode in classified_subnets
                }

                # Create and add discovery scan with subnet categorization
                discovery_scan = DiscoveryScan(selected_subnets, subnet_categorization)
                self.scan_manager.add_scan(discovery_scan)

                # Store the classification information for future use and save to
                # persistent storage
                for subnet, mode in classified_subnets:
                    if subnet not in self.scan_manager.categorized_targets:
                        self.scan_manager.categorized_targets[subnet] = {
                            "targets": set(),
                            "mode": mode,
                            "count": 0,
                        }
                    else:
                        self.scan_manager.categorized_targets[subnet]["mode"] = mode

                    # Save categorization to persistent storage
                    self.scan_manager.save_categorization(subnet, mode)

                break

            elif option == "5":
                # Cancel and return
                return
            else:
                print(Fore.RED + "Invalid option. Please enter 1-5.")

    def _categorize_existing_targets(self, targets: List[str]) -> List[str]:
        """Categorize existing targets by subnet.

        Ask user for mode classification.
        """
        print(Fore.CYAN + "\n=== Categorizing Existing Targets ===")

        # Group targets by /24 subnet
        subnet_targets = {}
        for target in targets:
            try:
                ip = ipaddress.ip_address(target)
                subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnet_str = str(subnet)

                if subnet_str not in subnet_targets:
                    subnet_targets[subnet_str] = []
                subnet_targets[subnet_str].append(target)
            except ValueError:
                continue

        categorized_subnets = []

        # Ask user to categorize each subnet
        for subnet, ips in subnet_targets.items():
            print(Fore.CYAN + f"\nSubnet {subnet} contains {len(ips)} targets:")
            for ip in ips[:5]:  # Show first 5 IPs
                print(f"  {ip}")
            if len(ips) > 5:
                print(f"  ... and {len(ips) - 5} more")

            # Initialize variables
            was_categorized = False
            previous_mode = None

            # Check if this subnet is already categorized in the scan manager
            if (
                subnet in self.scan_manager.categorized_targets
                and self.scan_manager.categorized_targets[subnet]["mode"] is not None
            ):
                # Subnet is already categorized, use existing categorization
                mode = self.scan_manager.categorized_targets[subnet]["mode"]
                print(Fore.GREEN + f"[+] Subnet {subnet} already categorized as {mode}")
                # Skip the rest of the categorization logic since it's already done
                categorized_subnets.append(subnet)
                continue
            else:
                # Check if this subnet was previously categorized
                was_categorized, previous_mode = (
                    self.scan_manager.was_subnet_previously_categorized(subnet)
                )

                # Check for persistent categorization from JSON file
                persistent_mode = self.scan_manager.get_persistent_categorization(
                    subnet
                )

                if was_categorized or persistent_mode is not None:
                    # Use the most recent categorization
                    previous_mode = previous_mode or persistent_mode
                    print(
                        Fore.CYAN + f"[!] This subnet was previously categorized as "
                        f"'{previous_mode}'"
                    )
                    print("Would you like to:")
                    print("1. Preserve the previous categorization")
                    print("2. Choose a new categorization")

                    while True:
                        preserve_choice = smart_input(
                            Fore.YELLOW + "Choose option: ", single_key=True
                        ).strip()
                        if preserve_choice == "1":
                            # Preserve previous categorization
                            mode = previous_mode
                            print(
                                Fore.GREEN
                                + f"[+] Preserving previous categorization: {mode}"
                            )
                            break
                        elif preserve_choice == "2":
                            # User wants to choose new categorization
                            print(Fore.CYAN + "Categorize this subnet:")
                            print("1. Internal")
                            print("2. External")

                            while True:
                                choice = smart_input(
                                    Fore.YELLOW + "Choose category: "
                                ).strip()
                                if choice == "1":
                                    mode = "internal"
                                    break
                                elif choice == "2":
                                    mode = "external"
                                    break
                                else:
                                    print(
                                        Fore.RED
                                        + "Invalid choice. Please enter 1 or 2."
                                    )
                            break
                        else:
                            print(Fore.RED + "Invalid choice. Please enter 1 or 2.")
                else:
                    # New subnet, no previous categorization
                    print(Fore.CYAN + "Categorize this subnet:")
                    print("1. Internal")
                    print("2. External")

                    while True:
                        try:
                            choice = smart_input(
                                Fore.YELLOW + "Choose category: "
                            ).strip()
                            if choice == "1":
                                mode = "internal"
                                break
                            elif choice == "2":
                                mode = "external"
                                break
                            else:
                                print(Fore.RED + "Invalid choice. Please enter 1 or 2.")
                        except KeyboardInterrupt:
                            handle_keyboard_interrupt()

            # Store in scan manager's categorized targets
            if subnet not in self.scan_manager.categorized_targets:
                self.scan_manager.categorized_targets[subnet] = {
                    "targets": set(ips),
                    "mode": mode,
                    "count": len(ips),
                }
            else:
                self.scan_manager.categorized_targets[subnet]["targets"].update(ips)
                self.scan_manager.categorized_targets[subnet]["mode"] = mode
                self.scan_manager.categorized_targets[subnet]["count"] = len(
                    self.scan_manager.categorized_targets[subnet]["targets"]
                )

            # Save categorization to persistent storage
            if mode is not None:
                self.scan_manager.save_categorization(subnet, mode)

            # Remove from previously categorized since we're using it again
            if was_categorized:
                del self.scan_manager.previously_categorized_subnets[subnet]

            categorized_subnets.append(subnet)

        return categorized_subnets

    def _categorize_existing_targets_from_scan_manager(self) -> None:
        """Categorize existing targets that are already loaded in the scan manager."""
        print(Fore.CYAN + "\n=== Categorizing Existing Targets ===")

        # Get subnets that need categorization
        uncategorized_subnets = [
            subnet
            for subnet, info in self.scan_manager.categorized_targets.items()
            if info["mode"] is None
        ]

        if not uncategorized_subnets:
            print(Fore.GREEN + "[+] All subnets are already categorized.")
            return

        # Ask user to categorize each uncategorized subnet
        for subnet in uncategorized_subnets:
            info = self.scan_manager.categorized_targets[subnet]
            print(Fore.CYAN + f"\nSubnet {subnet} contains {info['count']} targets:")

            # Show some sample targets
            sample_targets = list(info["targets"])[:5]
            for target in sample_targets:
                print(f"  {target}")
            if info["count"] > 5:
                print(f"  ... and {info['count'] - 5} more")

            print(Fore.CYAN + "Categorize this subnet:")
            print("1. Internal")
            print("2. External")

            while True:
                choice = smart_input(Fore.YELLOW + "Choose category: ").strip()
                if choice == "1":
                    mode = "internal"
                    break
                elif choice == "2":
                    mode = "external"
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please enter 1 or 2.")

            # Update the mode in the scan manager
            self.scan_manager.categorized_targets[subnet]["mode"] = mode

            # Save categorization to persistent storage
            self.scan_manager.save_categorization(subnet, mode)

            print(Fore.GREEN + f"[+] Categorized {subnet} as {mode}")

    def add_tcp_scan(self) -> None:
        """Add a TCP scan."""
        print(Fore.CYAN + "\n=== Add TCP Scan ===")

        # Check if targets are available
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            print(Fore.RED + "[!] No targets available. Run a discovery scan first.")
            return

        # Load and categorize targets
        if not self.scan_manager.categorized_targets:
            # Try to load existing targets and categorize them
            if self.scan_manager.load_existing_targets():
                print(
                    Fore.GREEN
                    + f"[+] Loaded {len(self.scan_manager.categorized_targets)} "
                    "subnets from targets.txt"
                )
            else:
                print(
                    Fore.RED + "[!] No valid targets found. Run a discovery scan first."
                )
                return

        # Check if targets need categorization - only if there are uncategorized subnets
        uncategorized_subnets = [
            subnet
            for subnet, info in self.scan_manager.categorized_targets.items()
            if info["mode"] is None
        ]

        if uncategorized_subnets:
            print(
                Fore.YELLOW
                + f"[!] Found {len(uncategorized_subnets)} uncategorized subnet(s). "
                "Categorizing..."
            )
            self._categorize_existing_targets_from_scan_manager()

        if not self.scan_manager.categorized_targets:
            print(Fore.RED + "[!] No valid targets found. Run a discovery scan first.")
            return

        # Show available subnets and let user choose
        print(Fore.CYAN + "\nAvailable subnets:")
        subnets = list(self.scan_manager.categorized_targets.keys())
        for i, subnet in enumerate(subnets, 1):
            info = self.scan_manager.categorized_targets[subnet]
            print(
                f"{i}. {subnet} ({info['count']} targets) - Mode: {info['mode'] or
                                                                   'Not set'}"
            )

        print(f"{len(subnets) + 1}. Return to Configure and Run Scans menu")

        # Let user select subnet
        while True:
            choice = smart_input(
                Fore.YELLOW + "Select subnet for TCP scan: ", single_key=True
            ).strip()
            try:
                index = int(choice) - 1
                if 0 <= index < len(subnets):
                    selected_subnet = subnets[index]
                    break
                elif index == len(subnets):
                    return  # Return to previous menu
                else:
                    print(Fore.RED + "Invalid subnet number.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

        # Get the mode from the categorized targets
        mode = self.scan_manager.categorized_targets[selected_subnet]["mode"]
        if mode is None:
            print(
                Fore.RED
                + "[!] Subnet mode not set. Please run discovery scan first to "
                "categorize subnets."
            )
            return

        # Ask for custom flags or default
        print(Fore.CYAN + "\nNmap flags options:")
        print("1. Use default flags")
        print("2. Use custom flags")

        # Show saved flag combinations if available
        saved_flags = get_saved_flag_combinations("tcp")
        if saved_flags:
            print("3. Use saved flag combination")
            print(Fore.CYAN + "\nSaved TCP flag combinations:")
            for i, (name, flags) in enumerate(saved_flags.items(), 1):
                print(f"  {i}. {name} ({flags})")

        while True:
            flag_choice = smart_input(
                Fore.YELLOW + "Choose option: ", single_key=True
            ).strip()
            if flag_choice == "1":
                nmap_flags = None  # Use default
                break
            elif flag_choice == "2":
                custom_flags = get_custom_flags_with_validation("tcp")
                if custom_flags:
                    nmap_flags = custom_flags
                    # Add to config for future use
                    if custom_flags not in self.config["nmap_flags_tcp"]["custom"]:
                        self.config["nmap_flags_tcp"]["custom"].append(custom_flags)
                        save_config(self.config)
                    # Prompt to save new flag combination
                    prompt_to_save_flags("tcp", custom_flags)
                    break
                else:
                    print(Fore.RED + "Custom flags input cancelled.")
            elif flag_choice == "3" and saved_flags:
                # Use saved flag combination
                flag_names = list(saved_flags.keys())
                print(Fore.CYAN + "\nSelect saved flag combination:")
                for i, name in enumerate(flag_names, 1):
                    print(f"{i}. {name}")

                while True:
                    choice = smart_input(
                        Fore.YELLOW + "Choose saved flags: ", single_key=True
                    ).strip()
                    try:
                        index = int(choice) - 1
                        if 0 <= index < len(flag_names):
                            selected_name = flag_names[index]
                            nmap_flags = saved_flags[selected_name]
                            print(
                                Fore.GREEN + f"[+] Using saved flags: {selected_name}"
                            )
                            break
                        else:
                            print(Fore.RED + "Invalid choice.")
                    except ValueError:
                        print(Fore.RED + "Please enter a valid number.")
                break
            else:
                print(Fore.RED + "Invalid choice. Please enter a valid option.")

        # Ask for port options
        print(Fore.CYAN + "\nPort options:")
        print("1. Full port scan (1-65535)")
        print("2. Enter port ranges (e.g., 80,443,8080-8090)")
        print("3. Enter individual ports (comma-separated)")

        while True:
            port_choice = smart_input(
                Fore.YELLOW + "Choose option: ", single_key=True
            ).strip()
            if port_choice == "1":
                ports = None  # Use default full scan
                break
            elif port_choice == "2":
                port_input = smart_input(Fore.YELLOW + "Enter port ranges: ").strip()
                if self._validate_port_input(port_input):
                    ports = port_input
                    break
                else:
                    print(
                        Fore.RED
                        + "Invalid port format. Use format like: 80,443,8080-8090"
                    )
            elif port_choice == "3":
                port_input = smart_input(
                    Fore.YELLOW + "Enter individual ports: "
                ).strip()
                if self._validate_port_input(port_input):
                    ports = port_input
                    break
                else:
                    print(
                        Fore.RED + "Invalid port format. Use format like: 80,443,8080"
                    )
            else:
                print(Fore.RED + "Invalid choice. Please enter 1, 2, or 3.")

        # Create and add TCP scan
        tcp_scan = TCPScan(
            mode=mode, nmap_flags=nmap_flags, ports=ports, subnet=selected_subnet
        )
        self.scan_manager.add_scan(tcp_scan)

    def add_udp_scan(self) -> None:
        """Add a UDP scan."""
        print(Fore.CYAN + "\n=== Add UDP Scan ===")

        # Check if targets are available
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")
        if not os.path.exists(targets_file):
            print(Fore.RED + "[!] No targets available. Run a discovery scan first.")
            return

        # Load and categorize targets
        if not self.scan_manager.categorized_targets:
            # Try to load existing targets and categorize them
            if self.scan_manager.load_existing_targets():
                print(
                    Fore.GREEN
                    + f"[+] Loaded {len(self.scan_manager.categorized_targets)} "
                    "subnets from targets.txt"
                )
            else:
                print(
                    Fore.RED + "[!] No valid targets found. Run a discovery scan first."
                )
                return

        # Check if targets need categorization - only if there are uncategorized subnets
        uncategorized_subnets = [
            subnet
            for subnet, info in self.scan_manager.categorized_targets.items()
            if info["mode"] is None
        ]

        if uncategorized_subnets:
            print(
                Fore.YELLOW
                + f"[!] Found {len(uncategorized_subnets)} uncategorized subnet(s). "
                "Categorizing..."
            )
            self._categorize_existing_targets_from_scan_manager()

        if not self.scan_manager.categorized_targets:
            print(Fore.RED + "[!] No valid targets found. Run a discovery scan first.")
            return

        # Show available subnets and let user choose
        print(Fore.CYAN + "\nAvailable subnets:")
        subnets = list(self.scan_manager.categorized_targets.keys())
        for i, subnet in enumerate(subnets, 1):
            info = self.scan_manager.categorized_targets[subnet]
            print(
                f"{i}. {subnet} ({info['count']} targets) - Mode: {info['mode'] or
                                                                   'Not set'}"
            )

        print(f"{len(subnets) + 1}. Return to Configure and Run Scans menu")

        # Let user select subnet
        while True:
            choice = smart_input(
                Fore.YELLOW + "Select subnet for UDP scan: ", single_key=True
            ).strip()
            try:
                index = int(choice) - 1
                if 0 <= index < len(subnets):
                    selected_subnet = subnets[index]
                    break
                elif index == len(subnets):
                    return  # Return to previous menu
                else:
                    print(Fore.RED + "Invalid subnet number.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

        # Get the mode from the categorized targets
        mode = self.scan_manager.categorized_targets[selected_subnet]["mode"]
        if mode is None:
            print(
                Fore.RED + "[!] Subnet mode not set. Please run discovery scan first "
                "to categorize subnets."
            )
            return

        # Ask for custom flags or default
        print(Fore.CYAN + "\nNmap flags options:")
        print("1. Use default flags")
        print("2. Use custom flags")

        # Show saved flag combinations if available
        saved_flags = get_saved_flag_combinations("udp")
        if saved_flags:
            print("3. Use saved flag combination")
            print(Fore.CYAN + "\nSaved UDP flag combinations:")
            for i, (name, flags) in enumerate(saved_flags.items(), 1):
                print(f"  {i}. {name} ({flags})")

        while True:
            flag_choice = smart_input(
                Fore.YELLOW + "Choose option: ", single_key=True
            ).strip()
            if flag_choice == "1":
                nmap_flags = None  # Use default
                break
            elif flag_choice == "2":
                custom_flags = get_custom_flags_with_validation("udp")
                if custom_flags:
                    nmap_flags = custom_flags
                    # Add to config for future use
                    if custom_flags not in self.config["nmap_flags_udp"]["custom"]:
                        self.config["nmap_flags_udp"]["custom"].append(custom_flags)
                        save_config(self.config)
                    # Prompt to save new flag combination
                    prompt_to_save_flags("udp", custom_flags)
                    break
                else:
                    print(Fore.RED + "Custom flags input cancelled.")
            elif flag_choice == "3" and saved_flags:
                # Use saved flag combination
                flag_names = list(saved_flags.keys())
                print(Fore.CYAN + "\nSelect saved flag combination:")
                for i, name in enumerate(flag_names, 1):
                    print(f"{i}. {name}")

                while True:
                    choice = smart_input(
                        Fore.YELLOW + "Choose saved flags: ", single_key=True
                    ).strip()
                    try:
                        index = int(choice) - 1
                        if 0 <= index < len(flag_names):
                            selected_name = flag_names[index]
                            nmap_flags = saved_flags[selected_name]
                            print(
                                Fore.GREEN + f"[+] Using saved flags: {selected_name}"
                            )
                            break
                        else:
                            print(Fore.RED + "Invalid choice.")
                    except ValueError:
                        print(Fore.RED + "Please enter a valid number.")
                break
            else:
                print(Fore.RED + "Invalid choice. Please enter a valid option.")

        # Ask for port options
        print(Fore.CYAN + "\nPort options:")
        print("1. Full port scan (1-65535)")
        print("2. Enter port ranges (e.g., 53,161,500-510)")
        print("3. Enter individual ports (comma-separated)")

        while True:
            port_choice = smart_input(
                Fore.YELLOW + "Choose option: ", single_key=True
            ).strip()
            if port_choice == "1":
                ports = None  # Use default full scan
                break
            elif port_choice == "2":
                port_input = smart_input(Fore.YELLOW + "Enter port ranges: ").strip()
                if self._validate_port_input(port_input):
                    ports = port_input
                    break
                else:
                    print(
                        Fore.RED
                        + "Invalid port format. Use format like: 53,161,500-510"
                    )
            elif port_choice == "3":
                port_input = smart_input(
                    Fore.YELLOW + "Enter individual ports: "
                ).strip()
                if self._validate_port_input(port_input):
                    ports = port_input
                    break
                else:
                    print(Fore.RED + "Invalid port format. Use format like: 53,161,500")
            else:
                print(Fore.RED + "Invalid choice. Please enter 1, 2, or 3.")

        # Create and add UDP scan
        udp_scan = UDPScan(
            mode=mode, nmap_flags=nmap_flags, ports=ports, subnet=selected_subnet
        )
        self.scan_manager.add_scan(udp_scan)

    def _validate_port_input(self, port_input: str) -> bool:
        """Validate port input format for nmap."""
        try:
            parts = port_input.split(",")
            for part in parts:
                part = part.strip()
                if "-" in part:
                    # Port range (e.g., 80-90)
                    start, end = part.split("-")
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    if not (
                        1 <= start_port <= 65535
                        and 1 <= end_port <= 65535
                        and start_port <= end_port
                    ):
                        return False
                else:
                    # Single port
                    port = int(part.strip())
                    if not (1 <= port <= 65535):
                        return False
            return True
        except (ValueError, AttributeError):
            return False

    def run_scans(self) -> Optional[str]:
        """Run all configured scans."""
        if not self.scan_manager.scans:
            print(Fore.RED + "[!] No scans configured. Add scans first.")
            return

        print(Fore.CYAN + "\n=== Running Scans ===")
        self.scan_manager.execute_all_scans()

        # Return to main menu after scans complete
        print(Fore.CYAN + "\n[!] Returning to main menu...")
        return "main_menu"

    def remove_scans(self) -> None:
        """Remove scans."""
        if not self.scan_manager.scans:
            print(Fore.YELLOW + "[!] No scans to remove.")
            return

        self.scan_manager.list_scans()

        while True:
            choice = smart_input(
                Fore.YELLOW + "Enter scan number to remove (or 'back'): "
            ).strip()

            if choice.lower() == "back":
                return

            try:
                index = int(choice) - 1
                if self.scan_manager.remove_scan(index):
                    break
                else:
                    print(Fore.RED + "Invalid scan number.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

    def view_configuration(self) -> None:
        """View current configuration."""
        print(Fore.CYAN + "\n=== Current Configuration ===")
        print(json.dumps(self.config, indent=2))
        smart_input(Fore.YELLOW + "Press Enter to continue...", allow_empty=True)

    def update_configuration(self) -> None:
        """Update configuration settings."""
        print(Fore.CYAN + "\n=== Update Configuration ===")
        print("1. Update Thread Count")
        print("2. Toggle JSON Output")
        print("3. Update Output Directory")
        print("4. Back to Main Menu")

        choice = smart_input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == "1":
            self._update_thread_count()
        elif choice == "2":
            self._toggle_json_output()
        elif choice == "3":
            self._update_output_directory()
        elif choice == "4":
            return
        else:
            print(Fore.RED + "Invalid option.")

    def _update_thread_count(self) -> None:
        """Update thread count."""
        print(Fore.CYAN + f"\nCurrent thread count: {self.config['thread_count']}")
        while True:
            try:
                new_count = int(
                    smart_input(
                        Fore.YELLOW + "Enter new thread count (1-100): "
                    ).strip()
                )
                if 1 <= new_count <= 100:
                    self.config["thread_count"] = new_count
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Thread count updated to {new_count}")
                    break
                else:
                    print(Fore.RED + "Please enter a number between 1 and 100.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

    def _toggle_json_output(self) -> None:
        """Toggle JSON output."""
        current = self.config["enable_json"]
        self.config["enable_json"] = not current
        save_config(self.config)
        status = "enabled" if self.config["enable_json"] else "disabled"
        print(Fore.GREEN + f"[+] JSON output {status}")

    def _update_output_directory(self) -> None:
        """Update output directory."""
        print(
            Fore.CYAN + f"\nCurrent output directory: {self.config['output_directory']}"
        )
        new_dir = smart_input(Fore.YELLOW + "Enter new output directory: ").strip()

        if new_dir:
            self.config["output_directory"] = new_dir
            save_config(self.config)
            print(Fore.GREEN + f"[+] Output directory updated to {new_dir}")

    def advanced_configuration_management(self) -> None:
        """Advanced configuration management with comprehensive options."""
        while True:
            print(Fore.CYAN + "\n=== Advanced Configuration Management ===")
            print("1. Manage TCP Scan Configuration")
            print("2. Manage UDP Scan Configuration")
            print("3. Manage Port Settings")
            print("4. Manage Thread and Output Settings")
            print("5. View Current Configuration")
            print("6. Reset to Defaults")
            print("7. Back to Main Menu")

            choice = smart_input(
                Fore.YELLOW + "Choose an option: ", single_key=True
            ).strip()

            if choice == "1":
                self._manage_tcp_config()
            elif choice == "2":
                self._manage_udp_config()
            elif choice == "3":
                self._manage_port_settings()
            elif choice == "4":
                self._manage_basic_settings()
            elif choice == "5":
                self.view_configuration()
            elif choice == "6":
                self._reset_to_defaults()
            elif choice == "7":
                break
            else:
                print(Fore.RED + "Invalid option.")

    def _manage_tcp_config(self) -> None:
        """Manage TCP scan configuration."""
        print(Fore.CYAN + "\n=== TCP Scan Configuration ===")
        print("1. View current TCP flags")
        print("2. Add custom TCP flags")
        print("3. Remove custom TCP flags")
        print("4. Reset TCP flags to default")
        print("5. Back")

        choice = smart_input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == "1":
            print(Fore.CYAN + "\nCurrent TCP Configuration:")
            print(
                f"Default flags: {' '.join(self.config['nmap_flags_tcp']['default'])}"
            )
            if self.config["nmap_flags_tcp"]["custom"]:
                print("Custom flags:")
                for i, flags in enumerate(self.config["nmap_flags_tcp"]["custom"], 1):
                    print(f"  {i}. {flags}")
            else:
                print("No custom flags configured.")

        elif choice == "2":
            custom_flags = smart_input(Fore.YELLOW + "Enter custom TCP flags: ").strip()
            if custom_flags:
                if custom_flags not in self.config["nmap_flags_tcp"]["custom"]:
                    self.config["nmap_flags_tcp"]["custom"].append(custom_flags)
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Custom TCP flags added: {custom_flags}")
                else:
                    print(Fore.YELLOW + "[!] These flags are already configured.")
            else:
                print(Fore.RED + "Custom flags cannot be empty.")

        elif choice == "3":
            if not self.config["nmap_flags_tcp"]["custom"]:
                print(Fore.YELLOW + "[!] No custom TCP flags to remove.")
                return

            print(Fore.CYAN + "Select flags to remove:")
            for i, flags in enumerate(self.config["nmap_flags_tcp"]["custom"], 1):
                print(f"{i}. {flags}")

            try:
                index = int(smart_input(Fore.YELLOW + "Enter number: ").strip()) - 1
                if 0 <= index < len(self.config["nmap_flags_tcp"]["custom"]):
                    removed = self.config["nmap_flags_tcp"]["custom"].pop(index)
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Removed: {removed}")
                else:
                    print(Fore.RED + "Invalid number.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

        elif choice == "4":
            self.config["nmap_flags_tcp"]["custom"] = []
            save_config(self.config)
            print(Fore.GREEN + "[+] TCP flags reset to default.")

    def _manage_udp_config(self) -> None:
        """Manage UDP scan configuration."""
        print(Fore.CYAN + "\n=== UDP Scan Configuration ===")
        print("1. View current UDP flags")
        print("2. Add custom UDP flags")
        print("3. Remove custom UDP flags")
        print("4. Reset UDP flags to default")
        print("5. Back")

        choice = smart_input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == "1":
            print(Fore.CYAN + "\nCurrent UDP Configuration:")
            print(
                f"Default flags: {' '.join(self.config['nmap_flags_udp']['default'])}"
            )
            if self.config["nmap_flags_udp"]["custom"]:
                print("Custom flags:")
                for i, flags in enumerate(self.config["nmap_flags_udp"]["custom"], 1):
                    print(f"  {i}. {flags}")
            else:
                print("No custom flags configured.")

        elif choice == "2":
            custom_flags = smart_input(Fore.YELLOW + "Enter custom UDP flags: ").strip()
            if custom_flags:
                if custom_flags not in self.config["nmap_flags_udp"]["custom"]:
                    self.config["nmap_flags_udp"]["custom"].append(custom_flags)
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Custom UDP flags added: {custom_flags}")
                else:
                    print(Fore.YELLOW + "[!] These flags are already configured.")
            else:
                print(Fore.RED + "Custom flags cannot be empty.")

        elif choice == "3":
            if not self.config["nmap_flags_udp"]["custom"]:
                print(Fore.YELLOW + "[!] No custom UDP flags to remove.")
                return

            print(Fore.CYAN + "Select flags to remove:")
            for i, flags in enumerate(self.config["nmap_flags_udp"]["custom"], 1):
                print(f"{i}. {flags}")

            try:
                index = int(smart_input(Fore.YELLOW + "Enter number: ").strip()) - 1
                if 0 <= index < len(self.config["nmap_flags_udp"]["custom"]):
                    save_config(self.config)
                    print(Fore.GREEN + "[+] Removed: {removed}")
                else:
                    print(Fore.RED + "Invalid number.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

        elif choice == "4":
            self.config["nmap_flags_udp"]["custom"] = []
            save_config(self.config)
            print(Fore.GREEN + "[+] UDP flags reset to default.")

    def _manage_port_settings(self) -> None:
        """Manage port configuration settings."""
        print(Fore.CYAN + "\n=== Port Settings ===")
        print("1. View current port settings")
        print("2. Update TCP full scan ports")
        print("3. Update UDP full scan ports")
        print("4. Add custom TCP ports")
        print("5. Add custom UDP ports")
        print("6. Remove custom ports")
        print("7. Back")

        choice = smart_input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == "1":
            print(Fore.CYAN + "\nCurrent Port Settings:")
            print(f"TCP full scan: {self.config['tcp_ports_full_scan']}")
            print(f"UDP full scan: {self.config['udp_ports_full_scan']}")
            print(f"Custom TCP ports: {self.config['tcp_ports']}")
            print(f"Custom UDP ports: {self.config['udp_ports']}")

        elif choice == "2":
            new_ports = smart_input(
                Fore.YELLOW + "Enter new TCP full scan ports (e.g., 1-1000): "
            ).strip()
            if self._validate_port_input(new_ports):
                self.config["tcp_ports_full_scan"] = new_ports
                save_config(self.config)
                print(Fore.GREEN + f"[+] TCP full scan ports updated to: {new_ports}")
            else:
                print(Fore.RED + "Invalid port format.")

        elif choice == "3":
            new_ports = smart_input(
                Fore.YELLOW + "Enter new UDP full scan ports (e.g., 1-1000): "
            ).strip()
            if self._validate_port_input(new_ports):
                self.config["udp_ports_full_scan"] = new_ports
                save_config(self.config)
                print(Fore.GREEN + f"[+] UDP full scan ports updated to: {new_ports}")
            else:
                print(Fore.RED + "Invalid port format.")

        elif choice == "4":
            new_ports = smart_input(
                Fore.YELLOW + "Enter custom TCP ports (comma-separated): "
            ).strip()
            if self._validate_port_input(new_ports):
                if new_ports not in self.config["tcp_ports"]:
                    self.config["tcp_ports"].append(new_ports)
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Custom TCP ports added: {new_ports}")
                else:
                    print(Fore.YELLOW + "[!] These ports are already configured.")
            else:
                print(Fore.RED + "Invalid port format.")

        elif choice == "5":
            new_ports = smart_input(
                Fore.YELLOW + "Enter custom UDP ports (comma-separated): "
            ).strip()
            if self._validate_port_input(new_ports):
                if new_ports not in self.config["udp_ports"]:
                    self.config["udp_ports"].append(new_ports)
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Custom UDP ports added: {new_ports}")
                else:
                    print(Fore.RED + "Invalid port format.")

        elif choice == "6":
            print(Fore.CYAN + "Select ports to remove:")
            all_ports = self.config["tcp_ports"] + self.config["udp_ports"]
            if not all_ports:
                print(Fore.YELLOW + "[!] No custom ports to remove.")
                return

            for i, ports in enumerate(all_ports, 1):
                print(f"{i}. {ports}")

            try:
                index = int(smart_input(Fore.YELLOW + "Enter number: ").strip()) - 1
                if 0 <= index < len(all_ports):
                    removed = all_ports.pop(index)
                    if removed in self.config["tcp_ports"]:
                        self.config["tcp_ports"].remove(removed)
                    if removed in self.config["udp_ports"]:
                        self.config["udp_ports"].remove(removed)
                    save_config(self.config)
                    print(Fore.GREEN + f"[+] Removed: {removed}")
                else:
                    print(Fore.RED + "Invalid number.")
            except ValueError:
                print(Fore.RED + "Please enter a valid number.")

    def _manage_basic_settings(self) -> None:
        """Manage basic configuration settings."""
        print(Fore.CYAN + "\n=== Basic Settings ===")
        print("1. Update thread count")
        print("2. Toggle JSON output")
        print("3. Update output directory")
        print("4. Back")

        choice = smart_input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == "1":
            self._update_thread_count()
        elif choice == "2":
            self._toggle_json_output()
        elif choice == "3":
            self._update_output_directory()
        elif choice == "4":
            return
        else:
            print(Fore.RED + "Invalid option.")

    def _reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        print(Fore.CYAN + "\n=== Reset to Defaults ===")
        print("This will reset all configuration to default values.")
        confirm = smart_input(Fore.YELLOW + "Are you sure? (y/n): ").strip().lower()

        if confirm in ("y", "yes"):
            self.config = DEFAULT_CONFIG.copy()
            save_config(self.config)
            print(Fore.GREEN + "[+] Configuration reset to defaults.")
        else:
            print(Fore.YELLOW + "Reset cancelled.")

    def flag_management(self) -> None:
        """Manage saved flag combinations."""
        while True:
            print(Fore.CYAN + "\n=== Flag Management ===")
            print("1. Set flags file path")
            print("2. View saved flag combinations")
            print("3. Clear all saved flags")
            print("4. Back to Main Menu")

            choice = smart_input(
                Fore.YELLOW + "Choose an option: ", single_key=True
            ).strip()

            if choice == "1":
                self._set_flags_file_path()
            elif choice == "2":
                self._view_saved_flags()
            elif choice == "3":
                self._clear_saved_flags()
            elif choice == "4":
                break
            else:
                print(Fore.RED + "Invalid option. Try again.")

    def _set_flags_file_path(self) -> None:
        """Set the path for the flags file."""
        print(Fore.CYAN + "\n=== Set Flags File Path ===")

        current_path = get_flags_file_path()
        if current_path:
            print(Fore.YELLOW + f"Current path: {current_path}")

        new_path = smart_input(Fore.YELLOW + "Enter path for flags file: ").strip()
        if new_path:
            set_flags_file_path(new_path)
        else:
            print(Fore.RED + "Path cannot be empty.")

    def _view_saved_flags(self) -> None:
        """View all saved flag combinations."""
        print(Fore.CYAN + "\n=== Saved Flag Combinations ===")

        flags_file = get_flags_file_path()
        if not flags_file:
            print(Fore.RED + "[!] No flags file path set. Use option 1 to set a path.")
            return

        if not os.path.exists(flags_file):
            print(Fore.RED + "[!] Flags file does not exist.")
            return

        flags_data = load_saved_flags()
        if not flags_data:
            print(Fore.YELLOW + "[!] No saved flag combinations found.")
            return

        for scan_type, combinations in flags_data.items():
            print(Fore.CYAN + f"\n{scan_type.upper()} Flags:")
            for name, flags in combinations.items():
                print(f"  • {name}: {flags}")

    def _clear_saved_flags(self) -> None:
        """Clear all saved flag combinations."""
        print(Fore.CYAN + "\n=== Clear Saved Flags ===")
        print(
            "This will remove all saved flag combinations and unset the "
            "environment variable."
        )

        confirm = smart_input(
            Fore.YELLOW + "Are you sure? (y/n): ", single_key=True
        ).lower()
        if confirm == "y":
            flags_file = get_flags_file_path()
            if flags_file and os.path.exists(flags_file):
                try:
                    os.remove(flags_file)
                    print(Fore.GREEN + "[+] Flags file removed.")
                except OSError as e:
                    print(Fore.RED + f"[!] Error removing flags file: {e}")

            unset_flags_file_path()
        else:
            print(Fore.YELLOW + "Clear cancelled.")

    def add_ips_manually(self) -> None:
        """Add IPs manually to targets.txt without discovery scan."""
        print(Fore.CYAN + "\n=== Add IPs Manually ===")

        # Display current subnets and IPs
        self._display_current_subnets_and_ips()

        # Get comma-separated list of IPs
        while True:
            ip_input = smart_input(
                Fore.YELLOW
                + "Enter comma-separated list of IPs (e.g., 192.168.1.1,10.0.0.1): "
            ).strip()
            if not ip_input:
                print(Fore.RED + "IP list cannot be empty.")
                continue

            # Parse and validate IPs
            ip_list = [ip.strip() for ip in ip_input.split(",")]
            valid_ips = []
            invalid_ips = []

            for ip in ip_list:
                try:
                    ipaddress.ip_address(ip)
                    valid_ips.append(ip)
                except ValueError:
                    invalid_ips.append(ip)

            if invalid_ips:
                print(Fore.RED + f"Invalid IPs found: {', '.join(invalid_ips)}")
                print(Fore.YELLOW + "Please correct the invalid IPs and try again.")
                continue

            if not valid_ips:
                print(Fore.RED + "No valid IPs provided.")
                continue

            break

        # Categorize each IP as internal or external
        print(
            Fore.CYAN
            + f"\nCategorizing {len(valid_ips)} IP(s) as internal or external:"
        )

        for ip in valid_ips:
            while True:
                print(Fore.CYAN + f"\nIP: {ip}")
                print("1. Internal")
                print("2. External")

                choice = smart_input(
                    Fore.YELLOW + "Choose category: ", single_key=True
                ).strip()

                if choice == "1":
                    mode = "internal"
                    break
                elif choice == "2":
                    mode = "external"
                    break
                else:
                    print(Fore.RED + "Please enter 1 or 2.")

            # Add IP to categorized targets
            self._add_ip_to_categorized_targets(ip, mode)
            print(Fore.GREEN + f"[+] Added {ip} as {mode}")

        # Save updated targets to file
        self._save_targets_to_file()
        print(
            Fore.GREEN
            + f"\n[+] Successfully added {len(valid_ips)} IP(s) to targets.txt"
        )

    def _display_current_subnets_and_ips(self) -> None:
        """Display current subnets and their IPs."""
        print(Fore.CYAN + "\n=== Current Subnets and IPs ===")

        if not self.scan_manager.categorized_targets:
            print(Fore.YELLOW + "No subnets or IPs currently configured.")
            return

        for subnet, info in self.scan_manager.categorized_targets.items():
            print(Fore.CYAN + f"\nSubnet: {subnet}")
            print(f"  Mode: {info['mode'] or 'Not set'}")
            print(f"  IP Count: {info['count']}")
            if info["targets"]:
                ip_list = sorted(list(info["targets"]))
                print(f"  IPs: {', '.join(ip_list)}")

    def _add_ip_to_categorized_targets(self, ip: str, mode: str) -> None:
        """Add an IP to the categorized targets."""
        # Determine subnet for the IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                # For IPv4, use /24 subnet
                subnet = f"{ip}/24"
                # Convert to network address
                network = ipaddress.ip_network(subnet, strict=False)
                subnet = str(network)
            else:
                # For IPv6, use /64 subnet
                subnet = f"{ip}/64"
                network = ipaddress.ip_network(subnet, strict=False)
                subnet = str(network)
        except ValueError:
            print(Fore.RED + f"[!] Error processing IP {ip}")
            return

        # Add to categorized targets
        if subnet not in self.scan_manager.categorized_targets:
            self.scan_manager.categorized_targets[subnet] = {
                "targets": set(),
                "mode": mode,
                "count": 0,
            }

        # Add IP to the subnet
        self.scan_manager.categorized_targets[subnet]["targets"].add(ip)
        self.scan_manager.categorized_targets[subnet]["count"] = len(
            self.scan_manager.categorized_targets[subnet]["targets"]
        )

        # Update mode if not set or if different
        if self.scan_manager.categorized_targets[subnet]["mode"] is None:
            self.scan_manager.categorized_targets[subnet]["mode"] = mode

    def _save_targets_to_file(self) -> None:
        """Save all targets to targets.txt file."""
        targets_file = os.path.join(self.config["output_directory"], "targets.txt")

        # Collect all IPs from all subnets
        all_ips = set()
        for info in self.scan_manager.categorized_targets.values():
            all_ips.update(info["targets"])

        # Write to file
        try:
            with open(targets_file, "w") as f:
                for ip in sorted(all_ips):
                    f.write(f"{ip}\n")
        except IOError as e:
            print(Fore.RED + f"[!] Error saving targets file: {e}")


def main():
    """Execute main program function."""
    try:
        # Ensure output directory exists
        config = load_config()
        os.makedirs(config["output_directory"], exist_ok=True)

        # Start the user interface
        ui = UserInterface()
        ui.main_menu()
    except KeyboardInterrupt:
        handle_keyboard_interrupt()
    except Exception as e:
        print(Fore.RED + f"[!] An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
