#!/usr/bin/env python3
"""Nmap flag validation module.

Contains comprehensive lists of valid nmap flags categorized by scan type compatibility.
"""

# TCP-specific scan flags (incompatible with UDP)
TCP_ONLY_FLAGS = {
    # TCP scan techniques
    "-sS",  # TCP SYN scan
    "-sT",  # TCP Connect scan
    "-sA",  # TCP ACK scan
    "-sW",  # TCP Window scan
    "-sM",  # TCP Maimon scan
    "-sN",  # TCP Null scan
    "-sF",  # TCP FIN scan
    "-sX",  # TCP Xmas scan
    "--scanflags",  # Customize TCP scan flags
    "-sI",  # Idle scan
    "-b",  # FTP bounce scan
}

# UDP-specific scan flags (incompatible with TCP)
UDP_ONLY_FLAGS = {
    "-sU",  # UDP scan
}

# SCTP-specific scan flags
SCTP_ONLY_FLAGS = {
    "-sY",  # SCTP INIT scan
    "-sZ",  # SCTP COOKIE-ECHO scan
}

# IP protocol scan flags
IP_PROTOCOL_FLAGS = {
    "-sO",  # IP protocol scan
}

# Flags that work with both TCP and UDP
UNIVERSAL_FLAGS = {
    # Host discovery
    "-sL",  # List scan
    "-sn",  # Ping scan
    "-Pn",  # Skip host discovery
    "-PS",  # TCP SYN discovery
    "-PA",  # TCP ACK discovery
    "-PU",  # UDP discovery
    "-PY",  # SCTP discovery
    "-PE",  # ICMP echo discovery
    "-PP",  # ICMP timestamp discovery
    "-PM",  # ICMP netmask discovery
    "-PO",  # IP protocol ping
    "-n",  # Never do DNS resolution
    "-R",  # Always resolve DNS
    "--dns-servers",
    "--system-dns",
    "--traceroute",
    # Port specification
    "-p",  # Port ranges
    "--exclude-ports",
    "-F",  # Fast mode
    "-r",  # Sequential port scan
    "--top-ports",
    "--port-ratio",
    # Service/version detection
    "-sV",  # Service version detection
    "--version-intensity",
    "--version-light",
    "--version-all",
    "--version-trace",
    # Script scanning
    "-sC",  # Default scripts
    "--script",
    "--script-args",
    "--script-args-file",
    "--script-trace",
    "--script-updatedb",
    "--script-help",
    # OS detection
    "-O",  # OS detection
    "--osscan-limit",
    "--osscan-guess",
    # Timing and performance
    "-T0",
    "-T1",
    "-T2",
    "-T3",
    "-T4",
    "-T5",  # Timing templates
    "--min-hostgroup",
    "--max-hostgroup",
    "--min-parallelism",
    "--max-parallelism",
    "--min-rtt-timeout",
    "--max-rtt-timeout",
    "--initial-rtt-timeout",
    "--max-retries",
    "--host-timeout",
    "--scan-delay",
    "--max-scan-delay",
    "--min-rate",
    "--max-rate",
    # Firewall/IDS evasion and spoofing
    "-f",  # Fragment packets
    "--mtu",
    "-D",  # Decoy scan
    "-S",  # Spoof source address
    "-e",  # Use specified interface
    "-g",  # Use given source port
    "--source-port",
    "--proxies",
    "--data",
    "--data-string",
    "--data-length",
    "--ip-options",
    "--ttl",
    "--spoof-mac",
    "--badsum",
    # Output
    "-oN",  # Normal output
    "-oX",  # XML output
    "-oS",  # Script kiddie output
    "-oG",  # Grepable output
    "-oA",  # All formats output
    "-v",  # Verbose
    "-d",  # Debug
    "--reason",
    "--open",
    "--packet-trace",
    "--iflist",
    "--append-output",
    "--resume",
    "--noninteractive",
    "--stylesheet",
    "--webxml",
    "--no-stylesheet",
    # Misc
    "-6",  # IPv6
    "-A",  # Aggressive scan
    "--datadir",
    "--send-eth",
    "--send-ip",
    "--privileged",
    "--unprivileged",
    "-V",  # Version
    "-h",  # Help
    # Target specification
    "-iL",  # Input from file
    "-iR",  # Random targets
    "--exclude",
    "--excludefile",
}

# All valid flags combined
ALL_VALID_FLAGS = (
    TCP_ONLY_FLAGS
    | UDP_ONLY_FLAGS
    | SCTP_ONLY_FLAGS
    | IP_PROTOCOL_FLAGS
    | UNIVERSAL_FLAGS
)


def validate_nmap_flags(flags_list, scan_type="tcp"):
    """
    Validate a list of nmap flags for the specified scan type.

    Args:
        flags_list: List of flag strings to validate
        scan_type: 'tcp' or 'udp'

    Returns:
        tuple: (valid_flags, invalid_flags, warnings)
    """
    valid_flags = []
    invalid_flags = []
    warnings = []

    for flag in flags_list:
        flag = flag.strip()
        if not flag:
            continue

        # Check if flag is valid
        if flag not in ALL_VALID_FLAGS:
            invalid_flags.append(flag)
            continue

        # Check compatibility with scan type
        if scan_type.lower() == "tcp":
            if flag in UDP_ONLY_FLAGS:
                warnings.append(
                    f"Flag '{flag}' is UDP-only and incompatible with TCP scans"
                )
                invalid_flags.append(flag)
            elif flag in SCTP_ONLY_FLAGS:
                warnings.append(
                    f"Flag '{flag}' is SCTP-only and incompatible with TCP scans"
                )
                invalid_flags.append(flag)
            elif flag in IP_PROTOCOL_FLAGS:
                warnings.append(
                    f"Flag '{flag}' is IP protocol-only and incompatible with TCP scans"
                )
                invalid_flags.append(flag)
            else:
                valid_flags.append(flag)

        elif scan_type.lower() == "udp":
            if flag in TCP_ONLY_FLAGS:
                warnings.append(
                    f"Flag '{flag}' is TCP-only and incompatible with UDP scans"
                )
                invalid_flags.append(flag)
            elif flag in SCTP_ONLY_FLAGS:
                warnings.append(
                    f"Flag '{flag}' is SCTP-only and incompatible with UDP scans"
                )
                invalid_flags.append(flag)
            elif flag in IP_PROTOCOL_FLAGS:
                warnings.append(
                    f"Flag '{flag}' is IP protocol-only and incompatible with UDP scans"
                )
                invalid_flags.append(flag)
            else:
                valid_flags.append(flag)
        else:
            # Unknown scan type, just check if flag is valid
            valid_flags.append(flag)

    return valid_flags, invalid_flags, warnings


def get_flag_categories():
    """Return information about flag categories for help text."""
    return {
        "tcp_only": sorted(TCP_ONLY_FLAGS),
        "udp_only": sorted(UDP_ONLY_FLAGS),
        "universal": sorted(UNIVERSAL_FLAGS),
        "total_flags": len(ALL_VALID_FLAGS),
    }
