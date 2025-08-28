# 🚀 Fancy Nmap Wrapper

A multi-threaded, stylish, and configurable network scanner with:

- Multi-subnet ping sweep (Discovery)
- Full TCP port scans (all ports, aggressive detection)
- Top 50 UDP port scans with optional NSE scripts
- Threaded execution using ThreadPoolExecutor
- Optional JSON output and detailed logging
- Fancy ASCII menu with colors and progress bars

---

## ✨ Features

- **Discovery Mode**  
  Multi-subnet ping sweep to find live hosts. Writes live hosts to `targets.txt`.

- **TCP Scan**  
  Full port range (1–65535) with service detection and OS fingerprinting.

- **UDP Scan**  
  Top 50 UDP ports with optional NSE scripts for service detection.

- **Performance**  
  Multi-threaded scans for speed and efficiency.

- **Customization**  
  Configurable via `config.json` for threads, ports, output directories, and Nmap flags.

- **Fancy UI**  
  ASCII art menu with colored headings and progress bars (`tqdm`).

- **Logging & JSON**  
  All actions logged to `scanner.log`. Optional JSON output for automation.

- **Summary Report**  
  Provides a concise summary of scan results for all targets scanned.

---

## ⚡ Requirements

- Python 3.7+  
- Nmap installed on the system
- Dependencies (handled via `installer.py` or `requirements.txt`):

```text
tqdm
colorama
pyfiglet
pytest
```

## ⚡ Installation

```bash
git clone https://github.com/h4ckusaur/fancy-nmap-wrapper.git
cd fancy-nmap-wrapper
```

## ⚡ Configuration

- **Sample Configuration File**
{
    "thread_count": 10,
    "enable_json": false,
    "output_directory": "scan_results",
    "udp_ports": [53,161,162,67,68,69,123,137,138,139,500,514,520,623,1701,1900,4500,49152,49153,49154,111,135,631,1434,5353],
    "nmap_flags_tcp": "-sT -sC -sV -A -Pn -p1-65535",
    "nmap_flags_udp": "-sU --top-ports 50"
}

- **Regenerate the Default Configuration**

```bash
python fnw.py --generate-config
```

## ⚡ Usage

- **Interactive Mode (Recommended)**

```bash
python fnw.py
```

- **Optionally Output to JSON**

```bash
python fnw.py --json
```

- **CLI Mode**

```bash
python fnw.py --mode discovery --subnets 192.168.1.0/24,192.168.2.0/24

python fnw.py --mode tcp --targets targets.txt --internal

python fnw.py --mode udp --targets targets.txt --external

python fnw.py --mode tcp --json
```

## ⚡ Testing

- **Run Unit Tests with Coverage**

```bash
pytest test_fnw.py --cov=fnw --cov-report=term-missing
```

