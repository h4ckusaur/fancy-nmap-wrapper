# 🚀 Fancy Network Scanner

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

---

## ⚡ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/fancy-network-scanner.git
```


2. Execute the installer.

```bash
cd fancy-network-scanner
python installer.py
```

## ⚡ Execution

**Interactive**

```bash
python fancy_scanner.py
```

**CLI Mode**

Dicover routable hosts in one or more subnets:

```bash
python fancy_scanner.py --mode discovery --subnets 192.168.1.0/24,192.168.2.0/24
```

TCP Scan on targets.txt (Internal network):

```bash
python fancy_scanner.py --mode tcp --targets targets.txt --internal
```
UDP Scan on targets.txt (External network):

```bash
python fancy_scanner.py --mode udp --targets targets.txt --external
```

Enable json output:

```bash
python fancy_scanner.py --mode tcp --json
```

## ⚡ Testing

```bash
pytest test_scanner.py
```