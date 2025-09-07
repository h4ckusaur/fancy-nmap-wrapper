# �� Fancy Nmap Wrapper (FNW) - Advanced Network Scanner

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/fnw/graphs/commit-activity)

> **Professional-grade network scanning tool with intelligent subnet categorization, persistent configurations, and beautiful user interface**

---

## 🌟 Features

### 🔍 **Smart Discovery & Categorization**
- **Intelligent Subnet Detection**: Automatically discovers and categorizes network subnets
- **Manual IP Addition**: Add target IPs directly without discovery scans
- **Persistent Categorization**: Remembers internal/external classifications across sessions
- **JSON Persistence**: Stores categorizations in `categorizations.json` for cross-session memory
- **Smart Target Management**: Preserves categorizations when adding/removing subnets
- **Comma-Separated Input**: Add multiple IPs at once with validation

### ⚡ **Advanced Scanning Capabilities**
- **Enhanced Quick Scan**: Multi-flag combination scanning with all available flag sources
- **Advanced Configuration**: Custom nmap flags, port ranges, and scan parameters
- **Concurrent Execution**: Multi-threaded scanning with separate progress bars
- **Subnet-Aware Targeting**: Scans only targets within designated subnets
- **Comprehensive Coverage**: Automatically uses default, custom, and saved flag combinations
- **Extensive NSE Scripts**: 42 UDP ports with 200+ specialized NSE scripts for deep service analysis
- **Intelligent Failure Detection**: Automatically detects and handles scan failures
- **Smart Scan Cancellation**: Cancels remaining scans for an IP when failure conditions are detected
- **Pre-Scan Ping Filtering**: Automatically filters out non-responsive IPs before scanning

### 🎯 **Professional User Experience**
- **Single-Key Navigation**: Press numbered keys without Enter for instant menu selection
- **Arrow Key Support**: Navigate menus with arrow keys, home/end, and word deletion
- **Enhanced Input**: Ctrl+W for word deletion, Ctrl+U to clear line
- **Beautiful Interface**: ASCII art banners and organized menu structures
- **Progress Tracking**: Real-time progress bars with detailed scan information
- **Smart Menu Navigation**: Return to main menu options from subnet selection screens
- **Graceful Exit**: Ctrl+C handling throughout the application for clean termination
- **Cross-Platform**: Works on Linux, macOS, and Windows with proper signal handling

### 🛠 **Configuration Management**
- **Persistent Settings**: Saves all configurations across program runs
- **Custom Port Ranges**: Define specific ports or port ranges for scans
- **Thread Management**: Configurable thread counts for optimal performance
- **Output Customization**: JSON output options and flexible directory structures
- **Flag Management**: Save and reuse custom nmap flag combinations with names
- **Environment Variables**: Persistent flag storage with configurable file paths
- **Smart Flag Storage**: Automatic prompts to save new flag combinations
- **Duplicate Detection**: Prevents saving identical flag combinations

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Configuration](#-configuration)
- [Advanced Features](#-advanced-features)
- [File Structure](#-file-structure)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Installation

### Prerequisites
- **Python 3.7+** (3.8+ recommended)
- **Nmap** installed and accessible in PATH
- **Root/Administrator** access for raw socket operations

### Automated Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/fnw.git
cd fnw

# Run the installer
python3 installer.py
```

### Manual Installation
```bash
# Install dependencies
pip3 install -r requirements.txt

# Or install system packages (Ubuntu/Debian)
sudo apt update
sudo apt install python3-tqdm python3-colorama python3-pyfiglet python3-pytest
```

### Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv ~/.venv/fnw
source ~/.venv/fnw/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🛡️ **Intelligent Failure Detection & Cancellation**

### **Automatic Failure Detection**
FNW automatically detects and handles various scan failure conditions:

- **TCP Scan Failures**: Detects "Host seems down" and "Scan timed out" messages
- **UDP Scan Failures**: Detects "All ports in ignored states" conditions
- **Timeout Detection**: Improved regex patterns catch timeouts with decimal values (e.g., "Scan timed out after 1.5 minutes")
- **No File Output**: When failures are detected, no output files are created to avoid cluttering results

### **Smart Scan Cancellation**
When a failure condition is detected for an IP address:

1. **Immediate Marking**: The IP is immediately marked as failed
2. **Remaining Scan Cancellation**: All pending scans for that IP are automatically skipped
3. **Resource Optimization**: Prevents wasted time and resources on known failed targets
4. **Clear Feedback**: Users see clear messages about skipped scans and failure reasons

### **Failure Detection Patterns**
```bash
# TCP Failure Patterns (automatically detected)
"Host seems down"
"Scan timed out after 5 minutes"
"Scan timed out after 1.5 minutes"
"Scan timed out after 2.25 minutes"

# UDP Failure Patterns (automatically detected)
"All 50 scanned ports on 192.168.1.100 are in ignored states"
"All 1000 scanned ports on 10.0.0.1 are in ignored states"
```

### **Comprehensive NSE Script Coverage**
FNW includes extensive NSE script coverage for UDP services across 42 different ports with intelligent script selection:

- **Smart Script Selection**: 
  - **Full UDP Scans**: Automatically uses all 134+ available NSE scripts for comprehensive service analysis
  - **Targeted Scans**: Only uses scripts relevant to specified ports for efficient scanning
- **DNS Services (Port 53)**: 18 scripts including zone transfers, brute forcing, and cache snooping
- **SNMP Services (Ports 161-162)**: 12 scripts for enumeration, brute forcing, and system information
- **SMB/NetBIOS (Ports 137-139, 445)**: 35+ scripts for share enumeration, user discovery, and vulnerability detection
- **Industrial Protocols**: Modbus (502), BACnet (47808), S7 (102), DNP3 (20000), Profinet (34964)
- **IoT Protocols**: MQTT (1883), CoAP (5683), UPnP (1900), mDNS (5353)
- **Network Services**: DHCP (67-68), TFTP (69), NTP (123), RPC (135), LDAP (389)
- **Specialized Services**: SIP (5060), RTSP (554), H.323 (1720), Bitcoin (8333)

### **Pre-Scan Ping Filtering**
Before executing TCP or UDP scans, FNW automatically performs a quick ping sweep:

- **Silent Operation**: No verbose output during ping sweep
- **Concurrent Pings**: Uses multi-threading for fast ping operations
- **Smart Filtering**: Only scans IPs that respond to ping
- **Resource Optimization**: Prevents wasted time on unreachable targets
- **Warning System**: Alerts if no targets respond to ping

### **User Experience**
- **Real-time Feedback**: Immediate notification when failures are detected
- **Progress Tracking**: Progress bars show skipped scans with clear indicators
- **Clean Results**: No failed scan files cluttering your output directory
- **Efficient Scanning**: Time and resources are not wasted on unreachable targets
- **Pre-filtered Targets**: Only responsive IPs are scanned, improving efficiency

---

## 🚀 Quick Start

### 1. **Discovery Scan**
```bash
python3 fnw.py
# Choose: Configure and Run Scans → Add Discovery Scan
# Enter subnet: 192.168.1.0/24
# Categorize as: Internal
```

### 2. **Enhanced Quick Scan**
```bash
# After discovery, choose: Quick Scan (Multi-Flag Combination Scan)
# Automatically runs comprehensive scans with ALL available flag combinations:
# - Default flags from configuration
# - Custom flags from configuration  
# - Saved flag combinations from persistent storage
# Results are consolidated into single files per IP+protocol
```

### 3. **Advanced Scanning**
```bash
# Choose: Advanced Scanning → Add TCP Scan
# Configure custom ports, flags, and parameters
```

### 4. **Flag Management**
```bash
# Choose: Flag Management → Set flags file path
# Enter path: /home/user/.fnw/flags.json
# Save custom flag combinations with names
# Reuse saved flags in future scans
```

### 5. **Manual IP Addition**
```bash
# Choose: Add IPs Manually
# View current subnets and IPs
# Enter: 192.168.1.100,10.0.0.50,172.16.1.10
# Categorize each IP as internal or external
# Automatically saves to targets.txt
```

---

## 📖 Usage Guide

### **Main Menu Options**

| Option | Description |
|--------|-------------|
| **Configure and Run Scans** | Main scanning interface |
| **View Configuration** | Display current settings |
| **Update Configuration** | Modify scan parameters |
| **Advanced Configuration** | Advanced settings management |
| **Flag Management** | Save and manage custom nmap flag combinations |
| **Add IPs Manually** | Add target IPs without discovery scan |

### **Scan Types**

#### 🔍 **Discovery Scan**
- **Purpose**: Find live hosts in specified subnets
- **Method**: Ping sweep with configurable timeouts
- **Output**: `targets.txt` with discovered IP addresses
- **Categorization**: Internal/External classification

#### 🎯 **TCP Scan**
- **Purpose**: Port scanning with TCP connect/syn scans
- **Features**: Custom ports, nmap flags, subnet targeting
- **Output**: `portscan_{mode}_tcp_{ip}.txt` files
- **Modes**: Internal/External with different default settings

#### 🚀 **UDP Scan**
- **Purpose**: UDP port discovery and service detection
- **Features**: NSE script integration, custom port ranges
- **Output**: `portscan_{mode}_udp_{ip}.txt` files
- **Scripts**: Automatic script selection based on ports

#### 📝 **Manual IP Addition**
- **Purpose**: Add target IPs without running discovery scans
- **Features**: Comma-separated input, IP validation, automatic categorization
- **Output**: Updates `targets.txt` with new IPs
- **Integration**: Seamlessly works with existing scan workflows

### **Scan Execution Flow**

```
1. Discovery Scan → targets.txt + categorizations.json
   OR
   Manual IP Addition → targets.txt + categorizations.json
2. Quick Scan → Automatic TCP/UDP scans
3. Advanced Scans → Custom configuration with saved flags
4. Results → Organized output files
```

---

## ⚙️ Configuration

### **Default Configuration**
```json
{
  "output_directory": "scan_results",
  "thread_count": 10,
  "enable_json": false,
  "tcp_ports_full_scan": "1-65535",
  "udp_ports_full_scan": "1-65535",
  "nmap_flags_tcp": {
    "default": ["-sS", "-sV", "-O", "--version-intensity", "5"],
    "custom": []
  },
  "nmap_flags_udp": {
    "default": ["-sU", "-sV", "--version-intensity", "3"],
    "custom": []
  }
}
```

### **Customization Options**
- **Port Ranges**: Define specific ports or ranges
- **Nmap Flags**: Custom scan parameters and options
- **Thread Count**: Performance tuning for your system
- **Output Format**: JSON and text output options

---

## 🔧 Advanced Features

### **Subnet Categorization System**
```python
# Automatic categorization
subnet_categorizations = {
    "10.0.0.0/8": "internal",
    "192.168.0.0/16": "internal", 
    "172.16.0.0/12": "internal"
}

# Persistent storage
categorizations.json → Cross-session memory
```

### **Intelligent Target Management**
- **Session Persistence**: Remembers categorizations during program run
- **Cross-Session Memory**: JSON file stores all categorizations
- **Smart Restoration**: Automatically restores previous settings
- **Conflict Resolution**: Handles subnet re-addition gracefully

### **Enhanced Input System**
- **Single-Key Selection**: Press numbered keys without Enter for instant menu navigation
- **Arrow Keys**: Navigate through input fields
- **Home/End**: Jump to beginning/end of line
- **Ctrl+W**: Delete word by word
- **Ctrl+U**: Clear entire line
- **Ctrl+K**: Kill from cursor to end

### **Flag Management System**
- **Persistent Storage**: Save custom nmap flag combinations with descriptive names
- **Environment Variables**: Store flag file paths in `FNW_FLAGS_FILE_PATH` environment variable
- **Smart Prompts**: Automatic prompts to save new flag combinations
- **Cross-Session Memory**: Flag combinations persist across program runs
- **Easy Access**: Quick selection of saved flags during scan configuration
- **Duplicate Prevention**: Automatically detects and prevents saving identical flags
- **Setup Wizard**: First-time setup prompts when using custom flags
- **Real-Time Validation**: Validates nmap flags against official documentation
- **TCP/UDP Compatibility**: Warns about incompatible flags for scan types
- **Interactive Input**: Enter flags one at a time with immediate feedback
- **Smart Error Handling**: Keeps valid flags, warns about invalid ones
- **Comprehensive Coverage**: Supports 116+ valid nmap flags across all categories

### **Advanced Flag Validation**
- **Real-Time Validation**: Validates space-separated flags as you enter them
- **TCP/UDP Compatibility**: Automatically detects incompatible flags
- **Smart Error Handling**: Keeps valid flags, shows warnings for invalid ones
- **Interactive Workflow**: Enter space-separated flags, type 'd' when done
- **Comprehensive Database**: 116+ validated nmap flags from official documentation
- **Category Awareness**: Distinguishes between TCP-only, UDP-only, and universal flags
- **Immediate Feedback**: See validation results and warnings instantly
- **Flexible Input**: Enter multiple flags in one line or continue adding more

### **Intelligent Scan Failure Detection**
- **TCP Scan Monitoring**: Detects "Host seems down" and "Scan timed out" conditions
- **UDP Scan Monitoring**: Detects "All ports in ignored states" conditions
- **Smart File Management**: No output files created for failed scans
- **User Notifications**: Clear warning messages for failed scan attempts
- **Detailed Information**: Extracts port counts and IP addresses from failure messages
- **Resource Optimization**: Prevents unnecessary file creation for failed scans

### **Multi-Combination Scan Tracking**
- **Flag Combination Tracking**: Tracks multiple flag combinations per IP+protocol pair
- **File Consolidation**: All scan results for the same IP+protocol are stored in a single file
- **Smart File Appending**: Additional scans append to existing files with clear separators
- **Combination History**: Maintains history of all flag combinations used for each target
- **Enhanced Custom Flag Input**: Shows existing saved flags when entering custom flags
- **Environment Variable**: Uses `FNW_FLAGS_FILE_PATH` for persistent flag storage

### **Enhanced Quick Scan**
- **Multi-Flag Combination Scanning**: Automatically runs scans with ALL available flag combinations
- **Comprehensive Coverage**: Includes default, custom, and saved flag combinations
- **Dynamic Messaging**: Shows exactly which flag sources are being used
- **File Consolidation**: All results for each IP+protocol are stored in a single file
- **Smart Detection**: Automatically detects available flag combinations from all sources
- **Efficient Execution**: Runs multiple scans concurrently with proper progress tracking
- **Message Examples**:
  - "Scanning with defaults" (default flags only)
  - "Scanning with default and custom" (default + config custom)
  - "Scanning with default and persistent json" (default + saved flags)
  - "Scanning with default, custom, and persistent json" (all sources)

### **Manual IP Management**
- **Direct Addition**: Add IPs without discovery scans
- **Batch Input**: Comma-separated IP lists with validation
- **Smart Categorization**: Individual internal/external classification
- **Automatic Subnetting**: IPs assigned to appropriate /24 subnets
- **Current State Display**: Shows existing subnets before adding new IPs
- **Seamless Integration**: Works with all existing scan workflows

### **Enhanced Signal Handling**
- **Graceful Exit**: Ctrl+C handling throughout the application
- **Cross-Platform**: SIGINT, SIGTERM, and SIGBREAK support
- **No Infinite Loops**: All input loops handle interrupts properly
- **Clean Termination**: Friendly exit messages and proper cleanup

---

## 📁 File Structure

```
fnw/
├── fnw.py                 # Main application with all features
├── installer.py           # Installation script
├── requirements.txt       # Python dependencies
├── config.json           # Configuration file
├── scan_results/         # Output directory
│   ├── targets.txt       # Discovered/manually added targets
│   ├── categorizations.json  # Subnet categorizations
│   ├── portscan_*_tcp_*.txt  # TCP scan results
│   └── portscan_*_udp_*.txt  # UDP scan results
├── flags.json            # Saved flag combinations (user-defined path)
├── test_fnw.py           # Comprehensive unit tests
├── README.md             # This file
└── LICENSE               # MIT License
```

### **Output Files**
- **`targets.txt`**: List of discovered and manually added IP addresses
- **`categorizations.json`**: Subnet categorization persistence
- **`portscan_{mode}_{type}_{ip}.txt`**: Individual scan results
- **`config.json`**: Application configuration
- **`flags.json`**: Saved nmap flag combinations (user-defined location)

---

## 🧪 Testing

### **Run Unit Tests**
```bash
# Basic tests
python3 -m pytest test_fnw.py

# With coverage
python3 -m pytest test_fnw.py --cov=fnw --cov-report=html

# Verbose output
python3 -m pytest test_fnw.py -v
```

### **Test Coverage**
- **Core Functionality**: Scan creation, execution, and management
- **Configuration**: Settings management and persistence
- **User Interface**: Menu navigation and input handling
- **File Operations**: Output generation and categorization
- **Flag Management**: Flag storage, retrieval, and environment variables
- **Signal Handling**: KeyboardInterrupt and signal processing
- **Manual IP Addition**: IP validation, categorization, and storage
- **Single-Key Input**: Terminal input handling and fallbacks

---

## 🔍 Troubleshooting

### **Common Issues**

#### **Permission Denied Errors**
```bash
# Ensure nmap is accessible
sudo chmod +s $(which nmap)

# Run with appropriate privileges
sudo python3 fnw.py
```

#### **Dependencies Missing**
```bash
# Reinstall requirements
pip3 install -r requirements.txt

# Check Python version
python3 --version  # Should be 3.7+
```

#### **Scan Failures**
```bash
# Verify targets.txt exists
ls -la scan_results/targets.txt

# Check categorizations
cat scan_results/categorizations.json

# Validate subnet format
# Use CIDR notation: 192.168.1.0/24
```

#### **Flag Management Issues**
```bash
# Check environment variable
echo $FNW_FLAGS_FILE_PATH

# Verify flags file exists
ls -la ~/.fnw/flags.json

# Reset flag storage
# Use Flag Management → Clear all saved flags
```

#### **Manual IP Addition Issues**
```bash
# Check IP format
# Valid: 192.168.1.1,10.0.0.1,172.16.1.100
# Invalid: 192.168.1,10.0.0.1.1,invalid-ip

# Verify targets.txt after addition
cat scan_results/targets.txt
```

#### **Ctrl+C Not Working**
```bash
# If Ctrl+C doesn't exit properly:
# 1. Try Ctrl+Z then 'kill %1'
# 2. Use 'kill -9 <pid>' from another terminal
# 3. Check if running in background mode
```

### **Debug Mode**
```bash
# Enable verbose logging
export FNW_DEBUG=1
python3 fnw.py
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Fork and clone
git clone https://github.com/yourusername/fnw.git
cd fnw

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Run tests
pytest test_fnw.py -v
```

### **Code Style**
- **Python**: PEP 8 compliance
- **Documentation**: Comprehensive docstrings
- **Testing**: High test coverage
- **Type Hints**: Where applicable

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Nmap Project**: For the powerful scanning engine
- **Python Community**: For excellent libraries and tools
- **Open Source Contributors**: For inspiration and feedback

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/fnw/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/fnw/discussions)
- **Wiki**: [Project Wiki](https://github.com/yourusername/fnw/wiki)

---

<div align="center">

**Made with ❤️ by the FNW Team**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/fnw?style=social)](https://github.com/yourusername/fnw)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/fnw?style=social)](https://github.com/yourusername/fnw)
[![GitHub issues](https://img.shields.io/github/issues/yourusername/fnw)](https://github.com/yourusername/fnw/issues)

</div>

