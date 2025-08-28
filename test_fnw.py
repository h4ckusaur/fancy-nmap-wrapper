# test_fancy_scanner.py
import os
import json
import builtins
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Adjust import if your module name differs
import fancy_scanner as fs


# -------------------------
# Fixtures & Test Utilities
# -------------------------

@pytest.fixture(autouse=True)
def clean_summary_and_config(tmp_path, monkeypatch):
    """
    - Puts outputs under a temp directory
    - Resets summary_data between tests
    - Ensures output directory exists
    - Resets enable_json to False unless a test flips it
    """
    # Backup original config and summary
    orig_output = fs.config.get("output_directory")
    orig_enable_json = fs.config.get("enable_json", False)

    fs.config["output_directory"] = str(tmp_path)
    fs.config["enable_json"] = False
    fs.summary_data.clear()

    Path(fs.config["output_directory"]).mkdir(parents=True, exist_ok=True)

    yield

    # Restore at end (best effort)
    fs.config["output_directory"] = orig_output
    fs.config["enable_json"] = orig_enable_json
    fs.summary_data.clear()


def _mock_run_ping(*args, **kwargs):
    """Simulate successful ICMP ping."""
    class Result:
        returncode = 0
        stdout = "Simulated ping output"
        stderr = ""
    return Result()


def _mock_run_nmap(*args, **kwargs):
    """Simulate successful nmap run."""
    class Result:
        returncode = 0
        stdout = "Simulated Nmap output for testing"
        stderr = ""
    return Result()


def _make_targets(tmp_path, ips=("192.168.1.1", "192.168.1.2")):
    targets_file = Path(tmp_path) / "targets.txt"
    targets_file.write_text("\n".join(ips) + "\n", encoding="utf-8")
    return targets_file


# -------------------------
# Discovery Tests
# -------------------------

@patch("fancy_scanner.subprocess.run", side_effect=_mock_run_ping)
def test_discovery_creates_targets_and_summary(mock_run, tmp_path):
    fs.discovery(['192.168.1.0/30'])  # /30 has two hosts: .1 and .2
    targets = Path(tmp_path) / "targets.txt"
    assert targets.exists(), "targets.txt not created"

    content = targets.read_text(encoding="utf-8").strip().splitlines()
    assert "192.168.1.1" in content and "192.168.1.2" in content

    # Summary should include discovery entry with the targets file
    assert any(e.get("Scan Type") == "Discovery" and str(targets) in e.get("Files", [])
               for e in fs.summary_data)


@patch("fancy_scanner.subprocess.run", side_effect=_mock_run_ping)
def test_discovery_invalid_subnet_does_not_create_targets(mock_run, tmp_path, capsys):
    fs.discovery(['not-a-subnet'])
    targets = Path(tmp_path) / "targets.txt"
    assert not targets.exists(), "targets.txt should not be created on invalid input"
    captured = capsys.readouterr().out
    assert "Invalid subnet" in captured


# -------------------------
# TCP / UDP Scan Tests
# -------------------------

@patch("fancy_scanner.subprocess.run", side_effect=_mock_run_nmap)
def test_tcp_scan_creates_output_and_returns_file(mock_run, tmp_path):
    ip = "192.0.2.10"
    res = fs.tcp_scan(ip, "internal")
    out_file = Path(tmp_path) / f"portscan_internal_tcp_{ip}.txt"
    assert out_file.exists()
    assert "Simulated Nmap output" in out_file.read_text(encoding="utf-8")
    assert res["ip"] == ip and res["type"] == "tcp" and res["file"] == str(out_file)


@patch("fancy_scanner.subprocess.run", side_effect=_mock_run_nmap)
def test_udp_scan_creates_output_and_returns_file(mock_run, tmp_path):
    ip = "198.51.100.42"
    res = fs.udp_scan(ip, "external")
    out_file = Path(tmp_path) / f"portscan_external_udp_{ip}.txt"
    assert out_file.exists()
    assert "Simulated Nmap output" in out_file.read_text(encoding="utf-8")
    assert res["ip"] == ip and res["type"] == "udp" and res["file"] == str(out_file)


# -------------------------
# scan_targets Tests
# -------------------------

def test_scan_targets_without_targets_file_returns_empty(capsys):
    results = fs.scan_targets(fs.tcp_scan, "internal", "TCP Scan 1", fs.Fore.BLUE)
    assert results == []
    out = capsys.readouterr().out
    assert "No targets found. Run discovery first." in out


def _mock_tcp_scan_creating_files(ip, scan_type):
    """Mock tcp_scan that writes its file like the real function."""
    out_dir = fs.config["output_directory"]
    path = Path(out_dir) / f"portscan_{scan_type}_tcp_{ip}.txt"
    path.write_text(f"[MOCK TCP] Results for {ip}", encoding="utf-8")
    return {"ip": ip, "type": "tcp", "output": "[MOCK TCP]", "file": str(path)}


def _mock_udp_scan_creating_files(ip, scan_type):
    out_dir = fs.config["output_directory"]
    path = Path(out_dir) / f"portscan_{scan_type}_udp_{ip}.txt"
    path.write_text(f"[MOCK UDP] Results for {ip}", encoding="utf-8")
    return {"ip": ip, "type": "udp", "output": "[MOCK UDP]", "file": str(path)}


def test_scan_targets_tcp_happy_path_with_json(tmp_path):
    fs.config["enable_json"] = True
    _make_targets(tmp_path, ips=("10.0.0.10", "10.0.0.11"))

    with patch.object(fs, "tcp_scan", side_effect=_mock_tcp_scan_creating_files):
        results = fs.scan_targets(fs.tcp_scan, "internal", "TCP Scan 1", fs.Fore.BLUE)

    # Should have one file per host and a JSON summary
    tcp_files = [
        Path(tmp_path) / "portscan_internal_tcp_10.0.0.10.txt",
        Path(tmp_path) / "portscan_internal_tcp_10.0.0.11.txt",
    ]
    for p in tcp_files:
        assert p.exists() and "[MOCK TCP]" in p.read_text(encoding="utf-8")

    # JSON name includes scan_type and label.lower()
    json_file = Path(tmp_path) / "results_internal_tcp scan 1.json"
    assert json_file.exists(), f"Missing JSON: {json_file}"
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 2
    # Summary should include an entry for this scan label
    assert any(e.get("Scan Type") == "TCP Scan 1" for e in fs.summary_data)


def test_scan_targets_udp_happy_path_no_json(tmp_path):
    fs.config["enable_json"] = False
    _make_targets(tmp_path, ips=("10.0.0.20", "10.0.0.21"))

    with patch.object(fs, "udp_scan", side_effect=_mock_udp_scan_creating_files):
        results = fs.scan_targets(fs.udp_scan, "external", "UDP Scan 1", fs.Fore.MAGENTA)

    udp_files = [
        Path(tmp_path) / "portscan_external_udp_10.0.0.20.txt",
        Path(tmp_path) / "portscan_external_udp_10.0.0.21.txt",
    ]
    for p in udp_files:
        assert p.exists() and "[MOCK UDP]" in p.read_text(encoding="utf-8")

    # No JSON expected
    json_file = Path(tmp_path) / "results_external_udp scan 1.json"
    assert not json_file.exists()
    assert any(e.get("Scan Type") == "UDP Scan 1" for e in fs.summary_data)


# -------------------------
# run_selected_scans Order & Summary
# -------------------------

def test_run_selected_scans_enforces_discovery_first(tmp_path):
    # Prepare targets that discovery would create
    targets_after_discovery = Path(tmp_path) / "targets.txt"

    call_order = []

    def mock_discovery(subnets):
        call_order.append(("discovery", tuple(subnets)))
        # simulate discovery creating targets
        targets_after_discovery.write_text("192.168.56.10\n", encoding="utf-8")

    def mock_scan_targets(scan_func, scan_type, label, color):
        call_order.append(("scan_targets", scan_type, label))

    choices = [
        {"type": "discovery", "subnets": ["192.168.56.0/30"]},
        {"type": "tcp", "count": 1, "mode": "internal"},
    ]

    with patch.object(fs, "discovery", side_effect=mock_discovery), \
         patch.object(fs, "scan_targets", side_effect=mock_scan_targets):
        fs.run_selected_scans(choices)

    # discovery must come before scan_targets
    assert call_order[0][0] == "discovery"
    assert any(c[0] == "scan_targets" for c in call_order)
    assert targets_after_discovery.exists()


def test_show_summary_report_outputs_table(capsys):
    # Seed the summary with two entries
    fs.summary_data.extend([
        {"Scan Type": "Discovery", "Details": "Subnets: 10.0.0.0/30", "Files": ["/tmp/targets.txt"]},
        {"Scan Type": "TCP Scan 1", "Details": "Mode: internal | Hosts: 2",
         "Files": ["/tmp/portscan_internal_tcp_10.0.0.10.txt", "/tmp/portscan_internal_tcp_10.0.0.11.txt"]},
    ])
    fs.show_summary_report()
    out = capsys.readouterr().out
    # PrettyTable draws borders, ensure key strings exist
    assert "Scan Summary Report" in out
    assert "Discovery" in out
    assert "TCP Scan 1" in out
    assert "/tmp/targets.txt" in out


# -------------------------
# Interactive Selection Tests
# -------------------------

def _inputs(*items):
    """Helper generator for monkeypatching input()."""
    it = iter(items)
    return lambda prompt="": next(it)

def test_collect_scan_choices_interactive_with_warning(monkeypatch, capsys):
    """
    Flow:
    - Choose Discovery (1), enter subnets, add more (y)
    - Choose TCP (2), enter count 12 (warn), choose mode Internal (1), add more (n)
    - Done (implicit by 'n')
    """
    user_inputs = _inputs(
        "1",                          # Discovery
        "192.168.10.0/30,10.0.0.0/30",# subnets
        "y",                          # add more
        "2",                          # TCP
        "12",                         # count (triggers warning)
        "1",                          # Internal
        "n"                           # stop adding
    )
    monkeypatch.setattr(builtins, "input", user_inputs)
    scans = fs.collect_scan_choices()

    # One discovery + one tcp block
    assert any(s["type"] == "discovery" for s in scans)
    tcp = next(s for s in scans if s["type"] == "tcp")
    assert tcp["count"] == 12 and tcp["mode"] == "internal"

    out = capsys.readouterr().out
    assert "More than 10 scans may cause instability" in out


def test_collect_scan_choices_prevents_multiple_discovery(monkeypatch, capsys):
    """
    Flow:
    - Choose Discovery twice, ensure only one is added
    - Then Done
    """
    user_inputs = _inputs(
        "1", "192.168.1.0/30", "y",  # Discovery add
        "1",                         # Attempt Discovery again -> should warn
        "4"                          # Done
    )
    monkeypatch.setattr(builtins, "input", user_inputs)
    scans = fs.collect_scan_choices()

    assert sum(1 for s in scans if s["type"] == "discovery") == 1
    out = capsys.readouterr().out
    assert "Only one discovery scan is allowed" in out


# -------------------------
# Config Tests
# -------------------------

def test_config_has_required_keys():
    required = [
        "thread_count", "enable_json", "output_directory",
        "udp_ports", "nmap_flags_tcp", "nmap_flags_udp"
    ]
    for key in required:
        assert key in fs.config, f"Missing config key: {key}"
