#!/usr/bin/env python3
"""Unit tests for fnw.py."""

import builtins
import pytest
from unittest.mock import patch
from colorama import Fore
import fnw
from fnw import collect_scan_choices, run_selected_scans, scan_targets


def _inputs(*inputs):
    """Generate simulated user input."""
    for i in inputs:
        yield i


def test_collect_scan_choices_single_tcp_udp(monkeypatch):
    """Test that a single TCP and UDP scan can be selected correctly."""
    user_inputs = _inputs("2", "1", "y", "3", "2", "n", "4")
    monkeypatch.setattr(builtins, "input", lambda _: next(user_inputs))
    scans = collect_scan_choices()
    tcp_scan = next(s for s in scans if s["type"] == "tcp")
    udp_scan = next(s for s in scans if s["type"] == "udp")
    assert tcp_scan["mode"] == "internal"
    assert udp_scan["mode"] == "external"


def test_collect_scan_choices_prevent_multiple_discovery(monkeypatch, capsys):
    """Ensure only one discovery scan is allowed but TCP can still be added."""
    user_inputs = _inputs("1", "192.168.0.0/30", "y", "2", "1", "n", "4")
    monkeypatch.setattr(builtins, "input", lambda _: next(user_inputs))
    scans = collect_scan_choices()
    assert sum(1 for s in scans if s["type"] == "discovery") == 1
    assert any(s["type"] == "tcp" for s in scans)


def test_run_selected_scans_only_tcp():
    """Ensure running only TCP scan triggers scan_targets with TCP label."""
    call_order = []

    def mock_scan_targets(scan_func, scan_type, label, color):
        call_order.append(label)

    choices = [{"type": "tcp", "mode": "internal"}]
    with patch("fnw.scan_targets", side_effect=mock_scan_targets):
        run_selected_scans(choices)

    assert call_order[0] == "TCP Scan"


def test_run_selected_scans_only_udp():
    """Ensure running only UDP scan triggers scan_targets with UDP label."""
    call_order = []

    def mock_scan_targets(scan_func, scan_type, label, color):
        call_order.append(label)

    choices = [{"type": "udp", "mode": "external"}]
    with patch("fnw.scan_targets", side_effect=mock_scan_targets):
        run_selected_scans(choices)

    assert call_order[0] == "UDP Scan"


def test_scan_targets_creates_json(tmp_path, monkeypatch):
    """Check that scan_targets writes JSON output if enabled."""
    monkeypatch.setattr(
        fnw,
        "config",
        {
            "output_directory": str(tmp_path),
            "thread_count": 1,
            "enable_json": True,
            "udp_ports": [53],
        },
    )

    (tmp_path / "targets.txt").write_text("192.168.0.1\n")

    def dummy_scan(ip, mode):
        return {
            "ip": ip,
            "type": "tcp",
            "output": "",
            "file": str(tmp_path / f"{ip}.txt"),
        }

    res = scan_targets(dummy_scan, "internal", "TCP Scan", Fore.BLUE)
    assert len(res) == 1
    json_files = list(tmp_path.glob("*.json"))
    assert json_files, "JSON output file not created"


def test_discovery_creates_targets_file(tmp_path):
    """Verify discovery creates targets.txt with reachable IPs."""
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        fnw, "config", {"output_directory": str(tmp_path), "thread_count": 1}
    )

    fnw.discovery(["192.168.0.0/30"])
    targets_file = tmp_path / "targets.txt"
    assert targets_file.exists()
    lines = targets_file.read_text().splitlines()
    assert all(line.startswith("192.168.0.") for line in lines)
    monkeypatch.undo()


def test_tcp_scan_returns_dict(tmp_path):
    """TCP scan returns a dictionary with required keys."""
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        fnw,
        "config",
        {"output_directory": str(tmp_path), "nmap_flags_tcp": "-sT -Pn -p22"},
    )
    res = fnw.tcp_scan("127.0.0.1", "internal")
    assert res["ip"] == "127.0.0.1"
    assert res["type"] == "tcp"
    assert "file" in res
    monkeypatch.undo()


def test_udp_scan_returns_dict(tmp_path):
    """UDP scan returns a dictionary with required keys."""
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        fnw, "config", {"output_directory": str(tmp_path), "udp_ports": [53]}
    )
    res = fnw.udp_scan("127.0.0.1", "internal")
    assert res["ip"] == "127.0.0.1"
    assert res["type"] == "udp"
    assert "file" in res
    monkeypatch.undo()


def test_discovery_invalid_subnet(capsys):
    """Pass invalid subnet and confirm error message."""
    fnw.discovery(["300.300.0.0/24"])
    out = capsys.readouterr().out
    assert "Invalid subnet" in out


def test_scan_targets_no_targets_file(tmp_path, capsys):
    """Ensure scan_targets gracefully handles missing targets.txt."""
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        fnw,
        "config",
        {"output_directory": str(tmp_path), "thread_count": 1, "enable_json": False},
    )
    results = fnw.scan_targets(fnw.tcp_scan, "internal", "TCP Scan", Fore.BLUE)
    out = capsys.readouterr().out
    assert "[!] No targets found" in out
    assert results == []
    monkeypatch.undo()


def test_main_menu_exit(monkeypatch, capsys):
    """Selecting '3' exits the main menu."""
    user_inputs = _inputs("3")
    monkeypatch.setattr(builtins, "input", lambda _: next(user_inputs))
    fnw.main_menu()
    out = capsys.readouterr().out
    assert "Exiting..." in out


# ---- Additional tests to boost coverage ----


def test_write_command_header_creates_header():
    """Ensure write_command_header returns expected header string."""
    cmd = "nmap -sT 127.0.0.1"
    header = fnw.write_command_header("dummy.txt", cmd)
    assert "Executed Command" in header
    assert cmd in header


def test_show_banner_outputs(capsys):
    """Ensure show_banner prints banner without errors."""
    fnw.show_banner()
    out = capsys.readouterr().out
    # Instead of checking for exact figlet text, check the tagline
    # which is always printed
    assert "Multi-Mode Network Scanner with Style!" in out


def test_show_summary_report_with_data(capsys):
    """Ensure summary report prints table with expected fields."""
    fnw.summary_data.append(
        {
            "Scan Type": "TCP Scan",
            "Details": "Mode: internal | Hosts: 1",
            "Files": ["dummy.txt"],
        }
    )
    fnw.show_summary_report()
    out = capsys.readouterr().out
    assert "Scan Summary Report" in out
    assert "TCP Scan" in out
    fnw.summary_data.clear()


def test_parse_args_enables_json(monkeypatch):
    """Ensure parse_args sets enable_json when flag provided."""
    monkeypatch.setattr("sys.argv", ["prog", "--json"])
    fnw.parse_args()
    assert fnw.config["enable_json"] is True
