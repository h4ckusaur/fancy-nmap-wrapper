import builtins
import pytest
from unittest.mock import patch
import os
from colorama import Fore  # <- add this

import fnw
from fnw import collect_scan_choices, run_selected_scans, scan_targets


# Helper to simulate input() calls
def _inputs(*inputs):
    for i in inputs:
        yield i


def test_collect_scan_choices_single_tcp_udp(monkeypatch):
    # TCP -> internal, then add more? y -> UDP -> external, then add more? n
    user_inputs = _inputs(
        "2",
        "1",
        "y",  # TCP -> internal, yes add more
        "3",
        "2",
        "n",  # UDP -> external, no more
        "4",  # Done
    )
    monkeypatch.setattr(builtins, "input", lambda _: next(user_inputs))
    scans = collect_scan_choices()
    tcp_scan = next(s for s in scans if s["type"] == "tcp")
    udp_scan = next(s for s in scans if s["type"] == "udp")
    assert tcp_scan["mode"] == "internal"
    assert udp_scan["mode"] == "external"


def test_collect_scan_choices_prevent_multiple_discovery(monkeypatch, capsys):
    # Discovery -> internal TCP
    user_inputs = _inputs(
        "1",
        "192.168.0.0/30",
        "y",  # Discovery, yes add more
        "2",
        "1",
        "n",  # TCP -> internal, no more
        "4",  # Done
    )
    monkeypatch.setattr(builtins, "input", lambda _: next(user_inputs))
    scans = collect_scan_choices()
    # Only one discovery
    assert sum(1 for s in scans if s["type"] == "discovery") == 1
    # TCP should still be added
    assert any(s["type"] == "tcp" for s in scans)


def test_run_selected_scans_only_tcp():
    call_order = []

    def mock_scan_targets(scan_func, scan_type, label, color):
        call_order.append(label)

    choices = [{"type": "tcp", "mode": "internal"}]
    with patch("fnw.scan_targets", side_effect=mock_scan_targets):
        run_selected_scans(choices)

    assert call_order[0] == "TCP Scan"


def test_run_selected_scans_only_udp():
    call_order = []

    def mock_scan_targets(scan_func, scan_type, label, color):
        call_order.append(label)

    choices = [{"type": "udp", "mode": "external"}]
    with patch("fnw.scan_targets", side_effect=mock_scan_targets):
        run_selected_scans(choices)

    assert call_order[0] == "UDP Scan"


def test_scan_targets_creates_json(tmp_path, monkeypatch):
    # Prepare config
    monkeypatch.setattr(
        "fnw.config",
        {
            "output_directory": str(tmp_path),
            "thread_count": 1,
            "enable_json": True,
            "udp_ports": [53],
        },
    )

    # Write dummy targets file
    (tmp_path / "targets.txt").write_text("192.168.0.1\n")

    def dummy_scan(ip, mode):
        return {
            "ip": ip,
            "type": "tcp",
            "output": "",
            "file": str(tmp_path / f"{ip}.txt"),
        }

    # Pass a color to avoid TypeError
    res = scan_targets(dummy_scan, "internal", "TCP Scan", "\033[36m")
    assert len(res) == 1
    json_file = tmp_path / "results_internal_tcp scan.json"
    assert json_file.exists() or any(f.endswith(".json")
                                     for f in os.listdir(tmp_path))


def test_discovery_creates_targets_file(tmp_path):
    # Patch config
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        fnw, "config", {"output_directory": str(tmp_path), "thread_count": 1}
    )

    # Run discovery with a small subnet
    fnw.discovery(["192.168.0.0/30"])
    targets_file = tmp_path / "targets.txt"
    assert targets_file.exists()
    lines = targets_file.read_text().splitlines()
    assert all(line.startswith("192.168.0.") for line in lines)

    monkeypatch.undo()


def test_tcp_scan_returns_dict(tmp_path):
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
    # Pass invalid subnet
    fnw.discovery(["300.300.0.0/24"])
    out = capsys.readouterr().out
    assert "Invalid subnet" in out


def test_scan_targets_no_targets_file(tmp_path, capsys):
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(fnw, "config", {"output_directory": str(
        tmp_path), "thread_count": 1, "enable_json": False}, )
    # Ensure no targets.txt exists
    results = fnw.scan_targets(fnw.tcp_scan, "internal", "TCP Scan", Fore.BLUE)
    out = capsys.readouterr().out
    assert "[!] No targets found" in out
    assert results == []
    monkeypatch.undo()


def test_main_menu_exit(monkeypatch, capsys):
    # Choose '3' to exit immediately
    user_inputs = _inputs("3")
    monkeypatch.setattr(builtins, "input", lambda _: next(user_inputs))
    fnw.main_menu()
    out = capsys.readouterr().out
    assert "Exiting..." in out
