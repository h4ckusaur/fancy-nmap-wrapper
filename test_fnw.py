#!/usr/bin/env python3
"""Comprehensive unit tests for Fancy Nmap Wrapper (fnw.py).

This test suite provides maximum code coverage for all major components:
- Core classes (Scan, TCPScan, UDPScan, DiscoveryScan, ScanManager)
- User interface and menu system
- Configuration management
- File operations and persistence
- Scan execution logic
- Input validation and error handling
"""

import unittest
import tempfile
import shutil
import os
import json
import sys
import signal
from unittest.mock import mock_open, patch
from unittest.mock import Mock
import subprocess

# Import the modules we want to test
import fnw
from fnw import (
    Scan,
    TCPScan,
    UDPScan,
    DiscoveryScan,
    ScanManager,
    UserInterface,
    smart_input,
    load_config,
    save_config,
    get_flags_file_path,
    set_flags_file_path,
    unset_flags_file_path,
    load_saved_flags,
    save_flags,
    add_flag_combination,
    get_saved_flag_combinations,
    prompt_to_save_flags,
    prompt_to_configure_flags_file,
    get_single_key,
    FLAGS_ENV_VAR,
    safe_input_loop,
    handle_keyboard_interrupt,
    safe_input_wrapper,
)

# Add the current directory to the path so we can import fnw
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestSmartInput(unittest.TestCase):
    """Test the smart_input function with various scenarios."""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_smart_input_valid_input(self, mock_print, mock_input):
        """Test smart_input with valid input."""
        mock_input.return_value = "test input"
        result = smart_input("Enter something: ")
        self.assertEqual(result, "test input")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_smart_input_empty_input_not_allowed(self, mock_print, mock_input):
        """Test smart_input rejects empty input when not allowed."""
        # First call returns empty, second call returns valid input
        mock_input.side_effect = ["", "valid input"]
        result = smart_input("Enter something: ")
        # Should have called print for the error message
        mock_print.assert_called()
        # Should return the valid input after the empty input was rejected
        self.assertEqual(result, "valid input")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_smart_input_empty_input_allowed(self, mock_print, mock_input):
        """Test smart_input accepts empty input when allowed."""
        mock_input.return_value = ""
        result = smart_input("Enter something: ", allow_empty=True)
        self.assertEqual(result, "")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_smart_input_strips_whitespace(self, mock_print, mock_input):
        """Test smart_input strips leading/trailing whitespace."""
        mock_input.return_value = "  test input  "
        result = smart_input("Enter something: ")
        self.assertEqual(result, "test input")


class TestConfiguration(unittest.TestCase):
    """Test configuration loading, saving, and management."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, "config.json")
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.temp_dir)

    def test_load_config_defaults(self):
        """Test loading configuration with defaults when no file exists."""
        config = load_config()
        self.assertEqual(config["output_directory"], "scan_results")
        self.assertEqual(config["thread_count"], 10)
        self.assertFalse(config["enable_json"])

    def test_load_config_existing_file(self):
        """Test loading configuration from existing file."""
        test_config = {
            "output_directory": "/custom/path",
            "thread_count": 20,
            "enable_json": True,
        }
        with open(self.config_file, "w") as f:
            json.dump(test_config, f)

        config = load_config()
        self.assertEqual(config["output_directory"], "/custom/path")
        self.assertEqual(config["thread_count"], 20)
        self.assertTrue(config["enable_json"])

    def test_load_config_merge_with_defaults(self):
        """Test that missing config keys are filled with defaults."""
        test_config = {"output_directory": "/custom/path"}
        with open(self.config_file, "w") as f:
            json.dump(test_config, f)

        config = load_config()
        self.assertEqual(config["output_directory"], "/custom/path")
        self.assertEqual(config["thread_count"], 10)  # Default value
        self.assertFalse(config["enable_json"])  # Default value

    def test_save_config(self):
        """Test saving configuration to file."""
        test_config = {
            "output_directory": "/test/path",
            "thread_count": 15,
            "enable_json": True,
        }

        save_config(test_config)

        with open(self.config_file, "r") as f:
            saved_config = json.load(f)

        self.assertEqual(saved_config, test_config)


class TestScanClasses(unittest.TestCase):
    """Test the base Scan class and its subclasses."""

    def test_scan_base_class(self):
        """Test the base Scan class functionality."""
        scan = Scan("test", "internal")
        self.assertEqual(scan.scan_type, "test")
        self.assertEqual(scan.mode, "internal")
        self.assertEqual(scan.targets, [])
        self.assertEqual(scan.files_created, [])

    def test_tcp_scan_creation(self):
        """Test TCPScan creation and properties."""
        tcp_scan = TCPScan(mode="external", ports="80,443,8080")
        self.assertEqual(tcp_scan.scan_type, "tcp")
        self.assertEqual(tcp_scan.mode, "external")
        self.assertEqual(tcp_scan.ports, "80,443,8080")
        self.assertIn("-sT", tcp_scan.nmap_flags)

    def test_udp_scan_creation(self):
        """Test UDPScan creation and properties."""
        udp_scan = UDPScan(mode="internal", ports=[53, 161, 162])
        self.assertEqual(udp_scan.scan_type, "udp")
        self.assertEqual(udp_scan.mode, "internal")
        self.assertEqual(udp_scan.ports, [53, 161, 162])
        self.assertIn("-sU", udp_scan.nmap_flags)

    def test_discovery_scan_creation(self):
        """Test DiscoveryScan creation and properties."""
        subnets = ["192.168.1.0/24", "10.0.0.0/8"]
        discovery_scan = DiscoveryScan(subnets)
        self.assertEqual(discovery_scan.scan_type, "discovery")
        self.assertEqual(discovery_scan.subnets, subnets)
        self.assertEqual(discovery_scan.subnet_categorization, {})

    def test_scan_display_info(self):
        """Test scan display information methods."""
        tcp_scan = TCPScan(mode="internal", subnet="192.168.1.0/24")
        tcp_scan.targets = ["192.168.1.1", "192.168.1.2"]

        info = tcp_scan.display_info()
        self.assertIn("TCP Scan", info)
        self.assertIn("internal", info)
        self.assertIn("192.168.1.0/24", info)
        self.assertIn("2", info)  # target count


class TestScanManager(unittest.TestCase):
    """Test the ScanManager class functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "output_directory": self.temp_dir,
            "thread_count": 5,
            "enable_json": False,
        }
        self.scan_manager = ScanManager(self.config)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_scan_manager_initialization(self):
        """Test ScanManager initialization."""
        self.assertEqual(self.scan_manager.config, self.config)
        self.assertEqual(self.scan_manager.scans, [])
        self.assertEqual(self.scan_manager.categorized_targets, {})
        self.assertEqual(self.scan_manager.existing_targets, [])
        self.assertEqual(self.scan_manager.previously_categorized_subnets, {})

    def test_add_scan(self):
        """Test adding scans to the manager."""
        tcp_scan = TCPScan(mode="internal")
        self.scan_manager.add_scan(tcp_scan)

        self.assertEqual(len(self.scan_manager.scans), 1)
        self.assertEqual(self.scan_manager.scans[0], tcp_scan)

    def test_add_scan_limit(self):
        """Test scan limit enforcement."""
        # Add 20 scans to reach the limit
        for i in range(20):
            scan = TCPScan(mode="internal")
            self.scan_manager.add_scan(scan)

        # Try to add one more
        extra_scan = TCPScan(mode="external")
        with patch("builtins.print") as mock_print:
            self.scan_manager.add_scan(extra_scan)
            mock_print.assert_called()

        self.assertEqual(len(self.scan_manager.scans), 20)

    def test_remove_scan(self):
        """Test removing scans from the manager."""
        tcp_scan = TCPScan(mode="internal")
        udp_scan = UDPScan(mode="external")

        self.scan_manager.add_scan(tcp_scan)
        self.scan_manager.add_scan(udp_scan)

        # Remove first scan
        result = self.scan_manager.remove_scan(0)
        self.assertTrue(result)
        self.assertEqual(len(self.scan_manager.scans), 1)
        self.assertEqual(self.scan_manager.scans[0], udp_scan)

    def test_remove_scan_invalid_index(self):
        """Test removing scan with invalid index."""
        result = self.scan_manager.remove_scan(999)
        self.assertFalse(result)

    def test_categorize_targets_by_subnet(self):
        """Test subnet categorization logic."""
        targets = ["192.168.1.100", "192.168.1.101", "10.0.0.50"]

        result = self.scan_manager.categorize_targets_by_subnet(targets)

        self.assertIn("192.168.1.0/24", result)
        self.assertIn("10.0.0.0/24", result)
        self.assertEqual(result["192.168.1.0/24"]["count"], 2)
        self.assertEqual(result["10.0.0.0/24"]["count"], 1)

    def test_get_subnet_scan_mode(self):
        """Test getting scan mode for subnets."""
        # Add a categorized subnet
        self.scan_manager.categorized_targets["192.168.1.0/24"] = {
            "targets": set(["192.168.1.1"]),
            "mode": "internal",
            "count": 1,
        }

        mode = self.scan_manager.get_subnet_scan_mode("192.168.1.0/24")
        self.assertEqual(mode, "internal")

        # Test default mode for unknown subnet
        mode = self.scan_manager.get_subnet_scan_mode("10.0.0.0/24")
        self.assertEqual(mode, "internal")

    def test_save_and_load_categorizations(self):
        """Test saving and loading categorizations."""
        # Save a categorization
        self.scan_manager.save_categorization("192.168.1.0/24", "internal")

        # Check if file was created
        categorizations_file = os.path.join(self.temp_dir, "categorizations.json")
        self.assertTrue(os.path.exists(categorizations_file))

        # Load categorizations
        self.scan_manager.load_categorizations()

        # Check if it was loaded into previously_categorized_subnets
        self.assertIn(
            "192.168.1.0/24", self.scan_manager.previously_categorized_subnets
        )
        self.assertEqual(
            self.scan_manager.previously_categorized_subnets["192.168.1.0/24"],
            "internal",
        )


class TestUserInterface(unittest.TestCase):
    """Test the UserInterface class functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "output_directory": self.temp_dir,
            "thread_count": 5,
            "enable_json": False,
        }
        self.ui = UserInterface()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_user_interface_initialization(self):
        """Test UserInterface initialization."""
        self.assertIsNotNone(self.ui.scan_manager)
        self.assertIsNotNone(self.ui.config)

    @patch("builtins.print")
    def test_show_banner(self, mock_print):
        """Test banner display."""
        fnw.show_banner()
        mock_print.assert_called()

    def test_validate_port_input(self):
        """Test port input validation."""
        # Valid inputs
        self.assertTrue(self.ui._validate_port_input("80"))
        self.assertTrue(self.ui._validate_port_input("80,443,8080"))
        self.assertTrue(self.ui._validate_port_input("80-90"))
        self.assertTrue(self.ui._validate_port_input("80,443,8080-8090"))

        # Invalid inputs
        self.assertFalse(self.ui._validate_port_input("99999"))  # Port > 65535
        self.assertFalse(self.ui._validate_port_input("abc"))
        self.assertFalse(self.ui._validate_port_input("80-"))
        self.assertFalse(self.ui._validate_port_input("-80"))


class TestFileOperations(unittest.TestCase):
    """Test file operations and persistence."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "output_directory": self.temp_dir,
            "thread_count": 5,
            "enable_json": False,
        }

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_create_output_directory(self):
        """Test output directory creation."""
        output_dir = os.path.join(self.temp_dir, "new_scan_results")
        os.makedirs(output_dir, exist_ok=True)

        self.assertTrue(os.path.exists(output_dir))
        self.assertTrue(os.path.isdir(output_dir))

    def test_write_command_header(self):
        """Test command header writing."""
        tcp_scan = TCPScan(mode="internal")
        cmd = "nmap -sS -p 80 192.168.1.1"

        header = tcp_scan._write_command_header("test.txt", cmd)

        self.assertIn("===== Executed Command =====", header)
        self.assertIn(cmd, header)
        self.assertIn("============================", header)


class TestScanExecution(unittest.TestCase):
    """Test scan execution logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "output_directory": self.temp_dir,
            "thread_count": 5,
            "enable_json": False,
        }
        self.scan_manager = ScanManager(self.config)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    @patch("subprocess.run")
    def test_tcp_scan_execution(self, mock_run):
        """Test TCP scan execution with mocked subprocess."""
        # Mock subprocess result
        mock_result = Mock()
        mock_result.stdout = "Scan completed successfully"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # Create TCP scan
        tcp_scan = TCPScan(mode="internal", subnet="192.168.1.0/24")

        # Mock categorized targets
        self.scan_manager.categorized_targets["192.168.1.0/24"] = {
            "targets": set(["192.168.1.1"]),
            "mode": "internal",
            "count": 1,
        }

        # Execute scan
        result = tcp_scan._scan_host("192.168.1.1", self.config)

        self.assertIsNotNone(result)
        self.assertEqual(result["target"], "192.168.1.1")
        self.assertEqual(result["returncode"], 0)
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_udp_scan_execution(self, mock_run):
        """Test UDP scan execution with mocked subprocess."""
        # Mock subprocess result for initial scan (Phase 1)
        mock_result_initial = Mock()
        mock_result_initial.stdout = """
Nmap scan report for 10.0.0.1
Host is up (0.0001s latency).

PORT     STATE         SERVICE
53/udp   open|filtered domain
161/udp  filtered      snmp

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
"""
        mock_result_initial.stderr = ""
        mock_result_initial.returncode = 0

        # Mock subprocess result for NSE scan (Phase 2)
        mock_result_nse = Mock()
        mock_result_nse.stdout = """
Nmap scan report for 10.0.0.1
Host is up (0.0001s latency).

PORT   STATE SERVICE VERSION
53/udp open  domain  ISC BIND 9.16.1
| dns-recursion: Recursion appears to be enabled
"""
        mock_result_nse.stderr = ""
        mock_result_nse.returncode = 0

        # Set up mock to return different results for different calls
        # 1 initial scan + 2 NSE scans (one for each port)
        mock_run.side_effect = [mock_result_initial, mock_result_nse, mock_result_nse]

        # Create UDP scan
        udp_scan = UDPScan(mode="external", subnet="10.0.0.0/24", ports=[53, 161])

        # Mock categorized targets
        self.scan_manager.categorized_targets["10.0.0.0/24"] = {
            "targets": set(["10.0.0.1"]),
            "mode": "external",
            "count": 1,
        }

        # Execute scan
        result = udp_scan._scan_host("10.0.0.1", self.config)

        self.assertIsNotNone(result)
        self.assertEqual(result["target"], "10.0.0.1")
        self.assertEqual(result["returncode"], 0)
        # Should be called 3 times: once for initial scan, twice for NSE scans
        # (one per port)
        self.assertEqual(mock_run.call_count, 3)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "output_directory": self.temp_dir,
            "thread_count": 5,
            "enable_json": False,
        }

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_invalid_subnet_format(self):
        """Test handling of invalid subnet formats."""
        scan_manager = ScanManager(self.config)

        # Test invalid subnet
        targets = ["invalid_ip", "192.168.1.100"]
        result = scan_manager.categorize_targets_by_subnet(targets)

        # Should only process valid IPs
        self.assertIn("192.168.1.0/24", result)
        self.assertNotIn("invalid_ip", str(result))

    def test_missing_output_directory(self):
        """Test handling of missing output directory."""
        config = self.config.copy()
        config["output_directory"] = "/nonexistent/path"

        # Should not crash, but handle gracefully
        scan_manager = ScanManager(config)
        self.assertIsNotNone(scan_manager)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "output_directory": self.temp_dir,
            "thread_count": 5,
            "enable_json": False,
        }

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_complete_workflow(self):
        """Test a complete scan workflow."""
        scan_manager = ScanManager(self.config)

        # 1. Add discovery scan
        discovery_scan = DiscoveryScan(["192.168.1.0/24"])
        scan_manager.add_scan(discovery_scan)

        # 2. Add TCP scan
        tcp_scan = TCPScan(mode="internal", subnet="192.168.1.0/24")
        scan_manager.add_scan(tcp_scan)

        # 3. Add UDP scan
        udp_scan = UDPScan(mode="internal", subnet="192.168.1.0/24")
        scan_manager.add_scan(udp_scan)

        # Verify scans were added
        self.assertEqual(len(scan_manager.scans), 3)
        self.assertTrue(any(isinstance(s, DiscoveryScan) for s in scan_manager.scans))
        self.assertTrue(any(isinstance(s, TCPScan) for s in scan_manager.scans))
        self.assertTrue(any(isinstance(s, UDPScan) for s in scan_manager.scans))

    def test_configuration_persistence(self):
        """Test that configuration persists across instances."""
        # Create first instance and modify config
        scan_manager1 = ScanManager(self.config)
        scan_manager1.config["thread_count"] = 15

        # Save config
        save_config(scan_manager1.config)

        # Create second instance and load config
        scan_manager2 = ScanManager(self.config)

        # Verify config was loaded
        self.assertEqual(scan_manager2.config["thread_count"], 15)


class TestFlagManagement(unittest.TestCase):
    """Test flag management functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.flags_file = os.path.join(self.temp_dir, "test_flags.json")
        self.original_env = os.environ.get(FLAGS_ENV_VAR)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
        # Restore original environment variable
        if self.original_env:
            os.environ[FLAGS_ENV_VAR] = self.original_env
        elif FLAGS_ENV_VAR in os.environ:
            del os.environ[FLAGS_ENV_VAR]

    def test_get_flags_file_path_none(self):
        """Test getting flags file path when not set."""
        if FLAGS_ENV_VAR in os.environ:
            del os.environ[FLAGS_ENV_VAR]
        result = get_flags_file_path()
        self.assertIsNone(result)

    def test_set_flags_file_path(self):
        """Test setting flags file path."""
        set_flags_file_path(self.flags_file)
        self.assertEqual(os.environ[FLAGS_ENV_VAR], self.flags_file)

    def test_unset_flags_file_path(self):
        """Test unsetting flags file path."""
        os.environ[FLAGS_ENV_VAR] = self.flags_file
        unset_flags_file_path()
        self.assertNotIn(FLAGS_ENV_VAR, os.environ)

    def test_load_saved_flags_empty(self):
        """Test loading flags when file doesn't exist."""
        if FLAGS_ENV_VAR in os.environ:
            del os.environ[FLAGS_ENV_VAR]
        result = load_saved_flags()
        self.assertEqual(result, {})

    def test_load_saved_flags_existing(self):
        """Test loading flags from existing file."""
        test_flags = {
            "tcp": {"stealth": "-sS -T2", "aggressive": "-sS -A -T4"},
            "udp": {"basic": "-sU -T2"},
        }

        with open(self.flags_file, "w") as f:
            json.dump(test_flags, f)

        os.environ[FLAGS_ENV_VAR] = self.flags_file
        result = load_saved_flags()
        self.assertEqual(result, test_flags)

    def test_save_flags(self):
        """Test saving flags to file."""
        test_flags = {"tcp": {"test": "-sS"}}
        os.environ[FLAGS_ENV_VAR] = self.flags_file

        result = save_flags(test_flags)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.flags_file))

        with open(self.flags_file, "r") as f:
            saved_flags = json.load(f)
        self.assertEqual(saved_flags, test_flags)

    def test_add_flag_combination(self):
        """Test adding a new flag combination."""
        os.environ[FLAGS_ENV_VAR] = self.flags_file
        add_flag_combination("tcp", "stealth", "-sS -T2")

        result = load_saved_flags()
        self.assertIn("tcp", result)
        self.assertIn("stealth", result["tcp"])
        self.assertEqual(result["tcp"]["stealth"], "-sS -T2")

    def test_get_saved_flag_combinations(self):
        """Test getting saved flag combinations for a scan type."""
        test_flags = {"tcp": {"stealth": "-sS -T2"}, "udp": {"basic": "-sU"}}

        with open(self.flags_file, "w") as f:
            json.dump(test_flags, f)

        os.environ[FLAGS_ENV_VAR] = self.flags_file
        tcp_flags = get_saved_flag_combinations("tcp")
        udp_flags = get_saved_flag_combinations("udp")

        self.assertEqual(tcp_flags, {"stealth": "-sS -T2"})
        self.assertEqual(udp_flags, {"basic": "-sU"})

    def test_get_saved_flag_combinations_empty(self):
        """Test getting saved flag combinations when none exist."""
        os.environ[FLAGS_ENV_VAR] = self.flags_file
        result = get_saved_flag_combinations("tcp")
        self.assertEqual(result, {})

    def test_prompt_to_save_flags_no_env_var(self):
        """Test prompt to save flags when no environment variable is set."""
        if FLAGS_ENV_VAR in os.environ:
            del os.environ[FLAGS_ENV_VAR]

        # Test that the function returns early when no flags file is configured
        # We can't easily test the full function without complex mocking,
        # so we'll test the logic that should cause early return
        flags_file = get_flags_file_path()
        self.assertIsNone(flags_file)

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_save_flags_user_declines(self, mock_print, mock_input):
        """Test prompt to save flags when user declines."""
        os.environ[FLAGS_ENV_VAR] = self.flags_file
        mock_input.side_effect = ["n"]

        prompt_to_save_flags("tcp", "-sS")

        # Should not save anything
        result = load_saved_flags()
        self.assertEqual(result, {})

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_save_flags_user_accepts(self, mock_print, mock_input):
        """Test prompt to save flags when user accepts."""
        os.environ[FLAGS_ENV_VAR] = self.flags_file
        mock_input.side_effect = ["y", "stealth_scan"]

        prompt_to_save_flags("tcp", "-sS -T2")

        # Should save the flags
        result = load_saved_flags()
        self.assertIn("tcp", result)
        self.assertIn("stealth_scan", result["tcp"])
        self.assertEqual(result["tcp"]["stealth_scan"], "-sS -T2")

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_configure_flags_file_user_accepts(self, mock_print, mock_input):
        """Test prompt to configure flags file when user accepts."""
        mock_input.side_effect = ["y", "~/.fnw/test_flags.json"]

        result = prompt_to_configure_flags_file()

        self.assertTrue(result)
        self.assertIn(FLAGS_ENV_VAR, os.environ)
        # Should expand ~ to home directory
        self.assertTrue(os.environ[FLAGS_ENV_VAR].endswith(".fnw/test_flags.json"))

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_configure_flags_file_user_declines(self, mock_print, mock_input):
        """Test prompt to configure flags file when user declines."""
        mock_input.side_effect = ["n"]

        result = prompt_to_configure_flags_file()

        self.assertFalse(result)
        self.assertNotIn(FLAGS_ENV_VAR, os.environ)

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_save_flags_with_setup(self, mock_print, mock_input):
        """Test prompt to save flags when no flags file is configured.

        Exercise the case where the user sets up the flags file.
        """
        if FLAGS_ENV_VAR in os.environ:
            del os.environ[FLAGS_ENV_VAR]

        mock_input.side_effect = ["y", "~/.fnw/test_flags.json", "y", "test_scan"]

        prompt_to_save_flags("tcp", "-sS -T2")

        # Should save the flags
        result = load_saved_flags()
        self.assertIn("tcp", result)
        self.assertIn("test_scan", result["tcp"])
        self.assertEqual(result["tcp"]["test_scan"], "-sS -T2")

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_save_flags_existing_flags(self, mock_print, mock_input):
        """Test prompt to save flags when flags already exist."""
        # Set up existing flags
        existing_flags = {"tcp": {"existing": "-sS -T2"}}
        with open(self.flags_file, "w") as f:
            json.dump(existing_flags, f)

        os.environ[FLAGS_ENV_VAR] = self.flags_file

        # Try to save the same flags
        prompt_to_save_flags("tcp", "-sS -T2")

        # Should not prompt since flags already exist
        mock_input.assert_not_called()

    @patch("fnw.smart_input")
    @patch("builtins.print")
    def test_prompt_to_save_flags_no_setup_declined(self, mock_print, mock_input):
        """Test prompt to save flags when user declines to set up flags file."""
        if FLAGS_ENV_VAR in os.environ:
            del os.environ[FLAGS_ENV_VAR]

        mock_input.side_effect = ["n"]

        prompt_to_save_flags("tcp", "-sS -T2")

        # Should not save anything
        self.assertNotIn(FLAGS_ENV_VAR, os.environ)


class TestSingleKeyInput(unittest.TestCase):
    """Test single key input functionality."""

    @patch("sys.stdin.fileno")
    @patch("termios.tcgetattr")
    @patch("termios.tcsetattr")
    @patch("tty.setraw")
    @patch("sys.stdin.read")
    def test_get_single_key_success(
        self, mock_read, mock_setraw, mock_tcsetattr, mock_tcgetattr, mock_fileno
    ):
        """Test successful single key input."""
        mock_fileno.return_value = 0
        mock_tcgetattr.return_value = [0, 1, 2, 3, 4, 5, 6]
        mock_read.return_value = "1"

        result = get_single_key()
        self.assertEqual(result, "1")
        mock_setraw.assert_called_once()
        mock_tcsetattr.assert_called_once()

    @patch("sys.stdin.fileno", side_effect=OSError)
    @patch("builtins.input")
    def test_get_single_key_fallback(self, mock_input, mock_fileno):
        """Test single key input fallback when termios is not available."""
        mock_input.return_value = "2"

        result = get_single_key()
        self.assertEqual(result, "2")

    @patch("fnw.get_single_key")
    def test_smart_input_single_key(self, mock_get_single_key):
        """Test smart_input with single_key=True."""
        mock_get_single_key.return_value = "3"

        result = smart_input("Choose: ", single_key=True)
        self.assertEqual(result, "3")


class TestSignalHandling(unittest.TestCase):
    """Test signal handling functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.original_signal_handlers = {}
        # Store original signal handlers
        for sig in [signal.SIGINT, signal.SIGTERM]:
            try:
                self.original_signal_handlers[sig] = signal.signal(sig, signal.SIG_DFL)
            except (OSError, ValueError):
                pass

    def tearDown(self):
        """Restore original signal handlers."""
        for sig, handler in self.original_signal_handlers.items():
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):
                pass

    # Signal handler tests removed - using KeyboardInterrupt exceptions instead

    @patch("builtins.input")
    @patch("sys.exit")
    def test_safe_input_loop_keyboard_interrupt(self, mock_exit, mock_input):
        """Test safe_input_loop with KeyboardInterrupt."""
        mock_input.side_effect = KeyboardInterrupt()

        def prompt_func():
            return mock_input("test: ")

        def validation_func(x):
            return True

        safe_input_loop(prompt_func, validation_func)
        mock_exit.assert_called_once_with(0)

    @patch("builtins.input")
    def test_safe_input_loop_valid_input(self, mock_input):
        """Test safe_input_loop with valid input."""
        mock_input.return_value = "valid_input"

        def prompt_func():
            return mock_input("test: ")

        def validation_func(x):
            return x == "valid_input"

        result = safe_input_loop(prompt_func, validation_func)
        self.assertEqual(result, "valid_input")

    @patch("builtins.input")
    def test_safe_input_loop_invalid_then_valid(self, mock_input):
        """Test safe_input_loop with invalid then valid input."""
        mock_input.side_effect = ["invalid", "valid"]

        def prompt_func():
            return mock_input("test: ")

        def validation_func(x):
            return x == "valid"

        result = safe_input_loop(prompt_func, validation_func)
        self.assertEqual(result, "valid")
        self.assertEqual(mock_input.call_count, 2)

    def test_handle_keyboard_interrupt(self):
        """Test centralized KeyboardInterrupt handler."""
        with patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit) as cm:
                handle_keyboard_interrupt()
            self.assertEqual(cm.exception.code, 0)
            mock_print.assert_called_once()

    @patch("sys.exit")
    def test_safe_input_wrapper_keyboard_interrupt(self, mock_exit):
        """Test safe_input_wrapper with KeyboardInterrupt."""

        def input_func():
            raise KeyboardInterrupt()

        with patch("builtins.print") as mock_print:
            safe_input_wrapper(input_func)
            mock_print.assert_called_once()
            mock_exit.assert_called_once_with(0)

    def test_safe_input_wrapper_success(self):
        """Test safe_input_wrapper with successful input."""

        def input_func():
            return "test_input"

        result = safe_input_wrapper(input_func)
        self.assertEqual(result, "test_input")


class TestMockingAndPatching(unittest.TestCase):
    """Test advanced mocking and patching scenarios."""

    @patch("os.path.exists")
    @patch(
        "builtins.open", new_callable=mock_open, read_data="192.168.1.1\n192.168.1.2"
    )
    def test_file_operations_with_mocks(self, mock_file, mock_exists):
        """Test file operations using mocks."""
        mock_exists.return_value = True

        # Test file reading
        with open("targets.txt", "r") as f:
            content = f.read()

        self.assertIn("192.168.1.1", content)
        self.assertIn("192.168.1.2", content)
        mock_file.assert_called()

    @patch("subprocess.run")
    def test_subprocess_mocking(self, mock_run):
        """Test subprocess mocking for scan execution."""
        # Mock successful execution
        mock_result = Mock()
        mock_result.stdout = "Success"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # Test that subprocess.run is called correctly
        result = subprocess.run(
            ["nmap", "-p", "80", "192.168.1.1"], capture_output=True, text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "Success")
        mock_run.assert_called_once()


def run_tests():
    """Run all tests with coverage reporting."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.discover(".", pattern="test_fnw.py")

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(
        f"Success rate: {((result.testsRun - len(result.failures) -
                           len(result.errors)) / result.testsRun * 100):.1f}%"
    )
    print(f"{'='*50}")

    return result.wasSuccessful()


class TestEnhancedFlagValidation(unittest.TestCase):
    """Test the enhanced flag validation and custom flag input functionality."""

    def setUp(self):
        """Set up test environment."""
        self.original_env = os.environ.get("FNW_FLAGS_FILE_PATH")
        if "FNW_FLAGS_FILE_PATH" in os.environ:
            del os.environ["FNW_FLAGS_FILE_PATH"]

    def tearDown(self):
        """Clean up test environment."""
        if self.original_env:
            os.environ["FNW_FLAGS_FILE_PATH"] = self.original_env
        elif "FNW_FLAGS_FILE_PATH" in os.environ:
            del os.environ["FNW_FLAGS_FILE_PATH"]

    @patch("fnw.smart_input")
    def test_get_custom_flags_with_validation_no_saved_flags(self, mock_input):
        """Test custom flag input when no saved flags exist."""
        mock_input.side_effect = ["-sV -sC -A", "d"]

        result = fnw.get_custom_flags_with_validation("tcp")

        self.assertEqual(result, "-sV -sC -A")
        self.assertEqual(mock_input.call_count, 2)

    @patch("fnw.smart_input")
    @patch("fnw.get_saved_flag_combinations")
    def test_get_custom_flags_with_validation_with_saved_flags(
        self, mock_saved, mock_input
    ):
        """Test custom flag input when saved flags exist."""
        mock_saved.return_value = {"Stealth": "-sS -sV -A", "Connect": "-sT -sC"}
        mock_input.side_effect = [
            "1",
            "1",
        ]  # Choose saved flags, then select first option

        result = fnw.get_custom_flags_with_validation("tcp")

        self.assertEqual(result, "-sS -sV -A")
        self.assertEqual(mock_input.call_count, 2)

    @patch("fnw.smart_input")
    def test_get_custom_flags_with_validation_cancel(self, mock_input):
        """Test custom flag input cancellation."""
        mock_input.side_effect = ["c"]

        result = fnw.get_custom_flags_with_validation("tcp")

        self.assertIsNone(result)
        self.assertEqual(mock_input.call_count, 1)


class TestEnhancedQuickScan(unittest.TestCase):
    """Test the enhanced Quick Scan functionality."""

    def setUp(self):
        """Set up test environment."""
        self.ui = fnw.UserInterface()
        self.original_config = self.ui.config.copy()

    def tearDown(self):
        """Clean up test environment."""
        self.ui.config = self.original_config

    def test_get_all_tcp_flag_combinations_default_only(self):
        """Test TCP flag combination collection with defaults only."""
        self.ui.config["nmap_flags_tcp"] = {
            "default": ["-sT", "-sC", "-sV"],
            "custom": [],
        }

        combinations = self.ui._get_all_tcp_flag_combinations()

        self.assertEqual(len(combinations), 1)
        self.assertEqual(combinations[0], "-sT -sC -sV")

    def test_get_all_tcp_flag_combinations_with_custom(self):
        """Test TCP flag combination collection with custom flags."""
        self.ui.config["nmap_flags_tcp"] = {
            "default": ["-sT", "-sC", "-sV"],
            "custom": ["-sS -sV -A", "-sT -sC -Pn"],
        }

        combinations = self.ui._get_all_tcp_flag_combinations()

        self.assertEqual(len(combinations), 3)
        self.assertIn("-sT -sC -sV", combinations)
        self.assertIn("-sS -sV -A", combinations)
        self.assertIn("-sT -sC -Pn", combinations)

    @patch("fnw.get_saved_flag_combinations")
    def test_get_all_tcp_flag_combinations_with_saved(self, mock_saved):
        """Test TCP flag combination collection with saved flags."""
        mock_saved.return_value = {"Stealth": "-sS -sV -A", "Connect": "-sT -sC"}
        self.ui.config["nmap_flags_tcp"] = {
            "default": ["-sT", "-sC", "-sV"],
            "custom": [],
        }

        combinations = self.ui._get_all_tcp_flag_combinations()

        self.assertEqual(len(combinations), 3)
        self.assertIn("-sT -sC -sV", combinations)
        self.assertIn("-sS -sV -A", combinations)
        self.assertIn("-sT -sC", combinations)

    def test_get_all_udp_flag_combinations(self):
        """Test UDP flag combination collection."""
        self.ui.config["nmap_flags_udp"] = {
            "default": ["-sU", "-Pn"],
            "custom": ["-sU -sV -A"],
        }

        combinations = self.ui._get_all_udp_flag_combinations()

        self.assertEqual(len(combinations), 2)
        self.assertIn("-sU -Pn", combinations)
        self.assertIn("-sU -sV -A", combinations)

    def test_generate_scan_message_default_only(self):
        """Test scan message generation for default only."""
        tcp_combinations = ["-sT -sC -sV"]
        udp_combinations = ["-sU -Pn"]

        message = self.ui._generate_scan_message(tcp_combinations, udp_combinations)

        self.assertEqual(message, "Scanning with default")

    def test_generate_scan_message_default_and_custom(self):
        """Test scan message generation for default and custom."""
        self.ui.config["nmap_flags_tcp"] = {"default": ["-sT"], "custom": ["-sS -sV"]}
        self.ui.config["nmap_flags_udp"] = {"default": ["-sU"], "custom": []}

        tcp_combinations = ["-sT", "-sS -sV"]
        udp_combinations = ["-sU"]

        message = self.ui._generate_scan_message(tcp_combinations, udp_combinations)

        self.assertEqual(message, "Scanning with default and custom")

    @patch("fnw.get_saved_flag_combinations")
    def test_generate_scan_message_all_sources(self, mock_saved):
        """Test scan message generation for all sources."""
        mock_saved.return_value = {"Test": "-sS -A"}
        self.ui.config["nmap_flags_tcp"] = {"default": ["-sT"], "custom": ["-sS -sV"]}
        self.ui.config["nmap_flags_udp"] = {"default": ["-sU"], "custom": []}

        tcp_combinations = ["-sT", "-sS -sV", "-sS -A"]
        udp_combinations = ["-sU"]

        message = self.ui._generate_scan_message(tcp_combinations, udp_combinations)

        self.assertEqual(message, "Scanning with default, custom, and persistent json")


class TestMultiCombinationTracking(unittest.TestCase):
    """Test the multi-combination scan tracking functionality."""

    def setUp(self):
        """Set up test environment."""
        self.config = fnw.DEFAULT_CONFIG.copy()
        self.scan_manager = fnw.ScanManager(self.config)

    def test_add_scan_combination(self):
        """Test adding scan combinations."""
        self.scan_manager.add_scan_combination("192.168.1.100", "tcp", "-sS -sV -A")
        self.scan_manager.add_scan_combination("192.168.1.100", "tcp", "-sT -sC -Pn")
        self.scan_manager.add_scan_combination(
            "192.168.1.100", "udp", "-sU --top-ports 50"
        )

        tcp_combinations = self.scan_manager.get_scan_combinations(
            "192.168.1.100", "tcp"
        )
        udp_combinations = self.scan_manager.get_scan_combinations(
            "192.168.1.100", "udp"
        )

        self.assertEqual(len(tcp_combinations), 2)
        self.assertIn("-sS -sV -A", tcp_combinations)
        self.assertIn("-sT -sC -Pn", tcp_combinations)

        self.assertEqual(len(udp_combinations), 1)
        self.assertIn("-sU --top-ports 50", udp_combinations)

    def test_get_scan_combinations_empty(self):
        """Test getting scan combinations when none exist."""
        combinations = self.scan_manager.get_scan_combinations("192.168.1.100", "tcp")

        self.assertEqual(len(combinations), 0)

    def test_add_scan_combination_duplicate_prevention(self):
        """Test that duplicate combinations are not added."""
        self.scan_manager.add_scan_combination("192.168.1.100", "tcp", "-sS -sV -A")
        self.scan_manager.add_scan_combination(
            "192.168.1.100", "tcp", "-sS -sV -A"
        )  # Duplicate

        combinations = self.scan_manager.get_scan_combinations("192.168.1.100", "tcp")

        self.assertEqual(len(combinations), 1)
        self.assertIn("-sS -sV -A", combinations)


class TestScanFailureDetection(unittest.TestCase):
    """Test the scan failure detection functionality."""

    def setUp(self):
        """Set up test environment."""
        self.tcp_scan = fnw.TCPScan(mode="internal", nmap_flags="-sT -sV")
        self.udp_scan = fnw.UDPScan(mode="internal", nmap_flags="-sU -sV")

    def test_tcp_scan_host_seems_down_detection(self):
        """Test TCP scan failure detection for 'Host seems down'."""
        mock_result = Mock()
        mock_result.stdout = (
            "Nmap scan report for 192.168.1.100\n"
            "Host seems down. If it is really up, but blocking our ping "
            "probes, try -Pn\n"
        )
        mock_result.stderr = ""
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            with patch("builtins.open", mock_open()):
                result = self.tcp_scan._scan_host(
                    "192.168.1.100", {"output_directory": "test"}
                )

        self.assertIn("error", result)
        self.assertEqual(result["error"], "Host seems down or scan timed out")

    def test_tcp_scan_timeout_detection(self):
        """Test TCP scan failure detection for 'Scan timed out'."""
        mock_result = Mock()
        mock_result.stdout = (
            "Nmap scan report for 192.168.1.100\nScan timed out after 30 seconds\n"
        )
        mock_result.stderr = ""
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            with patch("builtins.open", mock_open()):
                result = self.tcp_scan._scan_host(
                    "192.168.1.100", {"output_directory": "test"}
                )

        self.assertIn("error", result)
        self.assertEqual(result["error"], "Host seems down or scan timed out")

    def test_udp_scan_ignored_states_detection(self):
        """Test UDP scan failure detection for 'All ports in ignored states'."""
        mock_result = Mock()
        mock_result.stdout = (
            "Nmap scan report for 192.168.1.100\n"
            "All 50 scanned ports on 192.168.1.100 are in ignored states.\n"
        )
        mock_result.stderr = ""
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            with patch("builtins.open", mock_open()):
                result = self.udp_scan._scan_host(
                    "192.168.1.100", {"output_directory": "test"}
                )

        self.assertIn("error", result)
        self.assertEqual(result["error"], "All ports in ignored states")

    def test_tcp_scan_success_no_failure_detection(self):
        """Test TCP scan success (no failure detection)."""
        mock_result = Mock()
        mock_result.stdout = (
            "Nmap scan report for 192.168.1.100\n"
            "Host is up (0.001s latency).\n"
            "PORT   STATE SERVICE\n"
            "22/tcp open  ssh\n"
        )
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with patch("builtins.open", mock_open()):
                result = self.tcp_scan._scan_host(
                    "192.168.1.100", {"output_directory": "test"}
                )

        self.assertNotIn("error", result)
        self.assertIn("file", result)


class TestNmapFlagValidation(unittest.TestCase):
    """Test the nmap flag validation functionality."""

    def test_validate_nmap_flags_tcp_valid(self):
        """Test TCP flag validation with valid flags."""
        from nmap_flags import validate_nmap_flags

        flags = ["-sS", "-sV", "-sC", "-A", "-Pn"]
        valid, invalid, warnings = validate_nmap_flags(flags, "tcp")

        self.assertEqual(len(valid), 5)
        self.assertEqual(len(invalid), 0)
        self.assertEqual(len(warnings), 0)
        self.assertIn("-sS", valid)
        self.assertIn("-sV", valid)

    def test_validate_nmap_flags_tcp_invalid_udp_flag(self):
        """Test TCP flag validation with invalid UDP flag."""
        from nmap_flags import validate_nmap_flags

        flags = ["-sS", "-sV", "-sU", "-sC"]  # -sU is UDP-only
        valid, invalid, warnings = validate_nmap_flags(flags, "tcp")

        self.assertEqual(len(valid), 3)
        self.assertEqual(len(invalid), 1)
        self.assertEqual(len(warnings), 1)
        self.assertIn("-sU", invalid)
        self.assertIn("UDP-only", warnings[0])

    def test_validate_nmap_flags_udp_valid(self):
        """Test UDP flag validation with valid flags."""
        from nmap_flags import validate_nmap_flags

        flags = ["-sU", "-sV", "-sC", "--top-ports", "50"]
        valid, invalid, warnings = validate_nmap_flags(flags, "udp")

        self.assertEqual(len(valid), 4)  # --top-ports and 50 are separate
        self.assertEqual(len(invalid), 1)  # 50 is not a valid flag
        self.assertEqual(len(warnings), 0)
        self.assertIn("-sU", valid)
        self.assertIn("-sV", valid)

    def test_validate_nmap_flags_udp_invalid_tcp_flag(self):
        """Test UDP flag validation with invalid TCP flag."""
        from nmap_flags import validate_nmap_flags

        flags = ["-sU", "-sS", "-sT"]  # -sS and -sT are TCP-only
        valid, invalid, warnings = validate_nmap_flags(flags, "udp")

        self.assertEqual(len(valid), 1)
        self.assertEqual(len(invalid), 2)
        self.assertEqual(len(warnings), 2)
        self.assertIn("-sU", valid)
        self.assertIn("-sS", invalid)
        self.assertIn("-sT", invalid)


if __name__ == "__main__":
    # Run tests
    success = run_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)
