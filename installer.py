#!/usr/bin/env python3
import sys
import shutil
import subprocess
from pathlib import Path
import os

MIN_PYTHON = (3, 7)

REQUIREMENTS = [
    "tqdm",
    "colorama",
    "pyfiglet",
    "prettytable",
    "pytest-cov"
]

def check_python_version():
    if sys.version_info < MIN_PYTHON:
        print(f"❌ Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or higher is required.")
        sys.exit(1)

def check_apt_available():
    return shutil.which("apt") is not None

def create_requirements_file():
    req_file = Path("requirements.txt")
    if not req_file.exists():
        with open(req_file, "w") as f:
            for pkg in REQUIREMENTS:
                f.write(pkg + "\n")
        print("✅ Created requirements.txt with necessary dependencies.")
    else:
        print("✅ requirements.txt already exists.")

def print_venv_guide(venv_path):
    print("\n💡 Virtual Environment Usage Guide:")
    print(f"1. Activate the venv: source {venv_path}/bin/activate")
    print("2. Install dependencies: pip install -r requirements.txt")
    print("3. Run the scanner: python fnw.py")
    print("4. Deactivate the venv when done: deactivate\n")

def create_venv(venv_path):
    print(f"\n🐍 Creating virtual environment at {venv_path} ...")
    subprocess.run([sys.executable, "-m", "venv", str(venv_path)])
    subprocess.run([str(venv_path / "bin" / "python"), "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.run([str(venv_path / "bin" / "pip"), "install", "-r", "requirements.txt"])
    print("✅ Dependencies installed inside the virtual environment.")
    print_venv_guide(venv_path)
    # Offer immediate activation
    activate_now = input("Would you like to activate the venv now? (y/n): ").strip().lower()
    if activate_now == "y":
        shell = os.environ.get("SHELL", "/bin/bash")
        subprocess.run([shell, "-i", "-c", f"source {venv_path}/bin/activate && exec {shell}"])
    else:
        print(f"You can activate it later with: source {venv_path}/bin/activate\n")

def check_pytest_installed():
    try:
        import pytest
        return True
    except ImportError:
        return False

def detect_package_manager():
    managers = []
    if shutil.which("pip"):
        managers.append("pip")
    if shutil.which("apt"):
        managers.append("apt")
    if shutil.which("brew"):
        managers.append("brew")
    if shutil.which("conda"):
        managers.append("conda")
    return managers

def install_pytest(manager):
    print(f"Installing pytest using {manager} ...")
    if manager == "pip":
        subprocess.run([sys.executable, "-m", "pip", "install", "pytest"])
    elif manager == "apt":
        subprocess.run(["sudo", "apt", "install", "-y", "python3-pytest"])
    elif manager == "brew":
        subprocess.run(["brew", "install", "pytest"])
    elif manager == "conda":
        subprocess.run(["conda", "install", "-y", "pytest"])
    print("✅ pytest installed.")

def main():
    check_python_version()
    print("🛠 Fancy Nmap Wrapper Installer\n")

    # Step 0: Ensure requirements.txt exists
    create_requirements_file()

    # Step 1: venv vs apt
    apt_available = check_apt_available()
    if apt_available:
        print("Choose installation method:")
        print("1) Python Virtual Environment (recommended)")
        print("2) Install system packages via apt (not recommended)")
        choice = input("Enter 1 or 2: ").strip()
    else:
        print("APT not found. Only Python Virtual Environment (recommended) is available.")
        choice = "1"

    if choice == "1":
        pref_path = input("Enter preferred directory for venv (leave blank for ~/.venv): ").strip()
        if pref_path:
            base_path = Path(pref_path).expanduser()
            if not base_path.exists():
                print(f"❌ Directory {base_path} does not exist. Exiting.")
                sys.exit(1)
        else:
            base_path = Path.home() / ".venv"
        venv_path = base_path / "fnw"
        venv_path.mkdir(parents=True, exist_ok=True)
        auto_create = input(f"Do you want to automatically create the venv and install dependencies at {venv_path}? (y/n): ").strip().lower()
        if auto_create == 'y':
            create_venv(venv_path)
        else:
            print(f"\nSkipping automatic creation. You can create it later using: python3 -m venv {venv_path}")
            print_venv_guide(venv_path)
    elif choice == "2" and apt_available:
        print("\nInstalling packages via apt...")
        packages = ["python3-tqdm", "python3-colorama", "python3-pyfiglet", "python3-pytest"]
        subprocess.run(["sudo", "apt", "update"])
        subprocess.run(["sudo", "apt", "install", "-y"] + packages)
        print("✅ Packages installed via apt.")
    else:
        print("❌ Invalid choice or apt not available. Exiting installer.")
        sys.exit(1)

    # Step 2: Check pytest
    if not check_pytest_installed():
        managers = detect_package_manager()
        if managers:
            for mgr in managers:
                choice = input(f"pytest is not installed. Install it using {mgr}? (y/n): ").strip().lower()
                if choice == "y":
                    install_pytest(mgr)
                    break
            else:
                print("No installation performed. Please install pytest manually.")
        else:
            print("No package managers detected. Please install pytest manually.")
    else:
        print("✅ pytest is already installed.")

    print("✅ Installer finished.")

if __name__ == "__main__":
    main()
