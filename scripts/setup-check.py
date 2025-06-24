#!/usr/bin/env python3
"""
LogLens Setup Verification Script

Run this script to verify your development environment is properly configured.
"""

import sys
import subprocess
import shutil
from pathlib import Path


def check_python_version():
    """Check if Python version is 3.11 or higher."""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 11):
        print(f"❌ Python 3.11+ required, found {sys.version_info.major}.{sys.version_info.minor}")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True


def check_poetry():
    """Check if Poetry is installed and accessible."""
    print("\n📦 Checking Poetry installation...")
    
    if not shutil.which("poetry"):
        print("❌ Poetry not found. Please install Poetry: https://python-poetry.org/docs/#installation")
        return False
    
    try:
        result = subprocess.run(["poetry", "--version"], capture_output=True, text=True, check=True)
        version = result.stdout.strip()
        print(f"✅ {version}")
        return True
    except subprocess.CalledProcessError:
        print("❌ Poetry installation appears broken")
        return False


def check_git():
    """Check if Git is installed."""
    print("\n🗂️  Checking Git installation...")
    
    if not shutil.which("git"):
        print("❌ Git not found. Please install Git")
        return False
    
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, text=True, check=True)
        version = result.stdout.strip()
        print(f"✅ {version}")
        return True
    except subprocess.CalledProcessError:
        print("❌ Git installation appears broken")
        return False


def check_project_structure():
    """Check if we're in the correct project directory."""
    print("\n📁 Checking project structure...")
    
    required_files = [
        "pyproject.toml",
        "src/loglens/main.py",
        "src/loglens/models.py",
        "tests/test_main.py",
        "README.md",
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ Missing required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("Make sure you're in the LogLens project root directory")
        return False
    
    print("✅ Project structure looks good")
    return True


def check_dependencies():
    """Check if Poetry dependencies are installed."""
    print("\n📚 Checking dependencies...")
    
    try:
        result = subprocess.run(
            ["poetry", "run", "python", "-c", "import loglens; print('LogLens module available')"],
            capture_output=True,
            text=True,
            check=True
        )
        print("✅ LogLens module installed and importable")
        return True
    except subprocess.CalledProcessError:
        print("❌ LogLens dependencies not installed or importable")
        print("Run: poetry install")
        return False


def run_quick_tests():
    """Run a subset of tests to verify basic functionality."""
    print("\n🧪 Running quick tests...")
    
    try:
        result = subprocess.run(
            ["poetry", "run", "pytest", "tests/test_main.py", "-v", "--tb=short"],
            capture_output=True,
            text=True,
            check=True
        )
        print("✅ Basic tests passing")
        return True
    except subprocess.CalledProcessError as e:
        print("❌ Some tests failed")
        print("Run full test suite: poetry run pytest")
        return False


def check_cli():
    """Check if CLI is working."""
    print("\n🖥️  Checking CLI functionality...")
    
    try:
        result = subprocess.run(
            ["poetry", "run", "loglens", "--help"],
            capture_output=True,
            text=True,
            check=True
        )
        print("✅ CLI working correctly")
        return True
    except subprocess.CalledProcessError:
        print("❌ CLI not working")
        return False


def main():
    """Main setup verification function."""
    print("🔍 LogLens Development Environment Setup Check")
    print("=" * 50)
    
    checks = [
        check_python_version,
        check_poetry,
        check_git,
        check_project_structure,
        check_dependencies,
        check_cli,
        run_quick_tests,
    ]
    
    passed = 0
    failed = 0
    
    for check in checks:
        try:
            if check():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Error during check: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Setup Check Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n🎉 Your development environment is ready!")
        print("\nNext steps:")
        print("1. poetry run loglens --help")
        print("2. poetry run pytest")
        print("3. Start contributing to LogLens!")
    else:
        print("\n⚠️  Please fix the issues above before proceeding")
        print("\nFor help, see:")
        print("- README.md")
        print("- CONTRIBUTING.md")
        print("- https://github.com/your-org/loglens/issues")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 