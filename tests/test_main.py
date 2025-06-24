"""Tests for main CLI functionality."""

import pytest
from typer.testing import CliRunner
from pathlib import Path
import tempfile
import os

from src.loglens.main import app


class TestCLI:
    """Test CLI functionality."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_help_command(self) -> None:
        """Test that help command works."""
        result = self.runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "LogLens" in result.stdout
        assert "Log Analysis Tool" in result.stdout

    def test_version_command(self) -> None:
        """Test version command."""
        result = self.runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "LogLens version:" in result.stdout
        assert "0.1.0" in result.stdout

    def test_analyze_command_help(self) -> None:
        """Test analyze command help."""
        result = self.runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "Analyze a log file" in result.stdout
        assert "log_file" in result.stdout

    def test_analyze_command_with_valid_file(self) -> None:
        """Test analyze command with a valid log file."""
        # Create a temporary log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("127.0.0.1 - - [01/Jan/2023:00:00:00 +0000] \"GET /test HTTP/1.1\" 200 1234\n")
            temp_log_path = f.name

        try:
            result = self.runner.invoke(app, ["analyze", temp_log_path])
            assert result.exit_code == 0
            assert "LogLens Analysis starting" in result.stdout
            assert "Detection analysis complete" in result.stdout
        finally:
            # Clean up temp file
            os.unlink(temp_log_path)

    def test_analyze_command_with_nonexistent_file(self) -> None:
        """Test analyze command with non-existent file."""
        result = self.runner.invoke(app, ["analyze", "nonexistent_file.log"])
        assert result.exit_code != 0
        # Typer should handle file validation and show appropriate error

    def test_analyze_command_with_output_option(self) -> None:
        """Test analyze command with output option."""
        # Create a temporary log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("127.0.0.1 - - [01/Jan/2023:00:00:00 +0000] \"GET /test HTTP/1.1\" 200 1234\n")
            temp_log_path = f.name

        try:
            result = self.runner.invoke(app, ["analyze", temp_log_path, "--output", "report.txt"])
            assert result.exit_code == 0
            assert "Report will be saved to: report.txt" in result.stdout
        finally:
            os.unlink(temp_log_path)

    def test_analyze_command_with_verbose_option(self) -> None:
        """Test analyze command with verbose option."""
        # Create a temporary log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("127.0.0.1 - - [01/Jan/2023:00:00:00 +0000] \"GET /test HTTP/1.1\" 200 1234\n")
            temp_log_path = f.name

        try:
            result = self.runner.invoke(app, ["analyze", temp_log_path, "--verbose"])
            assert result.exit_code == 0
            assert f"Analyzing log file: {temp_log_path}" in result.stdout
        finally:
            os.unlink(temp_log_path) 