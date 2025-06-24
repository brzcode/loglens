"""Tests for the reporting service module."""

import pytest
from datetime import datetime
from pathlib import Path
from ipaddress import IPv4Address
import tempfile

from src.loglens.models import Finding, ParsedLogEntry, DetectionResult
from src.loglens.services.reporting import ReportingService, OutputConfig, RiskCalculator


def test_risk_calculator():
    """Test basic risk calculation functionality."""
    log_entry = ParsedLogEntry(
        ip_address=IPv4Address("192.168.1.100"),
        timestamp=datetime(2024, 1, 15, 10, 30, 45),
        request_line="GET /admin/login HTTP/1.1",
        status_code=401,
        raw_line='192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 401 2326'
    )
    
    finding = Finding(
        log_entry=log_entry,
        finding_type="Brute Force Attack",
        description="Multiple failed login attempts detected",
        risk_score=75
    )
    
    calculator = RiskCalculator()
    composite_risk = calculator.calculate_composite_risk(finding)
    
    assert isinstance(composite_risk, int)
    assert 0 <= composite_risk <= 100


def test_reporting_service_basic():
    """Test basic reporting service functionality."""
    log_entry = ParsedLogEntry(
        ip_address=IPv4Address("192.168.1.100"),
        timestamp=datetime(2024, 1, 15, 10, 30, 45),
        request_line="GET /admin/login HTTP/1.1",
        status_code=401,
        raw_line='192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 401 2326'
    )
    
    finding = Finding(
        log_entry=log_entry,
        finding_type="Test Finding",
        description="Test description",
        risk_score=50
    )
    
    detection_result = DetectionResult(
        findings=[finding],
        total_entries_analyzed=100
    )
    detection_result.update_statistics()
    
    service = ReportingService()
    report = service.generate_report(detection_result)
    
    assert "LOGLENS SECURITY ANALYSIS REPORT" in report
    assert "Executive Summary:" in report


def test_empty_report():
    """Test report generation with no findings."""
    detection_result = DetectionResult(
        findings=[],
        total_entries_analyzed=100
    )
    detection_result.update_statistics()
    
    service = ReportingService()
    report = service.generate_report(detection_result)
    
    assert "CLEAN LOG ANALYSIS" in report
    assert "No security threats detected" in report


def test_file_output():
    """Test saving report to file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / "test_report.txt"
        
        detection_result = DetectionResult(findings=[], total_entries_analyzed=100)
        detection_result.update_statistics()
        
        service = ReportingService()
        report = service.generate_report(detection_result)
        service.save_report(report, file_path)
        
        assert file_path.exists()
        content = file_path.read_text(encoding='utf-8')
        assert len(content) > 0 