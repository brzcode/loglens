"""Tests for the detection service."""

import pytest
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from typing import List

from src.loglens.models import ParsedLogEntry, Finding, DetectionResult, DetectionStatistics
from src.loglens.services.detection import (
    BaseDetector, KeywordDetector, FrequencyDetector, DetectionEngine,
    TimeWindowAnalyzer, ScanningDetector, BehavioralDetector, GeographicDetector
)


@pytest.fixture
def sample_log_entry():
    """Create a sample parsed log entry for testing."""
    return ParsedLogEntry(
        ip_address=IPv4Address("192.168.1.100"),
        timestamp=datetime(2024, 1, 15, 10, 30, 45),
        request_line="GET /index.html HTTP/1.1",
        status_code=200,
        raw_line='192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234',
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        bytes_sent=1234,
        referer=None,
        remote_user=None
    )


@pytest.fixture
def sql_injection_entries():
    """Create log entries with SQL injection patterns."""
    base_time = datetime.now()
    return [
        ParsedLogEntry(
            ip_address=IPv4Address("192.168.1.1"),
            timestamp=base_time,
            request_line="GET /login.php?username=admin' UNION SELECT * FROM users-- HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="sqlmap/1.0",
            bytes_sent=500
        ),
        ParsedLogEntry(
            ip_address=IPv4Address("192.168.1.2"),
            timestamp=base_time + timedelta(minutes=1),
            request_line="GET /app.php?id=1 OR 1=1 HTTP/1.1",
            status_code=500,
            raw_line="test line",
            user_agent="Mozilla/5.0",
            bytes_sent=200
        )
    ]


@pytest.fixture
def command_execution_entries():
    """Create log entries with command execution patterns."""
    base_time = datetime.now()
    return [
        ParsedLogEntry(
            ip_address=IPv4Address("10.0.0.1"),
            timestamp=base_time,
            request_line="GET /shell.php?cmd=bash%20-c%20whoami HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="curl/7.68.0",
            bytes_sent=100
        ),
        ParsedLogEntry(
            ip_address=IPv4Address("10.0.0.2"),
            timestamp=base_time + timedelta(minutes=1),
            request_line="POST /upload.php HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="wget/1.20.3",
            bytes_sent=300
        )
    ]


@pytest.fixture
def xss_entries():
    """Create log entries with XSS patterns."""
    base_time = datetime.now()
    return [
        ParsedLogEntry(
            ip_address=IPv4Address("172.16.0.1"),
            timestamp=base_time,
            request_line="GET /comment.php?msg=<script>alert('XSS')</script> HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="Mozilla/5.0",
            bytes_sent=400
        )
    ]


@pytest.fixture
def failed_login_entries():
    """Create log entries showing failed login attempts."""
    base_time = datetime.now()
    ip = IPv4Address("203.0.113.10")
    entries = []
    
    # Create 6 failed login attempts from same IP
    for i in range(6):
        entries.append(ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(minutes=i),
            request_line=f"POST /login.php HTTP/1.1",
            status_code=401,  # Unauthorized
            raw_line="test line",
            user_agent="Mozilla/5.0",
            bytes_sent=50
        ))
    
    return entries


@pytest.fixture
def high_frequency_entries():
    """Create log entries showing high-frequency requests."""
    base_time = datetime.now()
    ip = IPv4Address("198.51.100.5")
    entries = []
    
    # Create 55 requests from same IP (above threshold of 50)
    for i in range(55):
        entries.append(ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(seconds=i * 2),
            request_line=f"GET /api/data?page={i % 10} HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="bot/1.0",
            bytes_sent=150
        ))
    
    return entries


class TestBaseDetector:
    """Tests for BaseDetector abstract class."""
    
    def test_cannot_instantiate_base_detector(self):
        """Test that BaseDetector cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseDetector()
    
    def test_statistics_initialization(self):
        """Test that detectors initialize with empty statistics."""
        detector = KeywordDetector()
        stats = detector.get_statistics()
        assert stats.total_entries_processed == 0
        assert stats.total_findings == 0
        assert stats.processing_errors == 0


class TestKeywordDetector:
    """Tests for KeywordDetector."""
    
    def test_initialization(self):
        """Test KeywordDetector initialization."""
        detector = KeywordDetector()
        assert detector._compiled_patterns is not None
        assert 'sql_injection' in detector._compiled_patterns
        assert 'command_execution' in detector._compiled_patterns
        assert 'xss' in detector._compiled_patterns
    
    def test_sql_injection_detection(self, sql_injection_entries):
        """Test detection of SQL injection patterns."""
        detector = KeywordDetector()
        findings = list(detector.detect_patterns(iter(sql_injection_entries)))
        
        assert len(findings) >= 2  # Should detect patterns in both entries
        
        # Check for UNION SELECT detection
        union_findings = [f for f in findings if 'union' in f.description.lower()]
        assert len(union_findings) > 0
        assert union_findings[0].risk_score >= 80  # High risk
        assert union_findings[0].finding_type == "Keyword Match - Sql Injection"
        
        # Check statistics
        stats = detector.get_statistics()
        assert stats.total_entries_processed == 2
        assert stats.total_findings >= 2
        assert stats.high_risk_count > 0
    
    def test_command_execution_detection(self, command_execution_entries):
        """Test detection of command execution patterns."""
        detector = KeywordDetector()
        findings = list(detector.detect_patterns(iter(command_execution_entries)))
        
        assert len(findings) >= 1  # Should detect patterns
        
        # Check for bash command detection
        bash_findings = [f for f in findings if 'bash' in f.description.lower()]
        assert len(bash_findings) > 0
        assert bash_findings[0].risk_score >= 80
        assert bash_findings[0].finding_type == "Keyword Match - Command Execution"
    
    def test_xss_detection(self, xss_entries):
        """Test detection of XSS patterns."""
        detector = KeywordDetector()
        findings = list(detector.detect_patterns(iter(xss_entries)))
        
        assert len(findings) >= 1  # Should detect script tag
        
        # Check for script tag detection
        script_findings = [f for f in findings if 'script' in f.description.lower()]
        assert len(script_findings) > 0
        assert script_findings[0].risk_score >= 80
        assert script_findings[0].finding_type == "Keyword Match - Xss"
    
    def test_clean_logs_no_detection(self, sample_log_entry):
        """Test that clean log entries don't trigger detections."""
        detector = KeywordDetector()
        findings = list(detector.detect_patterns(iter([sample_log_entry])))
        
        assert len(findings) == 0
        
        stats = detector.get_statistics()
        assert stats.total_entries_processed == 1
        assert stats.total_findings == 0
    
    def test_url_decoding(self):
        """Test that URL-encoded attacks are properly decoded and detected."""
        entry = ParsedLogEntry(
            ip_address=IPv4Address("192.168.1.1"),
            timestamp=datetime.now(),
            request_line="GET /test.php?q=union%20select%20*%20from%20users HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="Mozilla/5.0",
            bytes_sent=100
        )
        
        detector = KeywordDetector()
        findings = list(detector.detect_patterns(iter([entry])))
        
        assert len(findings) > 0
        assert findings[0].risk_score >= 80
        assert 'union' in findings[0].description.lower()


class TestFrequencyDetector:
    """Tests for FrequencyDetector."""
    
    def test_initialization(self):
        """Test FrequencyDetector initialization with default thresholds."""
        detector = FrequencyDetector()
        assert detector.failed_login_threshold == 5
        assert detector.high_frequency_threshold == 50
    
    def test_failed_login_detection(self, failed_login_entries):
        """Test detection of failed login patterns."""
        detector = FrequencyDetector()
        findings = list(detector.detect_patterns(iter(failed_login_entries)))
        
        # Should detect failed login pattern (6 attempts > threshold of 5)
        failed_login_findings = [f for f in findings if f.finding_type == "Failed Login Pattern"]
        assert len(failed_login_findings) > 0
        
        finding = failed_login_findings[0]
        assert finding.risk_score >= 70  # Should be high risk
        assert "6 failed login attempts" in finding.description
        assert finding.enrichment_data['failed_attempt_count'] == 6
    
    def test_high_frequency_detection(self, high_frequency_entries):
        """Test detection of high-frequency request patterns."""
        detector = FrequencyDetector()
        findings = list(detector.detect_patterns(iter(high_frequency_entries)))
        
        # Should detect high frequency pattern (55 requests > threshold of 50)
        freq_findings = [f for f in findings if f.finding_type == "High Request Frequency"]
        assert len(freq_findings) > 0
        
        finding = freq_findings[0]
        assert finding.risk_score >= 50
        assert "55 requests" in finding.description
        assert finding.enrichment_data['total_requests'] == 55
    
    def test_below_threshold_no_detection(self):
        """Test that requests below thresholds don't trigger detections."""
        detector = FrequencyDetector()
        
        # Create 3 entries (below failed login threshold of 5)
        entries = []
        for i in range(3):
            entry = ParsedLogEntry(
                ip_address=IPv4Address("192.168.1.1"),
                timestamp=datetime.now() + timedelta(minutes=i),
                request_line="POST /login.php HTTP/1.1",
                status_code=401,
                raw_line="test line",
                user_agent="Mozilla/5.0",
                bytes_sent=50
            )
            entries.append(entry)
        
        findings = list(detector.detect_patterns(iter(entries)))
        assert len(findings) == 0


class TestDetectionEngine:
    """Tests for DetectionEngine orchestrator."""
    
    def test_initialization(self):
        """Test DetectionEngine initialization."""
        engine = DetectionEngine()
        assert engine.keyword_detector is not None
        assert engine.frequency_detector is not None
        assert len(engine.detectors) == 2
    
    def test_analyze_entries_empty_list(self):
        """Test analyzing empty list of entries."""
        engine = DetectionEngine()
        result = engine.analyze_entries([])
        
        assert result.total_entries_analyzed == 0
        assert result.total_findings == 0
        assert len(result.findings) == 0
    
    def test_analyze_entries_with_attacks(self, sql_injection_entries, failed_login_entries):
        """Test analyzing entries with multiple attack types."""
        engine = DetectionEngine()
        all_entries = sql_injection_entries + failed_login_entries
        
        result = engine.analyze_entries(all_entries)
        
        assert result.total_entries_analyzed == len(all_entries)
        assert result.total_findings > 0
        assert len(result.findings) > 0
        
        # Should have both keyword and frequency findings
        keyword_findings = [f for f in result.findings if "Keyword Match" in f.finding_type]
        frequency_findings = [f for f in result.findings if "Pattern" in f.finding_type or "Frequency" in f.finding_type]
        
        assert len(keyword_findings) > 0
        assert len(frequency_findings) > 0
    
    def test_clean_entries_no_findings(self, sample_log_entry):
        """Test that clean entries produce no findings."""
        engine = DetectionEngine()
        result = engine.analyze_entries([sample_log_entry])
        
        assert result.total_entries_analyzed == 1
        assert result.total_findings == 0
        assert len(result.findings) == 0


class TestDetectionModels:
    """Tests for detection-related data models."""
    
    def test_finding_model_validation(self, sample_log_entry):
        """Test Finding model validation."""
        finding = Finding(
            log_entry=sample_log_entry,
            finding_type="Test Finding",
            description="Test description",
            risk_score=85,
            enrichment_data={'test': 'data'}
        )
        
        assert finding.log_entry == sample_log_entry
        assert finding.finding_type == "Test Finding"
        assert finding.description == "Test description"
        assert finding.risk_score == 85
        assert finding.enrichment_data == {'test': 'data'}
        assert finding.detected_at is not None
    
    def test_finding_default_risk_score(self, sample_log_entry):
        """Test Finding model with default risk score."""
        finding = Finding(
            log_entry=sample_log_entry,
            finding_type="Test Finding",
            description="Test description"
        )
        
        assert finding.risk_score == 50  # Default value
    
    def test_detection_result_statistics_update(self, sample_log_entry):
        """Test DetectionResult statistics calculation."""
        result = DetectionResult()
        
        # Add findings with different risk scores
        findings = [
            Finding(log_entry=sample_log_entry, finding_type="High", description="High risk", risk_score=95),
            Finding(log_entry=sample_log_entry, finding_type="Medium", description="Medium risk", risk_score=65),
            Finding(log_entry=sample_log_entry, finding_type="Low", description="Low risk", risk_score=35),
            Finding(log_entry=sample_log_entry, finding_type="Info", description="Info level", risk_score=15),
        ]
        
        result.findings = findings
        result.update_statistics()
        
        assert result.total_findings == 4
        assert result.high_risk_findings == 1
        assert result.medium_risk_findings == 1
        assert result.low_risk_findings == 1
        assert result.info_findings == 1
    
    def test_detection_statistics_success_rate(self):
        """Test DetectionStatistics success rate calculation."""
        stats = DetectionStatistics()
        stats.total_entries_processed = 100
        stats.processing_errors = 5
        
        assert stats.success_rate == 95.0
        
        # Test zero division
        stats.total_entries_processed = 0
        assert stats.success_rate == 0.0
    
    def test_detection_statistics_processing_time(self):
        """Test DetectionStatistics processing time calculation."""
        stats = DetectionStatistics()
        start_time = datetime.now()
        stats.start_time = start_time
        stats.end_time = start_time + timedelta(seconds=2.5)
        
        assert abs(stats.processing_time - 2.5) < 0.1  # Allow small floating point differences


# Additional test fixtures for advanced frequency detection

@pytest.fixture
def time_windowed_brute_force_entries():
    """Create log entries for time-windowed brute force testing."""
    base_time = datetime.now()
    ip = IPv4Address("192.168.1.50")
    entries = []
    
    # Create 7 failed login attempts within 1 minute
    for i in range(7):
        entries.append(ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(seconds=i * 8),  # 8 seconds apart
            request_line="POST /login.php HTTP/1.1",
            status_code=401,
            raw_line="test line",
            user_agent="Mozilla/5.0",
            bytes_sent=50
        ))
    
    return entries


@pytest.fixture
def scanning_entries():
    """Create log entries for scanning pattern testing."""
    base_time = datetime.now()
    ip = IPv4Address("10.0.0.100")
    entries = []
    
    # Create requests to many unique paths in short time
    paths = ["/admin/", "/backup/", "/config/", "/wp-admin/", "/phpmyadmin/", 
             "/manager/", "/test/", "/tmp/", "/uploads/", "/login/", 
             "/api/", "/secret/", "/private/", "/debug/", "/panel/"]
    
    for i, path in enumerate(paths):
        entries.append(ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(seconds=i * 5),
            request_line=f"GET {path} HTTP/1.1",
            status_code=404,  # Most scanning produces 404s
            raw_line="test line",
            user_agent="gobuster/3.0",
            bytes_sent=150
        ))
    
    return entries


@pytest.fixture
def user_agent_rotation_entries():
    """Create log entries for user agent rotation testing."""
    base_time = datetime.now()
    ip = IPv4Address("172.16.0.50")
    entries = []
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Android 10; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
        "curl/7.68.0",
        "python-requests/2.25.1"
    ]
    
    for i, ua in enumerate(user_agents):
        entries.append(ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(seconds=i * 10),
            request_line=f"GET /api/data HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent=ua,
            bytes_sent=200
        ))
    
    return entries


@pytest.fixture
def dos_burst_entries():
    """Create log entries for DoS burst testing."""
    base_time = datetime.now()
    ip = IPv4Address("203.0.113.200")
    entries = []
    
    # Create 120 requests within 30 seconds (burst pattern)
    for i in range(120):
        entries.append(ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(milliseconds=i * 250),  # 4 per second
            request_line=f"GET /api/status HTTP/1.1",
            status_code=200,
            raw_line="test line",
            user_agent="bot/1.0",
            bytes_sent=100
        ))
    
    return entries


@pytest.fixture
def geographic_entries():
    """Create log entries with geographic enrichment data."""
    base_time = datetime.now()
    ip = IPv4Address("198.51.100.100")
    entries = []
    
    countries = ["US", "CN", "RU", "BR"]
    
    for i, country in enumerate(countries):
        entry = ParsedLogEntry(
            ip_address=ip,
            timestamp=base_time + timedelta(minutes=i * 10),
            request_line=f"GET /login.php HTTP/1.1",
            status_code=401,
            raw_line="test line",
            user_agent="Mozilla/5.0",
            bytes_sent=50
        )
        
        # Add enrichment data with geographic information
        entry.enrichment_data = {
            "ip_reputation": {
                "abuseipdb": {
                    "country_code": country,
                    "abuse_confidence": 75 if country in ["CN", "RU"] else 25,
                    "is_public": True
                }
            }
        }
        
        entries.append(entry)
    
    return entries


class TestTimeWindowAnalyzer:
    """Tests for TimeWindowAnalyzer."""
    
    def test_initialization(self):
        """Test TimeWindowAnalyzer initialization."""
        analyzer = TimeWindowAnalyzer()
        assert '1min' in analyzer.time_windows
        assert analyzer.time_windows['1min'] == 60
        assert analyzer.time_windows['5min'] == 300
    
    def test_analyze_empty_entries(self):
        """Test analyzer with empty entries."""
        analyzer = TimeWindowAnalyzer()
        result = analyzer.analyze_time_windows([])
        assert result == {'1min': {}, '5min': {}, '15min': {}, '1hour': {}}
    
    def test_time_window_analysis(self, time_windowed_brute_force_entries):
        """Test time window analysis with brute force entries."""
        analyzer = TimeWindowAnalyzer()
        result = analyzer.analyze_time_windows(time_windowed_brute_force_entries, ['1min'])
        
        ip_str = str(time_windowed_brute_force_entries[0].ip_address)
        assert ip_str in result['1min']
        
        ip_data = result['1min'][ip_str]
        assert ip_data['max_failed_logins_in_window'] >= 7
        assert ip_data['total_requests'] == 7


class TestScanningDetector:
    """Tests for ScanningDetector."""
    
    def test_initialization(self):
        """Test ScanningDetector initialization."""
        detector = ScanningDetector()
        assert detector.unique_paths_threshold == 10
        assert detector.scan_time_window == 300
        assert len(detector._compiled_scan_patterns) > 0
    
    def test_path_enumeration_detection(self, scanning_entries):
        """Test detection of path enumeration patterns."""
        detector = ScanningDetector()
        findings = list(detector.detect_patterns(iter(scanning_entries)))
        
        # Should detect path enumeration
        path_enum_findings = [f for f in findings if "Path Enumeration" in f.finding_type]
        assert len(path_enum_findings) > 0
        
        finding = path_enum_findings[0]
        assert finding.risk_score >= 60
        assert finding.enrichment_data['pattern_type'] == 'path_enumeration'
        assert finding.enrichment_data['total_unique_paths'] >= 10
    
    def test_scanning_tool_signature_detection(self, scanning_entries):
        """Test detection of scanning tool signatures."""
        detector = ScanningDetector()
        findings = list(detector.detect_patterns(iter(scanning_entries)))
        
        # Should detect gobuster signature
        tool_findings = [f for f in findings if "Tool Signature" in f.finding_type]
        assert len(tool_findings) > 0
        
        finding = tool_findings[0]
        assert finding.risk_score >= 75
        assert 'gobuster' in finding.enrichment_data['tool_signatures']


class TestBehavioralDetector:
    """Tests for BehavioralDetector."""
    
    def test_initialization(self):
        """Test BehavioralDetector initialization."""
        detector = BehavioralDetector()
        assert detector.dos_burst_threshold == 100
        assert detector.ua_rotation_threshold == 5
        assert '30sec' in detector.burst_time_windows
    
    def test_dos_burst_detection(self, dos_burst_entries):
        """Test detection of DoS burst patterns."""
        detector = BehavioralDetector()
        findings = list(detector.detect_patterns(iter(dos_burst_entries)))
        
        burst_findings = [f for f in findings if "DoS Burst" in f.finding_type]
        assert len(burst_findings) > 0
        
        finding = burst_findings[0]
        assert finding.risk_score >= 80
        assert finding.enrichment_data['max_burst_requests'] >= 100
    
    def test_user_agent_rotation_detection(self, user_agent_rotation_entries):
        """Test detection of user agent rotation."""
        detector = BehavioralDetector()
        findings = list(detector.detect_patterns(iter(user_agent_rotation_entries)))
        
        ua_findings = [f for f in findings if "User Agent Rotation" in f.finding_type]
        assert len(ua_findings) > 0
        
        finding = ua_findings[0]
        assert finding.risk_score >= 65
        assert finding.enrichment_data['unique_user_agents'] >= 5


class TestGeographicDetector:
    """Tests for GeographicDetector."""
    
    def test_initialization(self):
        """Test GeographicDetector initialization."""
        detector = GeographicDetector()
        assert detector.geo_change_threshold == 3
        assert 'CN' in detector.high_risk_countries
        assert detector.high_risk_countries['CN'] == 1.3
    
    def test_rapid_geographic_changes_detection(self, geographic_entries):
        """Test detection of rapid geographic changes."""
        detector = GeographicDetector()
        findings = list(detector.detect_patterns(iter(geographic_entries)))
        
        geo_findings = [f for f in findings if "Rapid Geographic" in f.finding_type]
        assert len(geo_findings) > 0
        
        finding = geo_findings[0]
        assert finding.risk_score >= 85
        assert len(finding.enrichment_data['unique_countries']) >= 3
    
    def test_high_risk_country_activity_detection(self, geographic_entries):
        """Test detection of high-risk country activity."""
        detector = GeographicDetector()
        findings = list(detector.detect_patterns(iter(geographic_entries)))
        
        high_risk_findings = [f for f in findings if "High-Risk Country" in f.finding_type]
        # Should detect activity from CN and RU (high-risk countries)
        assert len(high_risk_findings) >= 1
        
        finding = high_risk_findings[0]
        assert finding.risk_score >= 65
        assert finding.enrichment_data['country'] in ['CN', 'RU']


class TestEnhancedDetectionEngine:
    """Tests for enhanced DetectionEngine with all detectors."""
    
    def test_enhanced_initialization(self):
        """Test DetectionEngine initialization with all detectors."""
        engine = DetectionEngine(
            enable_advanced_frequency=True,
            enable_scanning_detection=True,
            enable_behavioral_analysis=True,
            enable_geographic_analysis=True
        )
        
        assert len(engine.detectors) == 5  # All detectors enabled
        assert engine.scanning_detector is not None
        assert engine.behavioral_detector is not None
        assert engine.geographic_detector is not None
    
    def test_selective_detector_disabling(self):
        """Test selective disabling of detectors."""
        engine = DetectionEngine(
            enable_scanning_detection=False,
            enable_behavioral_analysis=False,
            enable_geographic_analysis=False
        )
        
        assert len(engine.detectors) == 2  # Only core detectors
        assert engine.scanning_detector is None
        assert engine.behavioral_detector is None
        assert engine.geographic_detector is None
    
    def test_enhanced_statistics(self, scanning_entries, user_agent_rotation_entries):
        """Test enhanced statistics from all detectors."""
        engine = DetectionEngine()
        
        # Combine different attack patterns
        all_entries = scanning_entries + user_agent_rotation_entries
        result = engine.analyze_entries(all_entries)
        
        stats = engine.get_combined_statistics()
        
        # Should have stats from multiple detectors
        assert 'keyword_detector' in stats
        assert 'frequency_detector' in stats
        assert 'scanning_detector' in stats
        assert 'behavioral_detector' in stats
        assert 'geographic_detector' in stats
        
        # Check detector summary
        summary = engine.get_detector_summary()
        assert summary['scanning_detector'] == 'enabled'
        assert summary['behavioral_detector'] == 'enabled'
    
    def test_backward_compatibility(self, sql_injection_entries, failed_login_entries):
        """Test that enhanced engine maintains backward compatibility."""
        engine = DetectionEngine()
        
        # Test with original attack patterns
        all_entries = sql_injection_entries + failed_login_entries
        result = engine.analyze_entries(all_entries)
        
        # Should still detect original patterns
        assert result.total_findings > 0
        
        # Should have findings from core detectors
        sql_findings = [f for f in result.findings if "SQL" in f.finding_type or "Sql" in f.finding_type]
        login_findings = [f for f in result.findings if "Login" in f.finding_type]
        
        assert len(sql_findings) > 0
        assert len(login_findings) > 0


if __name__ == "__main__":
    pytest.main([__file__]) 