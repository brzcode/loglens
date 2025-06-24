"""Tests for LogLens parsing services."""

import pytest
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import Mock

from src.loglens.models import RawLogLine, ParsedLogEntry
from src.loglens.services.parsing import ApacheParser, BaseParser, ParsedResult


class TestApacheParser:
    """Test cases for Apache log parser."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = ApacheParser()
    
    def test_parse_valid_clf_log(self):
        """Test parsing valid Common Log Format log line."""
        raw_line = RawLogLine(
            line_number=1,
            content='127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is True
        assert result.entry is not None
        assert result.error is None
        
        entry = result.entry
        assert str(entry.ip_address) == "127.0.0.1"
        assert entry.timestamp == datetime(2000, 10, 10, 13, 55, 36)
        assert entry.request_line == "GET /apache_pb.gif HTTP/1.0"
        assert entry.status_code == 200
        assert entry.bytes_sent == 2326
        assert entry.remote_user == "frank"
        assert entry.user_agent is None  # CLF doesn't include user agent
        assert entry.referer is None  # CLF doesn't include referer
    
    def test_parse_valid_combined_log(self):
        """Test parsing valid Combined Log Format log line."""
        raw_line = RawLogLine(
            line_number=1,
            content='127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is True
        assert result.entry is not None
        
        entry = result.entry
        assert str(entry.ip_address) == "127.0.0.1"
        assert entry.timestamp == datetime(2000, 10, 10, 13, 55, 36)
        assert entry.request_line == "GET /apache_pb.gif HTTP/1.0"
        assert entry.status_code == 200
        assert entry.bytes_sent == 2326
        assert entry.remote_user == "frank"
        assert entry.user_agent == "Mozilla/4.08 [en] (Win98; I ;Nav)"
        assert entry.referer == "http://www.example.com/start.html"
    
    def test_parse_log_with_dash_values(self):
        """Test parsing log line with dash (-) values for missing fields."""
        raw_line = RawLogLine(
            line_number=1,
            content='192.168.1.1 - - [01/Jan/2023:12:00:00 +0000] "POST /api/data HTTP/1.1" 404 - "-" "-"',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is True
        entry = result.entry
        assert str(entry.ip_address) == "192.168.1.1"
        assert entry.remote_user is None
        assert entry.bytes_sent is None
        assert entry.user_agent is None
        assert entry.referer is None
    
    def test_parse_ipv6_address(self):
        """Test parsing log line with IPv6 address."""
        raw_line = RawLogLine(
            line_number=1,
            content='2001:db8::1 - - [01/Jan/2023:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is True
        entry = result.entry
        assert isinstance(entry.ip_address, IPv6Address)
        assert str(entry.ip_address) == "2001:db8::1"
    
    def test_parse_various_status_codes(self):
        """Test parsing log lines with various HTTP status codes."""
        status_codes = [200, 301, 404, 500, 503]
        
        for status_code in status_codes:
            raw_line = RawLogLine(
                line_number=1,
                content=f'127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /test HTTP/1.1" {status_code} 1024',
                file_path="test.log",
                timestamp_read=datetime.now()
            )
            
            result = self.parser.parse_line(raw_line)
            assert result.success is True
            assert result.entry.status_code == status_code
    
    def test_parse_empty_line(self):
        """Test parsing empty log line."""
        raw_line = RawLogLine(
            line_number=1,
            content="",
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert result.error == "Empty log line"
    
    def test_parse_invalid_format(self):
        """Test parsing log line that doesn't match Apache format."""
        raw_line = RawLogLine(
            line_number=1,
            content="This is not a valid Apache log line",
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert "does not match Apache CLF or Combined format" in result.error
    
    def test_parse_invalid_ip_address(self):
        """Test parsing log line with invalid IP address."""
        raw_line = RawLogLine(
            line_number=1,
            content='999.999.999.999 - - [01/Jan/2023:12:00:00 +0000] "GET /test HTTP/1.1" 200 1024',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert "Invalid IP address" in result.error
    
    def test_parse_invalid_timestamp(self):
        """Test parsing log line with invalid timestamp."""
        raw_line = RawLogLine(
            line_number=1,
            content='127.0.0.1 - - [invalid-timestamp] "GET /test HTTP/1.1" 200 1024',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert "Invalid timestamp" in result.error
    
    def test_parse_invalid_status_code(self):
        """Test parsing log line with invalid status code."""
        raw_line = RawLogLine(
            line_number=1,
            content='127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /test HTTP/1.1" 999 1024',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert "Invalid HTTP status code" in result.error
    
    def test_parse_non_numeric_status_code(self):
        """Test parsing log line with non-numeric status code."""
        raw_line = RawLogLine(
            line_number=1,
            content='127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /test HTTP/1.1" OK 1024',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert "Invalid status code format" in result.error
    
    def test_parse_invalid_bytes_sent(self):
        """Test parsing log line with invalid bytes sent value."""
        raw_line = RawLogLine(
            line_number=1,
            content='127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /test HTTP/1.1" 200 invalid',
            file_path="test.log",
            timestamp_read=datetime.now()
        )
        
        result = self.parser.parse_line(raw_line)
        
        assert result.success is False
        assert "Invalid bytes sent format" in result.error
    
    def test_parse_batch_processing(self):
        """Test batch processing of multiple log lines."""
        raw_lines = [
            RawLogLine(
                line_number=1,
                content='127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /test1 HTTP/1.1" 200 1024',
                file_path="test.log",
                timestamp_read=datetime.now()
            ),
            RawLogLine(
                line_number=2,
                content='127.0.0.2 - - [01/Jan/2023:12:00:01 +0000] "GET /test2 HTTP/1.1" 404 512',
                file_path="test.log",
                timestamp_read=datetime.now()
            ),
            RawLogLine(
                line_number=3,
                content="Invalid log line",
                file_path="test.log",
                timestamp_read=datetime.now()
            ),
        ]
        
        results = list(self.parser.parse_batch(iter(raw_lines)))
        stats = self.parser.get_statistics()
        
        assert len(results) == 3
        assert stats.total_lines == 3
        assert stats.successful_parses == 2
        assert stats.errors == 1
        assert stats.success_rate == pytest.approx(66.67, rel=1e-2)
        
        # Check individual results
        assert results[0].success is True
        assert results[0].line_number == 1
        assert results[1].success is True
        assert results[1].line_number == 2
        assert results[2].success is False
        assert results[2].line_number == 3
    
    def test_apache_timestamp_parsing(self):
        """Test various Apache timestamp formats."""
        test_cases = [
            ("10/Oct/2000:13:55:36 -0700", datetime(2000, 10, 10, 13, 55, 36)),
            ("01/Jan/2023:00:00:00 +0000", datetime(2023, 1, 1, 0, 0, 0)),
            ("31/Dec/2022:23:59:59 +0100", datetime(2022, 12, 31, 23, 59, 59)),
        ]
        
        for timestamp_str, expected_dt in test_cases:
            result = self.parser._parse_apache_timestamp(timestamp_str)
            assert result == expected_dt
    
    def test_apache_timestamp_parsing_invalid(self):
        """Test invalid Apache timestamp formats."""
        invalid_timestamps = [
            "invalid-format",
            "2023-01-01 12:00:00",  # Wrong format
            "01/Jan/2023",  # Missing time
            "01/Jan/2023:25:00:00 +0000",  # Invalid hour
        ]
        
        for timestamp_str in invalid_timestamps:
            with pytest.raises(ValueError):
                self.parser._parse_apache_timestamp(timestamp_str)
    
    def test_get_supported_formats(self):
        """Test getting supported log formats."""
        formats = self.parser.get_supported_formats()
        assert "Common Log Format (CLF)" in formats
        assert "Combined Log Format" in formats
    
    def test_statistics_tracking(self):
        """Test statistics tracking during parsing."""
        self.parser.reset_statistics()
        stats = self.parser.get_statistics()
        
        assert stats.total_lines == 0
        assert stats.successful_parses == 0
        assert stats.errors == 0
        assert stats.success_rate == 0.0
        assert stats.processing_time == 0.0
    
    def test_real_world_apache_logs(self):
        """Test parsing real-world-like Apache log entries."""
        real_world_logs = [
            # Standard GET request
            '10.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://www.google.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
            
            # POST request with authentication
            '192.168.1.100 - admin [25/Dec/2023:10:00:01 +0000] "POST /api/login HTTP/1.1" 200 45',
            
            # Error request
            '203.0.113.195 - - [25/Dec/2023:10:00:02 +0000] "GET /nonexistent.php HTTP/1.1" 404 315 "-" "curl/7.68.0"',
            
            # Large file download
            '198.51.100.178 - - [25/Dec/2023:10:00:03 +0000] "GET /download/largefile.zip HTTP/1.1" 200 52428800',
        ]
        
        for i, log_content in enumerate(real_world_logs):
            raw_line = RawLogLine(
                line_number=i+1,
                content=log_content,
                file_path="access.log",
                timestamp_read=datetime.now()
            )
            
            result = self.parser.parse_line(raw_line)
            assert result.success is True, f"Failed to parse line {i+1}: {result.error}"
            
            entry = result.entry
            assert entry.ip_address is not None
            assert entry.timestamp is not None
            assert entry.status_code in range(100, 600)
            assert entry.request_line is not None


class TestParsingStatistics:
    """Test cases for parsing statistics tracking."""
    
    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        from src.loglens.services.parsing.base_parser import ParsingStatistics
        
        stats = ParsingStatistics()
        stats.total_lines = 10
        stats.successful_parses = 8
        stats.errors = 2
        
        assert stats.success_rate == 80.0
    
    def test_success_rate_with_zero_lines(self):
        """Test success rate with zero lines processed."""
        from src.loglens.services.parsing.base_parser import ParsingStatistics
        
        stats = ParsingStatistics()
        assert stats.success_rate == 0.0
    
    def test_processing_time_calculation(self):
        """Test processing time calculation."""
        from src.loglens.services.parsing.base_parser import ParsingStatistics
        from datetime import timedelta
        
        stats = ParsingStatistics()
        start_time = datetime.now()
        stats.start_time = start_time
        stats.end_time = start_time + timedelta(seconds=5.5)
        
        assert stats.processing_time == pytest.approx(5.5, abs=0.1)


class TestParsedResult:
    """Test cases for ParsedResult container."""
    
    def test_successful_result(self):
        """Test creating successful parsing result."""
        from src.loglens.services.parsing.base_parser import ParsedResult
        
        entry = Mock()
        result = ParsedResult(success=True, entry=entry, line_number=1)
        
        assert result.success is True
        assert result.entry is entry
        assert result.error is None
        assert result.line_number == 1
    
    def test_failed_result(self):
        """Test creating failed parsing result."""
        from src.loglens.services.parsing.base_parser import ParsedResult
        
        result = ParsedResult(success=False, error="Test error", line_number=2)
        
        assert result.success is False
        assert result.entry is None
        assert result.error == "Test error"
        assert result.line_number == 2 