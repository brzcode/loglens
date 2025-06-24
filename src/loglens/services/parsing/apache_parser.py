"""Apache log parser implementation for LogLens."""

import re
from datetime import datetime
from typing import Optional, Match
from pydantic import ValidationError, IPvAnyAddress

from .base_parser import BaseParser, ParsedResult
from ...models import RawLogLine, ParsedLogEntry


class ApacheParser(BaseParser):
    """Parser for Apache Common Log Format (CLF) and Combined Log Format."""
    
    def __init__(self):
        super().__init__()
        
        # Common Log Format (CLF): %h %l %u %t "%r" %>s %b
        # Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
        self.clf_pattern = re.compile(
            r'^(?P<ip>\S+) '                      # IP address
            r'(?P<remote_logname>\S+) '           # Remote logname (usually -)
            r'(?P<remote_user>\S+) '              # Remote user (usually -)
            r'\[(?P<timestamp>[^\]]+)\] '         # Timestamp in brackets
            r'"(?P<request_line>[^"]*)" '         # Request line in quotes
            r'(?P<status_code>\d+) '              # Status code 
            r'(?P<bytes_sent>\S+)'                # Bytes sent (- if none)
        )
        
        # Combined Log Format: CLF + "%{Referer}i" "%{User-agent}i"
        # Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
        self.combined_pattern = re.compile(
            r'^(?P<ip>\S+) '                      # IP address
            r'(?P<remote_logname>\S+) '           # Remote logname (usually -)
            r'(?P<remote_user>\S+) '              # Remote user (usually -)
            r'\[(?P<timestamp>[^\]]+)\] '         # Timestamp in brackets
            r'"(?P<request_line>[^"]*)" '         # Request line in quotes
            r'(?P<status_code>\d+) '              # Status code
            r'(?P<bytes_sent>\S+) '               # Bytes sent
            r'"(?P<referer>[^"]*)" '              # Referer in quotes
            r'"(?P<user_agent>[^"]*)"'            # User agent in quotes
        )
    
    def parse_line(self, raw_line: RawLogLine) -> ParsedResult:
        """Parse a single Apache log line.
        
        Args:
            raw_line: RawLogLine object containing the log data
            
        Returns:
            ParsedResult containing success/failure and parsed data or error
        """
        content = raw_line.content.strip()
        
        if not content:
            return ParsedResult(success=False, error="Empty log line")
        
        # Try Combined format first (more specific)
        match = self.combined_pattern.match(content)
        is_combined = True
        
        if not match:
            # Try CLF format
            match = self.clf_pattern.match(content)
            is_combined = False
        
        if not match:
            return ParsedResult(
                success=False, 
                error="Log line does not match Apache CLF or Combined format"
            )
        
        try:
            # Extract fields from regex match
            groups = match.groupdict()
            
            # Parse and validate IP address
            ip_str = groups['ip']
            try:
                ip_address = IPvAnyAddress(ip_str)
            except ValueError as e:
                return ParsedResult(
                    success=False, 
                    error=f"Invalid IP address '{ip_str}': {str(e)}"
                )
            
            # Parse timestamp
            timestamp_str = groups['timestamp']
            try:
                timestamp = self._parse_apache_timestamp(timestamp_str)
            except ValueError as e:
                return ParsedResult(
                    success=False, 
                    error=f"Invalid timestamp '{timestamp_str}': {str(e)}"
                )
            
            # Parse status code
            try:
                status_code = int(groups['status_code'])
                if not (100 <= status_code <= 599):
                    return ParsedResult(
                        success=False, 
                        error=f"Invalid HTTP status code: {status_code}"
                    )
            except ValueError:
                return ParsedResult(
                    success=False, 
                    error=f"Invalid status code format: {groups['status_code']}"
                )
            
            # Parse bytes sent (can be - for no data)
            bytes_sent = None
            bytes_str = groups['bytes_sent']
            if bytes_str != '-':
                try:
                    bytes_sent = int(bytes_str)
                except ValueError:
                    return ParsedResult(
                        success=False, 
                        error=f"Invalid bytes sent format: {bytes_str}"
                    )
            
            # Handle remote user (- means no user)
            remote_user = groups['remote_user'] if groups['remote_user'] != '-' else None
            
            # Handle Combined format fields
            user_agent = None
            referer = None
            
            if is_combined:
                user_agent = groups['user_agent'] if groups['user_agent'] != '-' else None
                referer = groups['referer'] if groups['referer'] != '-' else None
            
            # Create ParsedLogEntry
            parsed_entry = ParsedLogEntry(
                ip_address=ip_address,
                timestamp=timestamp,
                request_line=groups['request_line'],
                status_code=status_code,
                raw_line=content,
                user_agent=user_agent,
                bytes_sent=bytes_sent,
                referer=referer,
                remote_user=remote_user
            )
            
            return ParsedResult(success=True, entry=parsed_entry)
            
        except ValidationError as e:
            return ParsedResult(
                success=False, 
                error=f"Data validation error: {str(e)}"
            )
        except Exception as e:
            return ParsedResult(
                success=False, 
                error=f"Unexpected parsing error: {str(e)}"
            )
    
    def _parse_apache_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Apache timestamp format: dd/MMM/yyyy:HH:mm:ss +0000
        
        Args:
            timestamp_str: Timestamp string from Apache log
            
        Returns:
            datetime object
            
        Raises:
            ValueError: If timestamp format is invalid
        """
        # Apache format: 10/Oct/2000:13:55:36 -0700
        try:
            # Remove timezone for now (Python datetime parsing is complex with timezones)
            # Split on space to separate date/time from timezone
            parts = timestamp_str.split(' ')
            if len(parts) != 2:
                raise ValueError("Expected format: 'dd/MMM/yyyy:HH:mm:ss +0000'")
            
            datetime_part, timezone_part = parts
            
            # Parse the datetime part
            dt = datetime.strptime(datetime_part, '%d/%b/%Y:%H:%M:%S')
            
            # For MVP, we'll ignore timezone and assume UTC
            # In future versions, we could add proper timezone handling
            return dt
            
        except ValueError as e:
            raise ValueError(f"Invalid Apache timestamp format: {str(e)}")
    
    def get_supported_formats(self) -> list[str]:
        """Get list of supported Apache log formats.
        
        Returns:
            List of format names
        """
        return ["Common Log Format (CLF)", "Combined Log Format"] 