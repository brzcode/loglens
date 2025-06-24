"""Detection service for LogLens - identifies security patterns in parsed log data."""

import re
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Generator, Iterator, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from ..models import ParsedLogEntry, Finding, DetectionResult, DetectionStatistics


class BaseDetector(ABC):
    """Abstract base class for log pattern detectors."""
    
    def __init__(self):
        self.statistics = DetectionStatistics()
    
    @abstractmethod
    def detect_patterns(self, log_entries: Iterator[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect patterns in log entries.
        
        Args:
            log_entries: Iterator of parsed log entries
            
        Yields:
            Finding objects for detected patterns
        """
        pass
    
    def reset_statistics(self):
        """Reset detection statistics for new analysis."""
        self.statistics = DetectionStatistics()
    
    def get_statistics(self) -> DetectionStatistics:
        """Get current detection statistics."""
        return self.statistics


class KeywordDetector(BaseDetector):
    """Detector for keyword-based security patterns."""
    
    def __init__(self):
        super().__init__()
        
        # SQL Injection patterns with risk scores
        self.sql_injection_patterns = {
            # High-risk SQL injection keywords (80-100)
            r'\bunion\s+(all\s+)?select\b': 90,  # UNION SELECT attacks
            r'\bselect\s+.*\bfrom\s+': 85,       # SELECT FROM statements
            r'\bdrop\s+(table|database)\b': 95,   # DROP statements
            r'\binsert\s+into\b': 80,            # INSERT statements
            r'\bupdate\s+.*\bset\b': 80,         # UPDATE statements
            r'\bdelete\s+from\b': 85,            # DELETE statements
            r'\bexec\s*\(': 90,                  # EXEC statements
            r'sqlmap': 95,                       # SQLMap tool signature
            r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+': 80,  # OR/AND 1=1 patterns
        }
        
        # Command execution patterns with risk scores
        self.command_execution_patterns = {
            # High-risk command execution (80-100)
            r'\bcmd\s*/c\b': 90,                 # Windows command execution
            r'\bpowershell\b': 85,               # PowerShell execution
            r'\bbash\s+-c\b': 90,                # Bash command execution
            r'\bwget\s+': 85,                    # File download
            r'\bcurl\s+': 85,                    # File download/upload
            r'\bnc\s+-': 90,                     # Netcat
            r'\bnetcat\s+': 90,                  # Netcat
        }
        
        # XSS patterns with risk scores
        self.xss_patterns = {
            # High-risk XSS patterns (80-100)
            r'<script[^>]*>': 90,                # Script tags
            r'javascript:\s*': 85,               # JavaScript protocol
            r'\balert\s*\(': 85,                 # Alert functions
            r'\beval\s*\(': 90,                  # Eval functions
            r'on\w+\s*=\s*[\'"][^\'\"]*[\'"]': 80,  # Event handlers
        }
        
        # Compile all patterns for efficiency
        self._compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        pattern_groups = [
            ('sql_injection', self.sql_injection_patterns),
            ('command_execution', self.command_execution_patterns),
            ('xss', self.xss_patterns)
        ]
        
        for group_name, patterns in pattern_groups:
            self._compiled_patterns[group_name] = [
                (re.compile(pattern, re.IGNORECASE), risk_score)
                for pattern, risk_score in patterns.items()
            ]
    
    def detect_patterns(self, log_entries: Iterator[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect keyword-based security patterns in log entries."""
        self.statistics.start_time = datetime.now()
        
        for log_entry in log_entries:
            self.statistics.total_entries_processed += 1
            
            try:
                # Analyze request line and user agent for patterns
                targets = [
                    ('request_line', log_entry.request_line),
                    ('user_agent', log_entry.user_agent or ''),
                    ('referer', log_entry.referer or '')
                ]
                
                for target_name, target_text in targets:
                    if not target_text:
                        continue
                    
                    # URL decode the text for analysis
                    decoded_text = unquote(target_text)
                    
                    # Check against all pattern groups
                    for group_name, compiled_patterns in self._compiled_patterns.items():
                        for pattern, risk_score in compiled_patterns:
                            match = pattern.search(decoded_text)
                            if match:
                                matched_text = match.group(0)
                                finding = Finding(
                                    log_entry=log_entry,
                                    finding_type=f"Keyword Match - {group_name.replace('_', ' ').title()}",
                                    description=f"Detected {group_name.replace('_', ' ')} pattern in {target_name}: '{matched_text}'",
                                    risk_score=risk_score,
                                    enrichment_data={
                                        'pattern_type': group_name,
                                        'target_field': target_name,
                                        'matched_pattern': pattern.pattern,
                                        'matched_text': matched_text,
                                        'decoded_text': decoded_text[:200],  # First 200 chars for context
                                        'original_text': target_text[:200]
                                    }
                                )
                                
                                # Update statistics
                                self.statistics.total_findings += 1
                                if 80 <= risk_score <= 100:
                                    self.statistics.high_risk_count += 1
                                elif 50 <= risk_score <= 79:
                                    self.statistics.medium_risk_count += 1
                                elif 20 <= risk_score <= 49:
                                    self.statistics.low_risk_count += 1
                                else:
                                    self.statistics.info_count += 1
                                
                                yield finding
                                
                                # Only report first match per pattern per field to avoid spam
                                break
                
            except Exception as e:
                self.statistics.processing_errors += 1
                self.statistics.error_details.append(f"Error processing entry: {str(e)}")
                continue
        
        self.statistics.end_time = datetime.now()


class TimeWindowAnalyzer:
    """Analyzer for time-windowed frequency detection patterns."""
    
    def __init__(self):
        # Time window configurations in seconds
        self.time_windows = {
            '1min': 60,
            '5min': 300,
            '15min': 900,
            '1hour': 3600
        }
    
    def analyze_time_windows(self, entries: List[ParsedLogEntry], 
                           window_types: List[str] = None) -> Dict[str, Dict]:
        """Analyze entries across multiple time windows.
        
        Args:
            entries: List of log entries sorted by timestamp
            window_types: List of window types to analyze (default: all)
            
        Returns:
            Dictionary with window analysis results
        """
        if window_types is None:
            window_types = list(self.time_windows.keys())
        
        if not entries:
            return {window: {} for window in window_types}
        
        results = {}
        
        for window_type in window_types:
            window_seconds = self.time_windows[window_type]
            results[window_type] = self._analyze_sliding_window(entries, window_seconds)
        
        return results
    
    def _analyze_sliding_window(self, entries: List[ParsedLogEntry], 
                               window_seconds: int) -> Dict:
        """Analyze entries in a sliding window.
        
        Args:
            entries: Sorted list of log entries
            window_seconds: Window size in seconds
            
        Returns:
            Dictionary with window analysis results
        """
        if not entries:
            return {}
        
        # Group entries by IP address
        ip_entries = defaultdict(list)
        for entry in entries:
            ip_entries[str(entry.ip_address)].append(entry)
        
        results = {}
        
        for ip_address, ip_logs in ip_entries.items():
            # Sort by timestamp
            ip_logs.sort(key=lambda x: x.timestamp)
            
            # Find maximum frequency in any window
            max_requests = 0
            max_failed_logins = 0
            unique_paths = set()
            unique_user_agents = set()
            burst_periods = []
            
            # Sliding window analysis
            for i, entry in enumerate(ip_logs):
                window_start = entry.timestamp
                window_end = window_start + timedelta(seconds=window_seconds)
                
                # Count events in this window
                window_requests = 0
                window_failed_logins = 0
                window_paths = set()
                window_user_agents = set()
                
                for j in range(i, len(ip_logs)):
                    if ip_logs[j].timestamp <= window_end:
                        window_requests += 1
                        window_paths.add(urlparse(ip_logs[j].request_line.split()[1]).path)
                        if ip_logs[j].user_agent:
                            window_user_agents.add(ip_logs[j].user_agent)
                        if ip_logs[j].status_code in [401, 403]:
                            window_failed_logins += 1
                    else:
                        break
                
                # Track maximums
                max_requests = max(max_requests, window_requests)
                max_failed_logins = max(max_failed_logins, window_failed_logins)
                unique_paths.update(window_paths)
                unique_user_agents.update(window_user_agents)
                
                # Detect burst patterns (high frequency in short time)
                if window_seconds <= 60 and window_requests >= 30:  # 30+ requests in 1 minute or less
                    burst_periods.append({
                        'start_time': window_start,
                        'requests': window_requests,
                        'duration': min(window_seconds, 60)
                    })
            
            results[ip_address] = {
                'max_requests_in_window': max_requests,
                'max_failed_logins_in_window': max_failed_logins,
                'unique_paths_accessed': len(unique_paths),
                'unique_user_agents': len(unique_user_agents),
                'burst_periods': burst_periods,
                'total_requests': len(ip_logs)
            }
        
        return results


class FrequencyDetector(BaseDetector):
    """Detector for frequency-based anomalies and patterns."""
    
    def __init__(self, failed_login_threshold: int = 5, high_frequency_threshold: int = 50,
                 enable_time_windows: bool = True):
        super().__init__()
        self.failed_login_threshold = failed_login_threshold
        self.high_frequency_threshold = high_frequency_threshold
        self.enable_time_windows = enable_time_windows
        self.time_analyzer = TimeWindowAnalyzer() if enable_time_windows else None
        
        # Time-windowed thresholds
        self.time_window_thresholds = {
            '1min': {'failed_logins': 5, 'requests': 100},
            '5min': {'failed_logins': 10, 'requests': 250},
            '15min': {'failed_logins': 20, 'requests': 500},
            '1hour': {'failed_logins': 50, 'requests': 1000}
        }
    
    def detect_patterns(self, log_entries: Iterator[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect frequency-based patterns in log entries."""
        self.statistics.start_time = datetime.now()
        
        # Collect all entries for frequency analysis
        entries_list = list(log_entries)
        self.statistics.total_entries_processed = len(entries_list)
        
        # Track patterns by IP address
        ip_patterns = defaultdict(lambda: {
            'failed_logins': [],
            'all_requests': [],
            'status_codes': Counter()
        })
        
        # Analyze each entry
        for entry in entries_list:
            ip_str = str(entry.ip_address)
            ip_patterns[ip_str]['all_requests'].append(entry)
            ip_patterns[ip_str]['status_codes'][entry.status_code] += 1
            
            # Track failed login attempts (401, 403 status codes)
            if entry.status_code in [401, 403]:
                ip_patterns[ip_str]['failed_logins'].append(entry)
        
        # Perform time window analysis if enabled
        time_window_results = {}
        if self.enable_time_windows and self.time_analyzer:
            time_window_results = self.time_analyzer.analyze_time_windows(entries_list)
        
        # Analyze patterns for each IP
        for ip_address, patterns in ip_patterns.items():
            try:
                # Original frequency detection (for backward compatibility)
                yield from self._detect_original_patterns(ip_address, patterns)
                
                # Time-windowed detection
                if self.enable_time_windows and ip_address in time_window_results.get('1min', {}):
                    yield from self._detect_time_windowed_patterns(ip_address, patterns, time_window_results)
                
            except Exception as e:
                self.statistics.processing_errors += 1
                self.statistics.error_details.append(f"Error analyzing IP {ip_address}: {str(e)}")
                continue
        
        self.statistics.end_time = datetime.now()
    
    def _detect_original_patterns(self, ip_address: str, patterns: Dict) -> Generator[Finding, None, None]:
        """Detect original frequency patterns for backward compatibility."""
        # Check for failed login attempts
        failed_logins = patterns['failed_logins']
        if len(failed_logins) >= self.failed_login_threshold:
            risk_score = min(70 + (len(failed_logins) - 5) * 5, 100)
            
            finding = Finding(
                log_entry=failed_logins[-1],  # Use most recent attempt as reference
                finding_type="Failed Login Pattern",
                description=f"Detected {len(failed_logins)} failed login attempts from IP {ip_address}",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'failed_login_frequency',
                    'ip_address': ip_address,
                    'failed_attempt_count': len(failed_logins),
                    'status_codes': dict(patterns['status_codes'])
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
        
        # Check for high-frequency requests
        all_requests = patterns['all_requests']
        if len(all_requests) >= self.high_frequency_threshold:
            risk_score = min(50 + (len(all_requests) - 50) * 1, 85)
            
            finding = Finding(
                log_entry=all_requests[-1],  # Use most recent request as reference
                finding_type="High Request Frequency",
                description=f"Detected {len(all_requests)} requests from IP {ip_address}",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'high_frequency_requests',
                    'ip_address': ip_address,
                    'total_requests': len(all_requests),
                    'status_code_distribution': dict(patterns['status_codes'])
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
    
    def _detect_time_windowed_patterns(self, ip_address: str, patterns: Dict, 
                                     time_results: Dict) -> Generator[Finding, None, None]:
        """Detect time-windowed frequency patterns."""
        all_requests = patterns['all_requests']
        if not all_requests:
            return
        
        # Check each time window for violations
        for window_type, thresholds in self.time_window_thresholds.items():
            if window_type not in time_results or ip_address not in time_results[window_type]:
                continue
            
            window_data = time_results[window_type][ip_address]
            
            # Time-windowed failed login detection
            max_failed_logins = window_data.get('max_failed_logins_in_window', 0)
            if max_failed_logins >= thresholds['failed_logins']:
                risk_score = min(85 + max_failed_logins * 2, 100)
                
                finding = Finding(
                    log_entry=all_requests[-1],
                    finding_type=f"Time-Windowed Brute Force ({window_type})",
                    description=f"Detected {max_failed_logins} failed logins within {window_type} from IP {ip_address}",
                    risk_score=risk_score,
                    enrichment_data={
                        'pattern_type': 'time_windowed_brute_force',
                        'ip_address': ip_address,
                        'time_window': window_type,
                        'max_failed_logins': max_failed_logins,
                        'threshold': thresholds['failed_logins'],
                        'window_data': window_data
                    }
                )
                
                self.statistics.total_findings += 1
                if 80 <= risk_score <= 100:
                    self.statistics.high_risk_count += 1
                elif 50 <= risk_score <= 79:
                    self.statistics.medium_risk_count += 1
                else:
                    self.statistics.low_risk_count += 1
                
                yield finding
            
            # Time-windowed burst detection
            max_requests = window_data.get('max_requests_in_window', 0)
            if max_requests >= thresholds['requests']:
                risk_score = min(75 + (max_requests - thresholds['requests']) // 10, 95)
                
                finding = Finding(
                    log_entry=all_requests[-1],
                    finding_type=f"Request Burst Pattern ({window_type})",
                    description=f"Detected {max_requests} requests within {window_type} from IP {ip_address}",
                    risk_score=risk_score,
                    enrichment_data={
                        'pattern_type': 'time_windowed_burst',
                        'ip_address': ip_address,
                        'time_window': window_type,
                        'max_requests': max_requests,
                        'threshold': thresholds['requests'],
                        'burst_periods': window_data.get('burst_periods', [])
                    }
                )
                
                self.statistics.total_findings += 1
                if 80 <= risk_score <= 100:
                    self.statistics.high_risk_count += 1
                elif 50 <= risk_score <= 79:
                    self.statistics.medium_risk_count += 1
                else:
                    self.statistics.low_risk_count += 1
                
                yield finding


class ScanningDetector(BaseDetector):
    """Detector for scanning patterns and endpoint enumeration."""
    
    def __init__(self, unique_paths_threshold: int = 10, scan_time_window: int = 300):
        super().__init__()
        self.unique_paths_threshold = unique_paths_threshold
        self.scan_time_window = scan_time_window  # 5 minutes default
        
        # Common vulnerability scanning patterns
        self.scanning_patterns = {
            # Directory traversal patterns
            r'\.\.\/': 70,
            r'\.\.\\': 70,
            r'\/\.\.\/%': 75,
            
            # Common scanning paths
            r'\/admin\/?$': 60,
            r'\/backup\/?$': 65,
            r'\/config\/?$': 65,
            r'\/wp-admin\/?': 60,
            r'\/phpmyadmin\/?': 65,
            r'\/manager\/?': 60,
            r'\/login\/?$': 50,
            r'\/test\/?$': 55,
            r'\/tmp\/?$': 60,
            r'\/uploads?\/?': 55,
            
            # File extensions commonly scanned
            r'\.php\?': 55,
            r'\.asp\?': 55,
            r'\.jsp\?': 55,
            r'\.cgi\?': 60,
            r'\.sh$': 65,
            r'\.sql$': 70,
            r'\.bak$': 65,
            r'\.old$': 65,
            
            # Tool signatures
            r'nikto': 80,
            r'dirb': 75,
            r'dirbuster': 75,
            r'gobuster': 75,
            r'sqlmap': 85,
            r'nmap': 80,
            r'masscan': 80,
        }
        
        # Compile patterns
        self._compiled_scan_patterns = [
            (re.compile(pattern, re.IGNORECASE), score)
            for pattern, score in self.scanning_patterns.items()
        ]
    
    def detect_patterns(self, log_entries: Iterator[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect scanning patterns in log entries."""
        self.statistics.start_time = datetime.now()
        
        entries_list = list(log_entries)
        self.statistics.total_entries_processed = len(entries_list)
        
        # Group by IP address
        ip_entries = defaultdict(list)
        for entry in entries_list:
            ip_entries[str(entry.ip_address)].append(entry)
        
        for ip_address, entries in ip_entries.items():
            try:
                # Sort entries by timestamp
                entries.sort(key=lambda x: x.timestamp)
                
                # Analyze scanning patterns
                yield from self._detect_path_enumeration(ip_address, entries)
                yield from self._detect_scanning_signatures(ip_address, entries)
                yield from self._detect_vulnerability_scanning(ip_address, entries)
                
            except Exception as e:
                self.statistics.processing_errors += 1
                self.statistics.error_details.append(f"Error analyzing scanning for IP {ip_address}: {str(e)}")
                continue
        
        self.statistics.end_time = datetime.now()
    
    def _detect_path_enumeration(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect path enumeration patterns."""
        if len(entries) < self.unique_paths_threshold:
            return
        
        # Extract unique paths accessed within time windows
        paths_accessed = set()
        scan_periods = []
        
        for i, entry in enumerate(entries):
            window_start = entry.timestamp
            window_end = window_start + timedelta(seconds=self.scan_time_window)
            
            # Count unique paths in this window
            window_paths = set()
            window_entries = []
            
            for j in range(i, len(entries)):
                if entries[j].timestamp <= window_end:
                    try:
                        # Extract path from request line
                        request_parts = entries[j].request_line.split()
                        if len(request_parts) >= 2:
                            path = urlparse(request_parts[1]).path
                            window_paths.add(path)
                            window_entries.append(entries[j])
                    except:
                        continue
                else:
                    break
            
            paths_accessed.update(window_paths)
            
            # If many unique paths in short time, it's likely scanning
            if len(window_paths) >= self.unique_paths_threshold:
                scan_periods.append({
                    'start_time': window_start,
                    'unique_paths': len(window_paths),
                    'total_requests': len(window_entries),
                    'paths': list(window_paths)[:20]  # Sample of paths
                })
        
        if scan_periods:
            # Calculate risk score based on scan intensity
            max_paths = max(period['unique_paths'] for period in scan_periods)
            risk_score = min(60 + max_paths * 2, 90)
            
            finding = Finding(
                log_entry=entries[-1],
                finding_type="Path Enumeration Scan",
                description=f"Detected scanning of {max_paths} unique paths from IP {ip_address}",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'path_enumeration',
                    'ip_address': ip_address,
                    'total_unique_paths': len(paths_accessed),
                    'max_paths_in_window': max_paths,
                    'scan_periods': scan_periods,
                    'scanning_threshold': self.unique_paths_threshold
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
    
    def _detect_scanning_signatures(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect known scanning tool signatures."""
        tool_signatures = set()
        matching_entries = []
        
        for entry in entries:
            # Check user agent and request for tool signatures
            targets = [
                entry.user_agent or '',
                entry.request_line or '',
                entry.referer or ''
            ]
            
            for target in targets:
                for pattern, risk_score in self._compiled_scan_patterns:
                    if pattern.search(target):
                        tool_signatures.add(pattern.pattern)
                        matching_entries.append((entry, pattern.pattern, risk_score))
        
        if tool_signatures:
            # Use highest risk score found
            max_risk = max(score for _, _, score in matching_entries)
            risk_score = min(max_risk + 10, 95)  # Boost for multiple signatures
            
            finding = Finding(
                log_entry=matching_entries[-1][0],
                finding_type="Scanning Tool Signature",
                description=f"Detected scanning tool signatures from IP {ip_address}: {', '.join(list(tool_signatures)[:3])}",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'scanning_tool_signature',
                    'ip_address': ip_address,
                    'tool_signatures': list(tool_signatures),
                    'signature_count': len(tool_signatures),
                    'matching_patterns': [(pattern, score) for _, pattern, score in matching_entries]
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
    
    def _detect_vulnerability_scanning(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect vulnerability scanning based on status code patterns."""
        if len(entries) < 10:  # Need sufficient requests to detect pattern
            return
        
        # Analyze status code distribution
        status_codes = Counter()
        for entry in entries:
            status_codes[entry.status_code] += 1
        
        # Scanning typically produces many 404s (file not found) and some 403s (forbidden)
        total_requests = len(entries)
        not_found_ratio = status_codes.get(404, 0) / total_requests
        forbidden_ratio = status_codes.get(403, 0) / total_requests
        
        # High 404 ratio with some variety indicates scanning
        if not_found_ratio >= 0.6 and total_requests >= 20:
            # Extract sample of 404 paths to show what was scanned
            sample_404_paths = []
            for entry in entries:
                if entry.status_code == 404 and len(sample_404_paths) < 10:
                    try:
                        path = urlparse(entry.request_line.split()[1]).path
                        sample_404_paths.append(path)
                    except:
                        continue
            
            risk_score = min(65 + int(not_found_ratio * 20), 85)
            
            finding = Finding(
                log_entry=entries[-1],
                finding_type="Vulnerability Scanning Pattern",
                description=f"Detected vulnerability scanning from IP {ip_address} ({not_found_ratio:.1%} 404 responses)",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'vulnerability_scanning',
                    'ip_address': ip_address,
                    'total_requests': total_requests,
                    'not_found_ratio': not_found_ratio,
                    'forbidden_ratio': forbidden_ratio,
                    'status_distribution': dict(status_codes),
                    'sample_404_paths': sample_404_paths
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding


class BehavioralDetector(BaseDetector):
    """Detector for advanced behavioral analysis and anomalies."""
    
    def __init__(self, dos_burst_threshold: int = 100, ua_rotation_threshold: int = 5):
        super().__init__()
        self.dos_burst_threshold = dos_burst_threshold
        self.ua_rotation_threshold = ua_rotation_threshold
        
        # Time windows for burst detection (in seconds)
        self.burst_time_windows = {
            '30sec': 30,
            '1min': 60,
            '2min': 120,
            '5min': 300
        }
        
        # Suspicious request size patterns
        self.suspicious_size_thresholds = {
            'tiny_requests': 10,     # < 10 bytes may indicate automation
            'huge_requests': 10000,  # > 10KB may indicate data exfiltration attempts
        }
    
    def detect_patterns(self, log_entries: Iterator[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect behavioral anomalies in log entries."""
        self.statistics.start_time = datetime.now()
        
        entries_list = list(log_entries)
        self.statistics.total_entries_processed = len(entries_list)
        
        # Group by IP address
        ip_entries = defaultdict(list)
        for entry in entries_list:
            ip_entries[str(entry.ip_address)].append(entry)
        
        for ip_address, entries in ip_entries.items():
            try:
                # Sort entries by timestamp
                entries.sort(key=lambda x: x.timestamp)
                
                # Analyze behavioral patterns
                yield from self._detect_dos_burst_patterns(ip_address, entries)
                yield from self._detect_user_agent_rotation(ip_address, entries)
                yield from self._detect_request_size_anomalies(ip_address, entries)
                yield from self._detect_session_anomalies(ip_address, entries)
                
            except Exception as e:
                self.statistics.processing_errors += 1
                self.statistics.error_details.append(f"Error analyzing behavioral patterns for IP {ip_address}: {str(e)}")
                continue
        
        self.statistics.end_time = datetime.now()
    
    def _detect_dos_burst_patterns(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect DoS-like burst patterns."""
        if len(entries) < self.dos_burst_threshold:
            return
        
        burst_patterns = {}
        
        # Analyze each time window
        for window_name, window_seconds in self.burst_time_windows.items():
            max_requests_in_window = 0
            burst_periods = []
            
            for i, entry in enumerate(entries):
                window_start = entry.timestamp
                window_end = window_start + timedelta(seconds=window_seconds)
                
                # Count requests in this window
                window_requests = 0
                for j in range(i, len(entries)):
                    if entries[j].timestamp <= window_end:
                        window_requests += 1
                    else:
                        break
                
                max_requests_in_window = max(max_requests_in_window, window_requests)
                
                # Record burst periods
                if window_requests >= self.dos_burst_threshold:
                    burst_periods.append({
                        'start_time': window_start,
                        'requests': window_requests,
                        'duration': window_seconds
                    })
            
            burst_patterns[window_name] = {
                'max_requests': max_requests_in_window,
                'burst_periods': burst_periods
            }
        
        # Find the most intense burst pattern
        max_burst = max(
            (pattern['max_requests'] for pattern in burst_patterns.values()),
            default=0
        )
        
        if max_burst >= self.dos_burst_threshold:
            # Determine which window had the most intense activity
            intense_window = max(
                burst_patterns.keys(),
                key=lambda w: burst_patterns[w]['max_requests']
            )
            
            risk_score = min(80 + (max_burst - self.dos_burst_threshold) // 10, 100)
            
            finding = Finding(
                log_entry=entries[-1],
                finding_type=f"DoS Burst Pattern ({intense_window})",
                description=f"Detected {max_burst} requests in {intense_window} from IP {ip_address}",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'dos_burst_pattern',
                    'ip_address': ip_address,
                    'max_burst_requests': max_burst,
                    'intense_window': intense_window,
                    'burst_patterns': burst_patterns,
                    'dos_threshold': self.dos_burst_threshold
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
    
    def _detect_user_agent_rotation(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect user agent rotation patterns."""
        user_agents = set()
        user_agent_timeline = []
        
        for entry in entries:
            if entry.user_agent:
                user_agents.add(entry.user_agent)
                user_agent_timeline.append({
                    'timestamp': entry.timestamp,
                    'user_agent': entry.user_agent
                })
        
        if len(user_agents) >= self.ua_rotation_threshold:
            # Analyze rotation pattern timing
            rotation_speed = 0
            if len(user_agent_timeline) > 1:
                time_span = (user_agent_timeline[-1]['timestamp'] - user_agent_timeline[0]['timestamp']).total_seconds()
                rotation_speed = len(user_agents) / max(time_span / 60, 1)  # UAs per minute
            
            risk_score = min(65 + len(user_agents) * 3, 90)
            
            finding = Finding(
                log_entry=entries[-1],
                finding_type="User Agent Rotation",
                description=f"Detected {len(user_agents)} different user agents from IP {ip_address}",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'user_agent_rotation',
                    'ip_address': ip_address,
                    'unique_user_agents': len(user_agents),
                    'rotation_speed': rotation_speed,
                    'sample_user_agents': list(user_agents)[:10],  # Sample for analysis
                    'ua_threshold': self.ua_rotation_threshold
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
    
    def _detect_request_size_anomalies(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect unusual request size patterns."""
        if len(entries) < 10:  # Need sufficient data
            return
        
        # Analyze request sizes (approximated from request line length)
        request_sizes = []
        tiny_requests = 0
        huge_requests = 0
        
        for entry in entries:
            # Approximate request size from request line length
            size = len(entry.request_line.encode('utf-8'))
            request_sizes.append(size)
            
            if size < self.suspicious_size_thresholds['tiny_requests']:
                tiny_requests += 1
            elif size > self.suspicious_size_thresholds['huge_requests']:
                huge_requests += 1
        
        total_requests = len(entries)
        tiny_ratio = tiny_requests / total_requests
        huge_ratio = huge_requests / total_requests
        
        # Detect automation (many tiny requests)
        if tiny_ratio > 0.7 and tiny_requests > 20:
            risk_score = min(60 + int(tiny_ratio * 30), 85)
            
            finding = Finding(
                log_entry=entries[-1],
                finding_type="Automated Request Pattern",
                description=f"Detected {tiny_ratio:.1%} tiny requests from IP {ip_address} (possible automation)",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'automated_request_pattern',
                    'ip_address': ip_address,
                    'tiny_requests_ratio': tiny_ratio,
                    'tiny_requests_count': tiny_requests,
                    'total_requests': total_requests,
                    'avg_request_size': sum(request_sizes) / len(request_sizes)
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
        
        # Detect data exfiltration attempts (huge requests)
        elif huge_ratio > 0.1 and huge_requests > 5:
            risk_score = min(70 + int(huge_ratio * 40), 95)
            
            finding = Finding(
                log_entry=entries[-1],
                finding_type="Large Request Pattern",
                description=f"Detected {huge_ratio:.1%} large requests from IP {ip_address} (possible data exfiltration)",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'large_request_pattern',
                    'ip_address': ip_address,
                    'huge_requests_ratio': huge_ratio,
                    'huge_requests_count': huge_requests,
                    'total_requests': total_requests,
                    'max_request_size': max(request_sizes)
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding
    
    def _detect_session_anomalies(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect session-based anomalies."""
        if len(entries) < 5:
            return
        
        # Analyze request timing patterns
        time_intervals = []
        for i in range(1, len(entries)):
            interval = (entries[i].timestamp - entries[i-1].timestamp).total_seconds()
            time_intervals.append(interval)
        
        if time_intervals:
            avg_interval = sum(time_intervals) / len(time_intervals)
            
            # Detect machine-like precise timing (potential automation)
            if len(set(int(interval) for interval in time_intervals if interval < 60)) == 1:
                # All intervals are the same (rounded to seconds)
                unique_intervals = len(set(int(interval) for interval in time_intervals if interval < 60))
                if unique_intervals <= 2 and len(time_intervals) >= 10:
                    risk_score = min(70 + len(time_intervals), 90)
                    
                    finding = Finding(
                        log_entry=entries[-1],
                        finding_type="Automated Session Pattern",
                        description=f"Detected machine-like timing pattern from IP {ip_address} (avg {avg_interval:.1f}s intervals)",
                        risk_score=risk_score,
                        enrichment_data={
                            'pattern_type': 'automated_session_pattern',
                            'ip_address': ip_address,
                            'avg_interval': avg_interval,
                            'request_count': len(entries),
                            'timing_consistency': unique_intervals,
                            'sample_intervals': time_intervals[:10]
                        }
                    )
                    
                    self.statistics.total_findings += 1
                    if 80 <= risk_score <= 100:
                        self.statistics.high_risk_count += 1
                    elif 50 <= risk_score <= 79:
                        self.statistics.medium_risk_count += 1
                    else:
                        self.statistics.low_risk_count += 1
                    
                    yield finding


class GeographicDetector(BaseDetector):
    """Detector for geographic frequency analysis using IP enrichment data."""
    
    def __init__(self, geo_change_threshold: int = 3, session_time_window: int = 3600):
        super().__init__()
        self.geo_change_threshold = geo_change_threshold  # Countries in session
        self.session_time_window = session_time_window    # 1 hour default
        
        # High-risk countries and their risk multipliers
        self.high_risk_countries = {
            'CN': 1.3,  # China
            'RU': 1.4,  # Russia
            'KP': 1.5,  # North Korea
            'IR': 1.4,  # Iran
            'PK': 1.2,  # Pakistan
            'BD': 1.2,  # Bangladesh
            'VN': 1.2,  # Vietnam
            'IN': 1.1,  # India (lower multiplier, large legitimate user base)
        }
        
        # Frequency thresholds adjusted by geographic risk
        self.geo_frequency_thresholds = {
            'base_requests_per_hour': 200,
            'base_failed_logins_per_hour': 20,
            'multiple_countries_window': 3600,  # 1 hour
        }
    
    def detect_patterns(self, log_entries: Iterator[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect geographic-based frequency anomalies."""
        self.statistics.start_time = datetime.now()
        
        entries_list = list(log_entries)
        self.statistics.total_entries_processed = len(entries_list)
        
        # Filter entries that have enrichment data with geographic info
        enriched_entries = []
        for entry in entries_list:
            if (hasattr(entry, 'enrichment_data') and 
                entry.enrichment_data and 
                'ip_reputation' in entry.enrichment_data):
                enriched_entries.append(entry)
        
        if not enriched_entries:
            # No geographic data available, skip analysis
            self.statistics.end_time = datetime.now()
            return
        
        # Group by IP address
        ip_entries = defaultdict(list)
        for entry in enriched_entries:
            ip_entries[str(entry.ip_address)].append(entry)
        
        for ip_address, entries in ip_entries.items():
            try:
                # Sort entries by timestamp
                entries.sort(key=lambda x: x.timestamp)
                
                # Analyze geographic patterns
                yield from self._detect_rapid_geo_changes(ip_address, entries)
                yield from self._detect_high_risk_country_activity(ip_address, entries)
                yield from self._detect_impossible_travel(ip_address, entries)
                
            except Exception as e:
                self.statistics.processing_errors += 1
                self.statistics.error_details.append(f"Error analyzing geographic patterns for IP {ip_address}: {str(e)}")
                continue
        
        self.statistics.end_time = datetime.now()
    
    def _extract_country_code(self, entry: ParsedLogEntry) -> Optional[str]:
        """Extract country code from enrichment data."""
        try:
            if (hasattr(entry, 'enrichment_data') and 
                entry.enrichment_data and 
                'ip_reputation' in entry.enrichment_data):
                
                # Check AbuseIPDB data first
                abuseipdb = entry.enrichment_data['ip_reputation'].get('abuseipdb', {})
                if 'country_code' in abuseipdb:
                    return abuseipdb['country_code']
                
                # Could add other providers' geographic data here
                
        except (AttributeError, KeyError, TypeError):
            pass
        
        return None
    
    def _detect_rapid_geo_changes(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect rapid geographic location changes."""
        if len(entries) < self.geo_change_threshold:
            return
        
        countries_timeline = []
        unique_countries = set()
        
        for entry in entries:
            country = self._extract_country_code(entry)
            if country:
                countries_timeline.append({
                    'timestamp': entry.timestamp,
                    'country': country,
                    'entry': entry
                })
                unique_countries.add(country)
        
        if len(unique_countries) >= self.geo_change_threshold:
            # Analyze timing of country changes
            rapid_changes = []
            
            for i in range(len(countries_timeline)):
                window_start = countries_timeline[i]['timestamp']
                window_end = window_start + timedelta(seconds=self.session_time_window)
                
                # Count unique countries in this window
                window_countries = set()
                for j in range(i, len(countries_timeline)):
                    if countries_timeline[j]['timestamp'] <= window_end:
                        window_countries.add(countries_timeline[j]['country'])
                    else:
                        break
                
                if len(window_countries) >= self.geo_change_threshold:
                    rapid_changes.append({
                        'start_time': window_start,
                        'countries': list(window_countries),
                        'count': len(window_countries)
                    })
            
            if rapid_changes:
                max_countries = max(change['count'] for change in rapid_changes)
                risk_score = min(85 + max_countries * 5, 100)
                
                finding = Finding(
                    log_entry=entries[-1],
                    finding_type="Rapid Geographic Changes",
                    description=f"Detected {max_countries} countries within {self.session_time_window//60} minutes from IP {ip_address}",
                    risk_score=risk_score,
                    enrichment_data={
                        'pattern_type': 'rapid_geographic_changes',
                        'ip_address': ip_address,
                        'unique_countries': list(unique_countries),
                        'max_countries_in_window': max_countries,
                        'rapid_changes': rapid_changes,
                        'geo_threshold': self.geo_change_threshold
                    }
                )
                
                self.statistics.total_findings += 1
                if 80 <= risk_score <= 100:
                    self.statistics.high_risk_count += 1
                elif 50 <= risk_score <= 79:
                    self.statistics.medium_risk_count += 1
                else:
                    self.statistics.low_risk_count += 1
                
                yield finding
    
    def _detect_high_risk_country_activity(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect elevated activity from high-risk countries."""
        country_activity = defaultdict(lambda: {'total': 0, 'failed_logins': 0, 'entries': []})
        
        for entry in entries:
            country = self._extract_country_code(entry)
            if country:
                country_activity[country]['total'] += 1
                country_activity[country]['entries'].append(entry)
                if hasattr(entry, 'status_code') and entry.status_code in [401, 403]:
                    country_activity[country]['failed_logins'] += 1
        
        # Check each high-risk country
        for country, activity in country_activity.items():
            if country in self.high_risk_countries:
                risk_multiplier = self.high_risk_countries[country]
                
                # Calculate time span for frequency analysis
                if len(activity['entries']) > 1:
                    time_span = (activity['entries'][-1].timestamp - activity['entries'][0].timestamp).total_seconds()
                    hourly_requests = activity['total'] / max(time_span / 3600, 1)
                    hourly_failed_logins = activity['failed_logins'] / max(time_span / 3600, 1)
                else:
                    hourly_requests = activity['total']
                    hourly_failed_logins = activity['failed_logins']
                
                # Apply risk multiplier to thresholds
                adjusted_request_threshold = self.geo_frequency_thresholds['base_requests_per_hour'] / risk_multiplier
                adjusted_failed_threshold = self.geo_frequency_thresholds['base_failed_logins_per_hour'] / risk_multiplier
                
                # Check if activity exceeds adjusted thresholds
                if (hourly_requests > adjusted_request_threshold or 
                    hourly_failed_logins > adjusted_failed_threshold):
                    
                    base_risk = 70 if hourly_requests > adjusted_request_threshold else 65
                    risk_score = min(int(base_risk * risk_multiplier), 95)
                    
                    finding = Finding(
                        log_entry=activity['entries'][-1],
                        finding_type=f"High-Risk Country Activity ({country})",
                        description=f"Elevated activity from high-risk country {country}: {activity['total']} requests, {activity['failed_logins']} failed logins",
                        risk_score=risk_score,
                        enrichment_data={
                            'pattern_type': 'high_risk_country_activity',
                            'ip_address': ip_address,
                            'country': country,
                            'risk_multiplier': risk_multiplier,
                            'total_requests': activity['total'],
                            'failed_logins': activity['failed_logins'],
                            'hourly_requests': hourly_requests,
                            'hourly_failed_logins': hourly_failed_logins,
                            'adjusted_thresholds': {
                                'requests': adjusted_request_threshold,
                                'failed_logins': adjusted_failed_threshold
                            }
                        }
                    )
                    
                    self.statistics.total_findings += 1
                    if 80 <= risk_score <= 100:
                        self.statistics.high_risk_count += 1
                    elif 50 <= risk_score <= 79:
                        self.statistics.medium_risk_count += 1
                    else:
                        self.statistics.low_risk_count += 1
                    
                    yield finding
    
    def _detect_impossible_travel(self, ip_address: str, entries: List[ParsedLogEntry]) -> Generator[Finding, None, None]:
        """Detect geographically impossible travel patterns."""
        if len(entries) < 2:
            return
        
        country_changes = []
        prev_country = None
        prev_timestamp = None
        
        for entry in entries:
            country = self._extract_country_code(entry)
            if country and country != prev_country:
                if prev_country is not None:
                    time_diff = (entry.timestamp - prev_timestamp).total_seconds()
                    country_changes.append({
                        'from_country': prev_country,
                        'to_country': country,
                        'time_diff_minutes': time_diff / 60,
                        'timestamp': entry.timestamp,
                        'entry': entry
                    })
                prev_country = country
                prev_timestamp = entry.timestamp
        
        # Look for rapid international changes (likely impossible travel)
        impossible_travel = []
        for change in country_changes:
            # If country change happens within 30 minutes, it's likely impossible
            if change['time_diff_minutes'] < 30:
                impossible_travel.append(change)
        
        if impossible_travel:
            risk_score = min(90 + len(impossible_travel) * 2, 100)
            
            countries_involved = set()
            for travel in impossible_travel:
                countries_involved.add(travel['from_country'])
                countries_involved.add(travel['to_country'])
            
            finding = Finding(
                log_entry=impossible_travel[-1]['entry'],
                finding_type="Impossible Travel Pattern",
                description=f"Detected {len(impossible_travel)} rapid country changes from IP {ip_address} (impossible travel)",
                risk_score=risk_score,
                enrichment_data={
                    'pattern_type': 'impossible_travel',
                    'ip_address': ip_address,
                    'impossible_travels': impossible_travel,
                    'countries_involved': list(countries_involved),
                    'total_rapid_changes': len(impossible_travel)
                }
            )
            
            self.statistics.total_findings += 1
            if 80 <= risk_score <= 100:
                self.statistics.high_risk_count += 1
            elif 50 <= risk_score <= 79:
                self.statistics.medium_risk_count += 1
            else:
                self.statistics.low_risk_count += 1
            
            yield finding


class DetectionEngine:
    """Main detection engine that orchestrates multiple detectors."""
    
    def __init__(self, enable_advanced_frequency: bool = True, 
                 enable_scanning_detection: bool = True,
                 enable_behavioral_analysis: bool = True,
                 enable_geographic_analysis: bool = True):
        # Core detectors (always enabled for backward compatibility)
        self.keyword_detector = KeywordDetector()
        self.frequency_detector = FrequencyDetector()
        self.detectors = [self.keyword_detector, self.frequency_detector]
        
        # Advanced detectors (configurable)
        self.scanning_detector = None
        self.behavioral_detector = None
        self.geographic_detector = None
        
        if enable_scanning_detection:
            self.scanning_detector = ScanningDetector()
            self.detectors.append(self.scanning_detector)
        
        if enable_behavioral_analysis:
            self.behavioral_detector = BehavioralDetector()
            self.detectors.append(self.behavioral_detector)
        
        if enable_geographic_analysis:
            self.geographic_detector = GeographicDetector()
            self.detectors.append(self.geographic_detector)
        
        # Configuration flags
        self.enable_advanced_frequency = enable_advanced_frequency
        self.enable_scanning_detection = enable_scanning_detection
        self.enable_behavioral_analysis = enable_behavioral_analysis
        self.enable_geographic_analysis = enable_geographic_analysis
    
    def analyze_entries(self, log_entries: List[ParsedLogEntry]) -> DetectionResult:
        """Analyze log entries using all detectors and return comprehensive results."""
        result = DetectionResult()
        result.processing_start = datetime.now()
        result.total_entries_analyzed = len(log_entries)
        
        all_findings = []
        
        # Run each detector
        for detector in self.detectors:
            detector.reset_statistics()
            findings = list(detector.detect_patterns(iter(log_entries)))
            all_findings.extend(findings)
        
        # Sort findings by risk score (highest first) and timestamp
        all_findings.sort(key=lambda f: (-f.risk_score, f.detected_at))
        
        result.findings = all_findings
        result.processing_end = datetime.now()
        result.update_statistics()
        
        return result
    
    def get_combined_statistics(self) -> Dict[str, DetectionStatistics]:
        """Get statistics from all detectors."""
        stats = {
            'keyword_detector': self.keyword_detector.get_statistics(),
            'frequency_detector': self.frequency_detector.get_statistics()
        }
        
        # Add advanced detector statistics if enabled
        if self.scanning_detector:
            stats['scanning_detector'] = self.scanning_detector.get_statistics()
        
        if self.behavioral_detector:
            stats['behavioral_detector'] = self.behavioral_detector.get_statistics()
        
        if self.geographic_detector:
            stats['geographic_detector'] = self.geographic_detector.get_statistics()
        
        return stats
    
    def get_detector_summary(self) -> Dict[str, str]:
        """Get a summary of enabled detectors."""
        summary = {
            'keyword_detector': 'enabled',
            'frequency_detector': 'enabled',
            'scanning_detector': 'enabled' if self.enable_scanning_detection else 'disabled',
            'behavioral_detector': 'enabled' if self.enable_behavioral_analysis else 'disabled',
            'geographic_detector': 'enabled' if self.enable_geographic_analysis else 'disabled'
        }
        
        return summary 