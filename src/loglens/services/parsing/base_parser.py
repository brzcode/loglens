"""Base parser abstract class for LogLens parsing services."""

from abc import ABC, abstractmethod
from typing import Generator, Iterator, List, Tuple
from ...models import RawLogLine, ParsedLogEntry


class ParsedResult:
    """Container for parsing results with success/error tracking."""
    
    def __init__(self, success: bool, entry: ParsedLogEntry = None, error: str = None, line_number: int = None):
        self.success = success
        self.entry = entry
        self.error = error
        self.line_number = line_number


class ParsingStatistics:
    """Tracks parsing statistics for reporting."""
    
    def __init__(self):
        self.total_lines = 0
        self.successful_parses = 0
        self.errors = 0
        self.start_time = None
        self.end_time = None
        self.error_details = []
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_lines == 0:
            return 0.0
        return (self.successful_parses / self.total_lines) * 100
    
    @property
    def processing_time(self) -> float:
        """Calculate processing time in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class BaseParser(ABC):
    """Abstract base class for log parsers."""
    
    def __init__(self):
        self.statistics = ParsingStatistics()
    
    @abstractmethod
    def parse_line(self, raw_line: RawLogLine) -> ParsedResult:
        """Parse a single log line.
        
        Args:
            raw_line: RawLogLine object containing the log data
            
        Returns:
            ParsedResult containing success/failure and parsed data or error
        """
        pass
    
    def parse_batch(self, raw_lines: Iterator[RawLogLine]) -> Generator[ParsedResult, None, None]:
        """Parse a batch of log lines using generator pattern for memory efficiency.
        
        Args:
            raw_lines: Iterator of RawLogLine objects
            
        Yields:
            ParsedResult for each processed line
        """
        from datetime import datetime
        
        self.statistics.start_time = datetime.now()
        line_number = 0
        
        for raw_line in raw_lines:
            line_number += 1
            self.statistics.total_lines += 1
            
            result = self.parse_line(raw_line)
            result.line_number = line_number
            
            if result.success:
                self.statistics.successful_parses += 1
            else:
                self.statistics.errors += 1
                self.statistics.error_details.append({
                    'line_number': line_number,
                    'error': result.error,
                    'raw_line': raw_line.content[:100] + '...' if len(raw_line.content) > 100 else raw_line.content
                })
            
            yield result
        
        self.statistics.end_time = datetime.now()
    
    def get_statistics(self) -> ParsingStatistics:
        """Get current parsing statistics."""
        return self.statistics
    
    def reset_statistics(self):
        """Reset parsing statistics for new batch."""
        self.statistics = ParsingStatistics() 