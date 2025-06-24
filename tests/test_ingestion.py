"""Tests for log file ingestion functionality."""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime
from unittest.mock import patch

from src.loglens.services.ingestion import LogFileIngester, IngestionError
from src.loglens.models import RawLogLine, FileMetadata, IngestionResult


class TestLogFileIngester:
    """Test the LogFileIngester class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.ingester = LogFileIngester(show_progress=False)  # Disable progress for tests

    def create_temp_log_file(self, content: str, encoding: str = 'utf-8') -> Path:
        """Create a temporary log file with given content."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False, encoding=encoding)
        temp_file.write(content)
        temp_file.close()
        return Path(temp_file.name)

    def test_validate_file_success(self) -> None:
        """Test successful file validation."""
        content = "Test log line 1\nTest log line 2\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            metadata = self.ingester.validate_file(temp_file)
            
            assert metadata.file_path == temp_file
            assert metadata.file_size > 0
            assert metadata.encoding == 'utf-8'
            assert isinstance(metadata.ingestion_start, datetime)
        finally:
            os.unlink(temp_file)

    def test_validate_file_not_exists(self) -> None:
        """Test validation with non-existent file."""
        non_existent = Path("non_existent_file.log")
        
        with pytest.raises(IngestionError, match="File does not exist"):
            self.ingester.validate_file(non_existent)

    def test_validate_file_empty(self) -> None:
        """Test validation with empty file."""
        temp_file = self.create_temp_log_file("")
        
        try:
            with pytest.raises(IngestionError, match="File is empty"):
                self.ingester.validate_file(temp_file)
        finally:
            os.unlink(temp_file)

    def test_validate_file_too_large(self) -> None:
        """Test validation with file exceeding size limit."""
        # Test by temporarily modifying the class constant
        original_max_size = LogFileIngester.MAX_FILE_SIZE_BYTES
        try:
            # Set max size to 1 byte to trigger the limit
            LogFileIngester.MAX_FILE_SIZE_BYTES = 1
            
            temp_file = self.create_temp_log_file("more than 1 byte")
            
            try:
                with pytest.raises(IngestionError, match="File too large"):
                    self.ingester.validate_file(temp_file)
            finally:
                os.unlink(temp_file)
        finally:
            # Restore original max size
            LogFileIngester.MAX_FILE_SIZE_BYTES = original_max_size

    def test_encoding_detection_utf8(self) -> None:
        """Test UTF-8 encoding detection."""
        content = "UTF-8 content: 🔍 Unicode characters\n"
        temp_file = self.create_temp_log_file(content, encoding='utf-8')
        
        try:
            metadata = self.ingester.validate_file(temp_file)
            assert metadata.encoding == 'utf-8'
        finally:
            os.unlink(temp_file)

    def test_encoding_detection_ascii(self) -> None:
        """Test ASCII encoding detection."""
        content = "Simple ASCII content\n"
        temp_file = self.create_temp_log_file(content, encoding='ascii')
        
        try:
            metadata = self.ingester.validate_file(temp_file)
            assert metadata.encoding in ['utf-8', 'ascii']  # Both are valid for ASCII content
        finally:
            os.unlink(temp_file)

    def test_ingest_file_lines_generator(self) -> None:
        """Test line-by-line ingestion using generator."""
        content = "Line 1\nLine 2\nLine 3\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            generator = self.ingester.ingest_file_lines(temp_file)
            lines = []
            
            # Collect all lines from generator
            for line in generator:
                lines.append(line)
                assert isinstance(line, RawLogLine)
                assert line.file_path == str(temp_file)
                assert isinstance(line.timestamp_read, datetime)
            
            # Check we got all lines
            assert len(lines) == 3
            assert lines[0].line_number == 1
            assert lines[0].content == "Line 1"
            assert lines[1].line_number == 2
            assert lines[1].content == "Line 2"
            assert lines[2].line_number == 3
            assert lines[2].content == "Line 3"
            
            # Get the result
            try:
                result = next(generator)
                assert isinstance(result, IngestionResult)
                assert result.success == True
                assert result.lines_processed == 3
                assert result.metadata.line_count == 3
            except StopIteration as e:
                if e.value:
                    result = e.value
                    assert isinstance(result, IngestionResult)
                    assert result.success == True
                    assert result.lines_processed == 3
                
        finally:
            os.unlink(temp_file)

    def test_ingest_file_to_list(self) -> None:
        """Test ingestion to complete list."""
        content = "Log entry 1\nLog entry 2\nLog entry 3\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            # Check lines
            assert len(lines) == 3
            assert all(isinstance(line, RawLogLine) for line in lines)
            assert lines[0].content == "Log entry 1"
            assert lines[1].content == "Log entry 2"
            assert lines[2].content == "Log entry 3"
            
            # Check result
            assert isinstance(result, IngestionResult)
            assert result.success == True
            assert result.lines_processed == 3
            assert result.metadata.line_count == 3
            assert result.duration_seconds is not None
            assert result.duration_seconds >= 0
            
        finally:
            os.unlink(temp_file)

    def test_ingest_removes_newlines(self) -> None:
        """Test that newlines are properly stripped from content."""
        # Simple test with clear line endings
        content = "First line\nSecond line\nThird line"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            # Check that we have the right number of lines
            assert len(lines) == 3
            assert lines[0].content == "First line"
            assert lines[1].content == "Second line"
            assert lines[2].content == "Third line"
            
            # Verify no trailing newlines in content
            for line in lines:
                assert not line.content.endswith('\n')
                assert not line.content.endswith('\r')
            
        finally:
            os.unlink(temp_file)

    def test_ingest_large_file_simulation(self) -> None:
        """Test ingestion with a simulated larger file."""
        # Create a file with many lines to test progress tracking
        lines_content = [f"Log line {i}" for i in range(1, 2001)]  # 2000 lines
        content = "\n".join(lines_content) + "\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            assert len(lines) == 2000
            assert result.lines_processed == 2000
            assert result.metadata.line_count == 2000
            assert lines[0].content == "Log line 1"
            assert lines[999].content == "Log line 1000"
            assert lines[1999].content == "Log line 2000"
            
        finally:
            os.unlink(temp_file)

    def test_ingest_with_progress_enabled(self) -> None:
        """Test ingestion with progress indicators enabled."""
        ingester_with_progress = LogFileIngester(show_progress=True)
        content = "Line 1\nLine 2\nLine 3\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            # This should work without errors even with progress enabled
            lines, result = ingester_with_progress.ingest_file_to_list(temp_file)
            assert len(lines) == 3
            assert result.success == True
            
        finally:
            os.unlink(temp_file)

    def test_file_metadata_tracking(self) -> None:
        """Test that file metadata is properly tracked."""
        content = "Sample log content\nAnother line\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            metadata = result.metadata
            assert metadata.file_path == temp_file
            # File size should be close to content size (allowing for platform differences in line endings)
            assert abs(metadata.file_size - len(content.encode('utf-8'))) <= 2
            assert metadata.line_count == 2
            assert metadata.encoding == 'utf-8'
            assert metadata.ingestion_start <= metadata.ingestion_end
            
        finally:
            os.unlink(temp_file)

    def test_error_handling_io_error(self) -> None:
        """Test error handling for I/O errors."""
        content = "Test content\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            # Delete the file while we're trying to read it (simulate I/O error)
            os.unlink(temp_file)
            
            with pytest.raises(IngestionError, match="File does not exist"):
                self.ingester.validate_file(temp_file)
                
        except FileNotFoundError:
            # File already deleted, which is expected
            pass

    def test_empty_lines_handling(self) -> None:
        """Test handling of empty lines in log files."""
        content = "Line 1\n\nLine 3\n\n\nLine 6\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            # Should preserve empty lines
            assert len(lines) == 6
            assert lines[0].content == "Line 1"
            assert lines[1].content == ""  # Empty line
            assert lines[2].content == "Line 3"
            assert lines[3].content == ""  # Empty line
            assert lines[4].content == ""  # Empty line
            assert lines[5].content == "Line 6"
            
        finally:
            os.unlink(temp_file)

    def test_line_numbering(self) -> None:
        """Test that line numbers are correctly assigned."""
        content = "First\nSecond\nThird\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            assert lines[0].line_number == 1
            assert lines[1].line_number == 2
            assert lines[2].line_number == 3
            
        finally:
            os.unlink(temp_file)

    def test_ingestion_result_properties(self) -> None:
        """Test IngestionResult computed properties."""
        content = "Test line\n"
        temp_file = self.create_temp_log_file(content)
        
        try:
            lines, result = self.ingester.ingest_file_to_list(temp_file)
            
            # Test duration calculation
            duration = result.duration_seconds
            assert duration is not None
            assert duration >= 0
            assert duration < 10  # Should be very fast for small file
            
        finally:
            os.unlink(temp_file) 