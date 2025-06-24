"""Log file ingestion service."""

import os
from pathlib import Path
from typing import Generator, Iterator, Optional
from datetime import datetime
import typer

from ..models import RawLogLine, FileMetadata, IngestionResult


class IngestionError(Exception):
    """Custom exception for ingestion-related errors."""
    pass


class LogFileIngester:
    """Service for ingesting log files with validation and error handling."""
    
    # File size threshold for showing progress (1MB)
    PROGRESS_THRESHOLD_BYTES = 1024 * 1024
    
    # Maximum supported file size (100MB)
    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
    
    # Supported text encodings to try
    SUPPORTED_ENCODINGS = ['utf-8', 'ascii', 'latin-1']
    
    def __init__(self, show_progress: bool = True) -> None:
        """Initialize the ingester.
        
        Args:
            show_progress: Whether to show progress indicators for large files
        """
        self.show_progress = show_progress
    
    def validate_file(self, file_path: Path) -> FileMetadata:
        """Validate a log file and return its metadata.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            FileMetadata with basic file information
            
        Raises:
            IngestionError: If file validation fails
        """
        # Check if file exists
        if not file_path.exists():
            raise IngestionError(f"File does not exist: {file_path}")
        
        # Check if it's actually a file
        if not file_path.is_file():
            raise IngestionError(f"Path is not a file: {file_path}")
        
        # Check file permissions
        if not os.access(file_path, os.R_OK):
            raise IngestionError(f"File is not readable: {file_path}")
        
        # Get file size
        file_size = file_path.stat().st_size
        
        # Check if file is empty
        if file_size == 0:
            raise IngestionError(f"File is empty: {file_path}")
        
        # Check file size limit
        if file_size > self.MAX_FILE_SIZE_BYTES:
            size_mb = file_size / (1024 * 1024)
            limit_mb = self.MAX_FILE_SIZE_BYTES / (1024 * 1024)
            raise IngestionError(
                f"File too large: {size_mb:.1f}MB (limit: {limit_mb}MB): {file_path}"
            )
        
        # Detect encoding
        encoding = self._detect_encoding(file_path)
        
        return FileMetadata(
            file_path=file_path,
            file_size=file_size,
            encoding=encoding
        )
    
    def _detect_encoding(self, file_path: Path) -> str:
        """Detect file encoding by trying common encodings.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Detected encoding string
            
        Raises:
            IngestionError: If no supported encoding works
        """
        # Read first 1KB to detect encoding
        sample_size = min(1024, file_path.stat().st_size)
        
        for encoding in self.SUPPORTED_ENCODINGS:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    f.read(sample_size)
                return encoding
            except UnicodeDecodeError:
                continue
        
        raise IngestionError(
            f"Could not detect supported text encoding for file: {file_path}"
        )
    
    def _show_progress(self, file_size: int, lines_read: int, bytes_read: int) -> None:
        """Show progress for large file processing.
        
        Args:
            file_size: Total file size in bytes
            lines_read: Number of lines processed
            bytes_read: Number of bytes processed
        """
        if not self.show_progress or file_size < self.PROGRESS_THRESHOLD_BYTES:
            return
        
        percentage = min(100, (bytes_read / file_size) * 100)
        size_mb = file_size / (1024 * 1024)
        
        typer.echo(
            f"\r📄 Processing: {lines_read:,} lines, "
            f"{percentage:.1f}% of {size_mb:.1f}MB",
            nl=False
        )
    
    def ingest_file_lines(self, file_path: Path) -> Generator[RawLogLine, None, IngestionResult]:
        """Ingest a log file line by line using generator pattern.
        
        Args:
            file_path: Path to the log file to ingest
            
        Yields:
            RawLogLine objects for each line in the file
            
        Returns:
            IngestionResult with processing summary
            
        Raises:
            IngestionError: If ingestion fails
        """
        # Validate file first
        metadata = self.validate_file(file_path)
        
        result = IngestionResult(metadata=metadata)
        file_path_str = str(file_path)
        
        try:
            with open(file_path, 'r', encoding=metadata.encoding) as file:
                bytes_read = 0
                line_number = 0
                
                for line in file:
                    line_number += 1
                    bytes_read += len(line.encode(metadata.encoding))
                    
                    # Create RawLogLine object
                    raw_line = RawLogLine(
                        line_number=line_number,
                        content=line.rstrip('\n\r'),  # Remove trailing newlines
                        file_path=file_path_str,
                        timestamp_read=datetime.now()
                    )
                    
                    # Show progress for large files
                    if line_number % 1000 == 0:  # Update every 1000 lines
                        self._show_progress(metadata.file_size, line_number, bytes_read)
                    
                    yield raw_line
                    result.lines_processed += 1
                
                # Final progress update
                if self.show_progress and metadata.file_size >= self.PROGRESS_THRESHOLD_BYTES:
                    self._show_progress(metadata.file_size, line_number, bytes_read)
                    typer.echo()  # New line after progress
                
                # Update metadata
                result.metadata.line_count = line_number
                result.metadata.ingestion_end = datetime.now()
                
        except UnicodeDecodeError as e:
            error_msg = f"Encoding error reading file {file_path}: {str(e)}"
            result.errors.append(error_msg)
            result.success = False
            raise IngestionError(error_msg)
        
        except IOError as e:
            error_msg = f"I/O error reading file {file_path}: {str(e)}"
            result.errors.append(error_msg)
            result.success = False
            raise IngestionError(error_msg)
        
        return result
    
    def ingest_file_to_list(self, file_path: Path) -> tuple[list[RawLogLine], IngestionResult]:
        """Ingest entire file into memory as a list.
        
        Args:
            file_path: Path to the log file to ingest
            
        Returns:
            Tuple of (list of RawLogLine objects, IngestionResult)
            
        Raises:
            IngestionError: If ingestion fails
        """
        lines = []
        result = None
        
        # Use generator to read lines
        generator = self.ingest_file_lines(file_path)
        
        try:
            for line in generator:
                lines.append(line)
        except StopIteration:
            pass
        
        # Get the result from generator
        try:
            result = next(generator)
        except StopIteration as e:
            if e.value:
                result = e.value
            else:
                # Fallback in case generator doesn't return properly
                metadata = self.validate_file(file_path)
                metadata.line_count = len(lines)
                metadata.ingestion_end = datetime.now()
                result = IngestionResult(
                    metadata=metadata,
                    lines_processed=len(lines)
                )
        
        return lines, result 