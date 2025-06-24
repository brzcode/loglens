"""LogLens data models using Pydantic."""

from datetime import datetime
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict


class RawLogLine(BaseModel):
    """Represents a single raw log line after ingestion."""
    
    line_number: int = Field(..., description="Line number in the file (1-indexed)")
    content: str = Field(..., description="Raw content of the log line")
    file_path: str = Field(..., description="Path to the source file")
    timestamp_read: datetime = Field(default_factory=datetime.now, description="When the line was read")


class FileMetadata(BaseModel):
    """Metadata about an ingested log file."""
    
    file_path: Path = Field(..., description="Path to the log file")
    file_size: int = Field(..., description="File size in bytes")
    line_count: int = Field(default=0, description="Number of lines in the file")
    encoding: str = Field(default="utf-8", description="File encoding detected/used")
    ingestion_start: datetime = Field(default_factory=datetime.now, description="When ingestion started")
    ingestion_end: Optional[datetime] = Field(None, description="When ingestion completed")


class IngestionResult(BaseModel):
    """Result container for log file ingestion process."""
    
    metadata: FileMetadata = Field(..., description="File metadata")
    lines_processed: int = Field(default=0, description="Number of lines successfully processed")
    errors: List[str] = Field(default_factory=list, description="Any errors encountered during ingestion")
    success: bool = Field(default=True, description="Whether ingestion completed successfully")
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate ingestion duration in seconds."""
        if self.metadata.ingestion_end and self.metadata.ingestion_start:
            return (self.metadata.ingestion_end - self.metadata.ingestion_start).total_seconds()
        return None


class ParsedLogEntry(BaseModel):
    """Represents a parsed log entry with structured fields."""
    
    ip_address: IPvAnyAddress = Field(..., description="Client IP address")
    timestamp: datetime = Field(..., description="Request timestamp")
    request_line: str = Field(..., description="HTTP request line (method, path, protocol)")
    status_code: int = Field(..., description="HTTP response status code")
    raw_line: str = Field(..., description="Original raw log line")
    user_agent: Optional[str] = Field(None, description="User agent string")
    bytes_sent: Optional[int] = Field(None, description="Number of bytes sent in response")
    referer: Optional[str] = Field(None, description="HTTP referer header")
    remote_user: Optional[str] = Field(None, description="Remote user identifier")
    
    model_config = ConfigDict(validate_assignment=True)


class Finding(BaseModel):
    """Represents a security finding detected in log data."""
    
    log_entry: ParsedLogEntry = Field(..., description="The log entry that triggered this finding")
    finding_type: str = Field(..., description="Type of finding (e.g., 'Keyword Match', 'High Frequency')")
    description: str = Field(..., description="Human-readable description of the finding")
    risk_score: int = Field(50, description="Risk score (1-100): Info(1-19), Low(20-49), Medium(50-79), High(80-100)")
    enrichment_data: Optional[dict] = Field(None, description="Additional context data for the finding")
    detected_at: datetime = Field(default_factory=datetime.now, description="When the finding was detected")
    
    model_config = ConfigDict(validate_assignment=True)


class DetectionResult(BaseModel):
    """Container for detection analysis results."""
    
    findings: List[Finding] = Field(default_factory=list, description="List of security findings detected")
    total_entries_analyzed: int = Field(0, description="Total number of log entries analyzed")
    total_findings: int = Field(0, description="Total number of findings detected")
    high_risk_findings: int = Field(0, description="Number of high-risk findings (80-100)")
    medium_risk_findings: int = Field(0, description="Number of medium-risk findings (50-79)")
    low_risk_findings: int = Field(0, description="Number of low-risk findings (20-49)")
    info_findings: int = Field(0, description="Number of info findings (1-19)")
    processing_start: Optional[datetime] = Field(None, description="When detection processing started")
    processing_end: Optional[datetime] = Field(None, description="When detection processing completed")
    
    @property
    def processing_time_seconds(self) -> Optional[float]:
        """Calculate detection processing time in seconds."""
        if self.processing_start and self.processing_end:
            return (self.processing_end - self.processing_start).total_seconds()
        return None
    
    def update_statistics(self):
        """Update finding statistics based on current findings list."""
        self.total_findings = len(self.findings)
        self.high_risk_findings = sum(1 for f in self.findings if 80 <= f.risk_score <= 100)
        self.medium_risk_findings = sum(1 for f in self.findings if 50 <= f.risk_score <= 79)
        self.low_risk_findings = sum(1 for f in self.findings if 20 <= f.risk_score <= 49)
        self.info_findings = sum(1 for f in self.findings if 1 <= f.risk_score <= 19)


class DetectionStatistics(BaseModel):
    """Statistics for detection processing."""
    
    total_entries_processed: int = Field(0, description="Total log entries processed")
    total_findings: int = Field(0, description="Total findings detected")
    high_risk_count: int = Field(0, description="High-risk findings count")
    medium_risk_count: int = Field(0, description="Medium-risk findings count")
    low_risk_count: int = Field(0, description="Low-risk findings count")
    info_count: int = Field(0, description="Info-level findings count")
    processing_errors: int = Field(0, description="Number of processing errors")
    start_time: Optional[datetime] = Field(None, description="Detection start time")
    end_time: Optional[datetime] = Field(None, description="Detection end time")
    error_details: List[str] = Field(default_factory=list, description="Detailed error messages")
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_entries_processed == 0:
            return 0.0
        successful = self.total_entries_processed - self.processing_errors
        return (successful / self.total_entries_processed) * 100
    
    @property
    def processing_time(self) -> float:
        """Calculate processing time in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0 