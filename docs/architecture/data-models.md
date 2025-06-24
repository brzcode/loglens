# Data Models

### Core Application Entities / Domain Objects

#### ParsedLogEntry

  * **Description:** Represents a single, structured log line after parsing.
  * **Schema / Interface Definition:**
    ```python
    # Using Pydantic for validation
    from pydantic import BaseModel, IPAddress
    from datetime import datetime

    class ParsedLogEntry(BaseModel):
        ip_address: IPAddress
        timestamp: datetime
        request_line: str
        status_code: int
        raw_line: str
    ```

#### Finding

  * **Description:** Represents a single suspicious event detected in the logs.
  * **Schema / Interface Definition:**
    ```python
    from typing import Optional

    class Finding(BaseModel):
        log_entry: ParsedLogEntry
        finding_type: str # e.g., "Keyword Match", "High Frequency"
        description: str # e.g., "Found suspicious keyword 'sqlmap'"
        risk_score: int = 50 # Default risk, to be adjusted
        enrichment_data: Optional[dict] = None
    ```
