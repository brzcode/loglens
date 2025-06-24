# 2. Functional Requirements (MVP)

* **Log File Ingestion:** The system shall accept a single log file as an input parameter.
* **Log Parsing:** The system shall parse a specified log format, with the initial version focused on Apache Access Logs. The system must be designed to allow for other parser modules in the future.
* **Pattern Detection:** The system shall analyze the parsed log data to detect a predefined set of suspicious patterns, including but not limited to:

  * Repeated failed login attempts.
  * Common web attack keywords (e.g., SQL injection, command execution patterns).
  * Anomalous request frequency from a single IP address.
* **IP Reputation Enrichment:** For any suspicious IP address identified, the system shall perform an automated lookup against a free, public IP reputation service to retrieve and store additional context.
* **Summary Report Generation:** The system shall generate a human-readable, text-based summary report displayed directly in the user's console.
* **Report Prioritization:** The summary report shall be prioritized to display the top 3-5 most critical findings first.
* **Noise Filtering:** The summary report shall only include suspicious findings, filtering out all benign log entries to reduce noise for the analyst.
