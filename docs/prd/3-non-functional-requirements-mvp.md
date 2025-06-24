# 3. Non-Functional Requirements (MVP)

**Performance:**

* The tool must be able to process a large log file (e.g., up to 200MB) and produce a summary report in under 20 seconds to meet the overall goal of "triage under 30 seconds."
* Memory usage should remain reasonable and not spike excessively, ensuring it can run on a standard analyst workstation.

**Usability:**

* The Command-Line Interface (CLI) must be simple, requiring no more than two arguments to run an analysis (e.g., loglens \<parser\_type> \<file\_path>).
* The final report output must be clear, concise, and formatted for easy readability in a standard terminal. It should use spacing and simple markers (\[!], \[+]) to improve scannability.
* Error messages must be user-friendly and provide clear guidance on what went wrong (e.g., "Error: File not found at path '...").

**Reliability:**

* The log parser must be robust enough to handle common variations and malformed lines within its target log format without crashing.
* The tool must handle failures from the external IP reputation service gracefully (e.g., by skipping the enrichment for that IP and noting the failure in the output, rather than halting the entire analysis).

**Installation:**

* The tool must be easy to install via standard Python packaging tools (e.g., pip).
* It must have minimal external dependencies to avoid installation conflicts and ensure it is lightweight.
