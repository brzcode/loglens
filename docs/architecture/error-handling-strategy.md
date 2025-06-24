# Error Handling Strategy

  * **General Approach:** Use specific, custom exceptions inheriting from a base `LogLensError` class.
  * **Logging:** Use Python's built-in `logging` module. Log messages will be simple text formatted for clarity on the console. Errors will be logged to `stderr`, and normal output to `stdout`.
  * **Specific Handling Patterns:**
      * **File I/O:** `FileNotFoundError` and `PermissionError` will be caught and translated into user-friendly error messages.
      * **Parsing:** The parser will skip malformed lines and log a warning to `stderr` for each one, but will not halt execution unless a configurable threshold of errors is met.
      * **External API Calls:** The `EnrichmentService` will use a `try...except` block to catch `httpx` exceptions (e.g., `ConnectTimeout`, `HTTPStatusError`). On failure, it will log a warning and proceed without enrichment data for that IP.
