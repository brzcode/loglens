# Security Best Practices

  * **Secrets Management:** The `ABUSEIPDB_API_KEY` must not be hardcoded. It will be loaded from an environment variable. The `README.md` will instruct users on how to set this up.
  * **Dependency Security:** The CI pipeline will include a step to scan dependencies for known vulnerabilities (e.g., using `pip-audit`).
  * **Input Sanitization:** While the tool is for analysis, not execution, all data from the external API will be validated against our Pydantic models to prevent unexpected data types from causing issues.