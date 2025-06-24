# Overall Testing Strategy

  * **Unit Tests:** Will be written for all services and logic modules using `pytest`. All external dependencies (API calls, file system) will be mocked using `pytest-mock`. Test files will live in the `tests/` directory.
  * **Integration Tests:** A small number of integration tests will verify the orchestration logic, ensuring components work together correctly. These will use real (but test-specific) components where possible, mocking only the file system and external API.
  * **Manual Testing:** The `manual_test_scripts` defined in the PRD will be created as shell scripts in the `/scripts` directory to guide human validation.
