# Architectural / Design Patterns Adopted

To ensure a clean and maintainable codebase, the following patterns will be central to the design:

  * **Strategy Pattern:** This will be used to select the appropriate log parser at runtime (e.g., `ApacheParser`, `NginxParser`) based on user input. This makes the parsing system pluggable and easy to extend.
  * **Adapter (or Facade) Pattern:** An adapter will be created to encapsulate all interactions with the external IP reputation service. This isolates the external dependency, making it easy to swap out services or add new ones in the future, and simplifies how the rest of the application interacts with it.
  * **Modular/Plugin Pattern:** The entire system for both parsers and detection logic will be treated as a plugin system. New parsers or detection rules can be added as new modules without altering the core orchestration logic.
