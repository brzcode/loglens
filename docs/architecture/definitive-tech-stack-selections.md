# Definitive Tech Stack Selections

| Category | Technology | Version / Details | Description / Purpose | Justification (Optional) |
| :--- | :--- | :--- | :--- | :--- |
| **Languages** | Python | 3.11+ | Primary language for the entire application. | As required by PRD. Modern versions ensure access to latest features. |
| **Frameworks** | Typer | Latest | CLI framework for creating a user-friendly command-line interface. | More modern and easier to use than `argparse`, with great autocompletion support. |
| | Pydantic | Latest | Data validation and settings management. | Enforces strict data models for internal consistency and reliable parsing. |
| **Libraries** | httpx | Latest | Asynchronous-capable HTTP client for API calls. | Modern, fast, and supports both sync and async usage if needed later. |
| **Testing** | pytest | Latest | Unit/Integration testing framework. | The de-facto standard for testing in Python; powerful and extensible. |
| | pytest-mock | Latest | `pytest` plugin for mocking objects. | Simplifies mocking during tests. |
| **CI/CD** | GitHub Actions | N/A | Continuous Integration/Deployment. | Tightly integrated with GitHub, easy to set up for linting/testing. |
| **Packaging** | Poetry | Latest | Dependency management and packaging. | Modern tool that simplifies dependency and environment management over `pip` and `venv`. |
