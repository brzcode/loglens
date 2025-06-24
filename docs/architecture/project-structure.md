# Project Structure

The project will follow a standard Python application structure.

```plaintext
loglens/
├── .github/
│   └── workflows/
│       └── main.yml
├── docs/
│   ├── PRD.md
│   └── architecture.md
├── scripts/
│   └── manual_test_cases.sh
├── src/
│   └── loglens/
│       ├── __init__.py
│       ├── main.py             # CLI Handler & Orchestrator
│       ├── services/
│       │   ├── __init__.py
│       │   ├── parsing/        # Parser Service & Strategies
│       │   │   ├── __init__.py
│       │   │   ├── base_parser.py
│       │   │   └── apache_parser.py
│       │   ├── detection.py    # Detection Service
│       │   ├── enrichment.py   # Enrichment Service
│       │   └── reporting.py    # Report Generator
│       ├── models.py           # Pydantic Data Models
│       └── core/
│           └── config.py       # Configuration management (e.g., API keys)
├── tests/
│   ├── __init__.py
│   ├── test_parsing.py
│   └── test_detection.py
├── .gitignore
├── pyproject.toml              # Project metadata and dependencies (Poetry/Flit)
└── README.md
```

### Key Directory Descriptions

  * **docs/**: Contains all project documentation, including the PRD and this Architecture Document.
  * **src/loglens/**: Contains the main application source code.
  * **src/loglens/services/**: Core business logic, separated into modules for each major function (parsing, detection, etc.).
  * **src/loglens/models.py**: Defines the core Pydantic data models used throughout the application.
  * **tests/**: Contains all automated tests, mirroring the `src` structure.
