# Contributing to LogLens

Thank you for your interest in contributing to LogLens! We welcome contributions from the community and are excited to work with you.

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- Poetry for dependency management
- Git for version control

### Setting Up Development Environment

1. **Fork and Clone**
   ```bash
   git clone https://github.com/brzcode/loglens.git
   cd loglens
   ```

2. **Install Dependencies**
   ```bash
   poetry install --with dev
   poetry shell
   ```

3. **Verify Setup**
   ```bash
   poetry run pytest
   poetry run loglens --help
   ```

## 📋 Development Guidelines

### Code Style

We follow strict code quality standards:

- **Formatting**: Black with 88-character line length
- **Linting**: flake8 with project-specific configuration
- **Type Checking**: mypy with strict settings
- **Imports**: isort for consistent import ordering

**Before committing, run:**
```bash
poetry run black src/ tests/
poetry run flake8 src/ tests/
poetry run mypy src/
poetry run isort src/ tests/
```

### Testing Standards

- **Coverage**: Maintain 90%+ test coverage
- **Test Types**: Unit tests, integration tests, and end-to-end tests
- **Test Naming**: Use descriptive test names that explain the scenario
- **Fixtures**: Use pytest fixtures for reusable test data

**Running Tests:**
```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=loglens --cov-report=html

# Run specific test files
poetry run pytest tests/test_detection.py -v

# Run tests matching pattern
poetry run pytest -k "test_apache_parser"
```

### Documentation Standards

- **Docstrings**: Use Google-style docstrings for all public functions
- **Type Hints**: Comprehensive type annotations required
- **Comments**: Explain complex algorithms and business logic
- **README**: Update README.md for new features

## 🔧 Contributing Process

### 1. Issue Creation

Before starting work:
- Check existing issues to avoid duplication
- Create a detailed issue describing the problem or enhancement
- Wait for maintainer approval for significant changes

### 2. Development Workflow

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write code following our style guidelines
   - Add comprehensive tests
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   poetry run pytest
   poetry run black --check src/ tests/
   poetry run flake8 src/ tests/
   poetry run mypy src/
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add amazing new feature"
   ```

### 3. Pull Request Process

1. **Push Branch**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create Pull Request**
   - Use the PR template provided
   - Include detailed description of changes
   - Reference related issues
   - Add screenshots for UI changes

3. **Review Process**
   - All PRs require at least one approval
   - Address review feedback promptly
   - Keep PR scope focused and manageable

## 🏗️ Architecture Guidelines

### Adding New Parsers

1. **Extend Base Parser**
   ```python
   from loglens.services.parsing.base_parser import BaseParser
   
   class YourParser(BaseParser):
       def parse_line(self, line: str) -> ParseResult:
           # Implementation here
           pass
   ```

2. **Add Comprehensive Tests**
   - Test valid log formats
   - Test edge cases and malformed input
   - Test performance with large datasets

3. **Update Documentation**
   - Add parser to README.md
   - Include usage examples
   - Document supported log formats

### Adding New Detectors

1. **Create Detector Class**
   ```python
   from loglens.services.detection.base_detector import BaseDetector
   
   class YourDetector(BaseDetector):
       def analyze(self, entries: List[LogEntry]) -> List[Finding]:
           # Implementation here
           pass
   ```

2. **Integration**
   - Register detector in DetectionEngine
   - Add configuration options
   - Include in CLI output

### Adding New Enrichment Providers

1. **Implement Provider Interface**
   ```python
   from loglens.services.enrichment.base_provider import BaseProvider
   
   class YourProvider(BaseProvider):
       async def lookup_ip(self, ip: str) -> ProviderResult:
           # Implementation here
           pass
   ```

2. **Configuration**
   - Add provider configuration options
   - Handle API key management
   - Implement rate limiting

## 🧪 Testing Guidelines

### Test Organization

```
tests/
├── test_main.py              # CLI tests
├── test_models.py           # Data model tests
├── test_ingestion.py        # File ingestion tests
├── test_detection.py        # Detection engine tests
├── test_enrichment.py       # Enrichment tests
├── test_parsing.py          # Parser tests
├── test_reporting.py        # Report generation tests
└── fixtures/                # Test data and fixtures
    ├── sample_logs/
    └── test_data.py
```

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test with large datasets

### Writing Good Tests

```python
def test_apache_parser_handles_valid_log_line():
    """Test that Apache parser correctly parses standard log format."""
    # Arrange
    parser = ApacheParser()
    log_line = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /test HTTP/1.1" 200 2326'
    
    # Act
    result = parser.parse_line(log_line)
    
    # Assert
    assert result.success is True
    assert result.entry.ip_address == "127.0.0.1"
    assert result.entry.status_code == 200
    assert result.entry.request_line == "GET /test HTTP/1.1"
```

## 📝 Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```
feat(detection): add SQL injection detection algorithm
fix(parser): handle malformed timestamp formats
docs(readme): update installation instructions
test(enrichment): add IP reputation provider tests
```

## 🚨 Security Guidelines

### Reporting Security Issues

- **DO NOT** create public issues for security vulnerabilities
- Email security@yourdomain.com with details
- Include steps to reproduce the vulnerability
- Allow time for fixes before public disclosure

### Security Best Practices

- Never commit API keys or secrets
- Validate all input data thoroughly
- Use secure defaults for configuration
- Follow OWASP guidelines for web security

## 🏷️ Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Run full test suite
4. Create release branch
5. Submit PR for review
6. Tag release after merge
7. Update documentation

## 🤝 Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Respect different perspectives and experiences

### Getting Help

- **Questions**: Use GitHub Discussions
- **Bugs**: Create detailed issue reports
- **Features**: Discuss in issues before implementation
- **Chat**: Join our community channels

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Community highlights

## 📚 Additional Resources

- [Architecture Documentation](./docs/architecture.md)
- [API Reference](./docs/architecture/api-reference.md)
- [Development Setup Guide](./docs/development.md)
- [Testing Strategy](./docs/architecture/overall-testing-strategy.md)

---

Thank you for contributing to LogLens! Your efforts help make log analysis more accessible and powerful for everyone. 🙏 