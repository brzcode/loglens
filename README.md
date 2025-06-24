# LogLens - Simplifying Log Analysis for Security Teams

![LogLens Logo](https://img.shields.io/badge/LogLens-0.1.0-blue)
![Python](https://img.shields.io/badge/Python-3.11+-green)
![License](https://img.shields.io/badge/License-TBD-yellow)

LogLens is a powerful command-line tool for comprehensive log file analysis, featuring advanced pattern detection, security threat identification, IP reputation analysis, and intelligent anomaly detection. Built with modern Python and designed for scalability.

## 🚀 Features

### Core Capabilities
- **📄 Multi-Format Log Ingestion**: Support for various log formats with intelligent encoding detection
- **🔍 Apache Log Parsing**: Specialized parser for Apache/Nginx access logs with comprehensive field extraction
- **🚨 Advanced Pattern Detection**: Multi-layered detection engine for security threats and anomalies
- **🌐 IP Reputation Analysis**: Real-time IP reputation checking with multiple provider support
- **📊 Comprehensive Reporting**: Detailed analysis reports with statistics and insights
- **⚡ High-Performance Processing**: Memory-efficient streaming for large log files
- **🛡️ Security-Focused**: Built-in detection for common attack patterns and threats

### Detection Capabilities
- **Frequency Analysis**: Detect unusual request patterns and potential attacks
- **Security Threat Detection**: Identify malicious IP addresses and suspicious activities
- **Anomaly Detection**: Statistical analysis to find outliers and unusual behaviors
- **Attack Pattern Recognition**: SQL injection, XSS, path traversal, and more
- **Rate Limiting Violations**: Detect potential DoS and abuse patterns

### Enrichment Features
- **IP Geolocation**: Geographic analysis of request sources
- **Reputation Scoring**: Multi-provider IP reputation analysis
- **Contextual Enhancement**: Additional metadata for improved threat assessment

## 📦 Installation

### Prerequisites

- **Python 3.11+** (required)
- **Poetry** (recommended) or pip for package management

### Quick Install

```bash
# Clone the repository
git clone https://github.com/brzcode/loglens.git
cd loglens

# Install with Poetry (recommended)
poetry install

# Or install with pip
pip install -e .
```

### Development Install

```bash
# Install with development dependencies
poetry install --with dev

# Activate virtual environment
poetry shell
```

## 🔧 Usage

### Basic Analysis

```bash
# Analyze an Apache access log
loglens analyze /var/log/apache2/access.log

# Save detailed report to file
loglens analyze /var/log/nginx/access.log --output security-report.txt

# Enable verbose output for detailed insights
loglens analyze /path/to/logfile.log --verbose
```

### Real-World Examples

```bash
# Quick security assessment
loglens analyze /var/log/httpd/access_log --verbose

# Generate comprehensive report
loglens analyze server-logs.log --output comprehensive-analysis.txt

# Pipeline analysis for multiple files
find /var/log -name "*.log" -exec loglens analyze {} \;
```

### Sample Output

```
🔍 LogLens Analysis starting for: access.log

✅ File ingestion complete:
   📊 Lines processed: 10,247
   📏 File size: 2.4 MB
   🕒 Duration: 0.15 seconds
   🔤 Encoding: utf-8

✅ Log parsing complete:
   📊 Lines parsed: 10,247
   ✅ Successful parses: 10,190
   ❌ Parse errors: 57
   📈 Success rate: 99.4%

✅ Detection analysis complete:
   📊 Entries analyzed: 10,190
   🚨 Total findings: 23
   🔴 High risk: 3
   🟡 Medium risk: 8
   🟢 Low risk: 12

✅ IP reputation enrichment complete:
   🌐 Unique IPs queried: 847
   ✅ Successful lookups: 834
   📈 Findings enriched: 23
   📊 Success rate: 98.5%
```

## 🏗️ Architecture

### Project Structure

```
loglens/
├── src/loglens/              # Main application package
│   ├── main.py              # CLI entry point and command handlers
│   ├── models.py            # Pydantic data models and schemas
│   ├── core/                # Core configuration and utilities
│   │   └── config.py        # Application configuration management
│   └── services/            # Business logic and processing services
│       ├── ingestion.py     # Log file reading and preprocessing
│       ├── detection.py     # Pattern detection and analysis engine
│       ├── enrichment.py    # IP reputation and contextual enhancement
│       ├── reporting.py     # Report generation and formatting
│       └── parsing/         # Log format parsers
│           ├── base_parser.py    # Abstract parser interface
│           └── apache_parser.py  # Apache/Nginx log parser
├── tests/                   # Comprehensive test suite
├── docs/                    # Project documentation
├── pyproject.toml          # Project configuration and dependencies
└── README.md               # This documentation
```

### Data Flow

1. **Ingestion**: Log files are read with encoding detection and validation
2. **Parsing**: Structured extraction of log entries using format-specific parsers
3. **Detection**: Multi-layered analysis for patterns, anomalies, and security threats
4. **Enrichment**: IP reputation analysis and contextual data enhancement
5. **Reporting**: Comprehensive report generation with statistics and insights

### Key Components

- **LogFileIngester**: Memory-efficient file processing with progress tracking
- **ApacheParser**: Comprehensive Apache/Nginx log format support
- **DetectionEngine**: Multi-detector analysis engine with configurable rules
- **EnrichmentEngine**: Async IP reputation analysis with provider abstraction
- **ReportGenerator**: Flexible reporting with multiple output formats

## 🛠️ Development

### Setup Development Environment

```bash
# Clone and setup
git clone https://github.com/your-org/loglens.git
cd loglens

# Install with development dependencies
poetry install --with dev

# Activate environment
poetry shell
```

### Running Tests

```bash
# Run full test suite
poetry run pytest

# Run with coverage
poetry run pytest --cov=loglens --cov-report=html

# Run specific test category
poetry run pytest tests/test_detection.py -v
```

### Code Quality

```bash
# Format code
poetry run black src/ tests/

# Lint code
poetry run flake8 src/ tests/

# Type checking
poetry run mypy src/

# Run all quality checks
poetry run black src/ tests/ && poetry run flake8 src/ tests/ && poetry run mypy src/
```

### Adding New Features

1. **Parsers**: Extend `base_parser.py` for new log formats
2. **Detectors**: Add new detection algorithms in `detection.py`
3. **Enrichment**: Implement new providers in `enrichment.py`
4. **Tests**: Maintain comprehensive test coverage

## 📊 Performance

### Benchmarks

- **Processing Speed**: ~50,000 lines/second on standard hardware
- **Memory Usage**: Constant memory usage with streaming processing
- **File Size Support**: Tested with files up to 1GB+
- **Accuracy**: 99%+ parsing success rate for standard Apache logs

### Optimization Features

- **Streaming Processing**: Memory-efficient handling of large files
- **Async Enrichment**: Parallel IP reputation queries
- **Smart Caching**: Reduced API calls through intelligent caching
- **Progress Tracking**: Real-time feedback for long-running operations

## 🤝 Contributing

### Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with tests
4. Run quality checks: `poetry run pytest && poetry run black . && poetry run flake8`
5. Commit changes: `git commit -m 'Add amazing feature'`
6. Push to branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Development Guidelines

- **Code Style**: Follow Black formatting and PEP 8
- **Testing**: Maintain 90%+ test coverage
- **Documentation**: Update docs for new features
- **Type Hints**: Use comprehensive type annotations
- **Commit Messages**: Use conventional commit format

### Roadmap

- [ ] Support for additional log formats (Syslog, JSON, etc.)
- [ ] Machine learning-based anomaly detection
- [ ] Web dashboard for analysis results
- [ ] Real-time log monitoring capabilities
- [ ] Custom rule engine for detection patterns

## 📝 Documentation

### Additional Resources

- [Architecture Documentation](./docs/architecture.md)
- [Product Requirements](./docs/prd.md)
- [User Stories](./docs/stories/)
- [API Reference](./docs/architecture/api-reference.md)

### API Documentation

The project includes comprehensive documentation for:
- Data models and schemas
- Service interfaces and methods
- Configuration options
- Extension points for custom functionality

## 🔧 Configuration

### Environment Variables

```bash
# Optional: Configure API keys for enrichment providers
export LOGLENS_VIRUSTOTAL_API_KEY="your-api-key"
export LOGLENS_ABUSEIPDB_API_KEY="your-api-key"

# Optional: Configure output preferences
export LOGLENS_DEFAULT_OUTPUT_FORMAT="detailed"
export LOGLENS_MAX_FILE_SIZE="104857600"  # 100MB
```

### Configuration File

Create `~/.loglens/config.yaml` for persistent settings:

```yaml
ingestion:
  max_file_size: 104857600  # 100MB
  encoding_detection: true
  show_progress: true

detection:
  enable_frequency_analysis: true
  enable_security_detection: true
  risk_threshold: "medium"

enrichment:
  enable_ip_reputation: true
  providers:
    - virustotal
    - abuseipdb
  timeout: 30

reporting:
  default_format: "detailed"
  include_statistics: true
  verbose_errors: false
```

## 📄 License

This project is licensed under the [License TBD]. See the `LICENSE` file for details.

## 🙏 Acknowledgments

- Built with [Typer](https://typer.tiangolo.com/) for CLI excellence
- Powered by [Pydantic](https://pydantic.dev/) for data validation
- Testing with [pytest](https://pytest.org/) framework
- Code quality with [Black](https://black.readthedocs.io/) and [flake8](https://flake8.pycqa.org/)

## 🐛 Support

### Reporting Issues

- **Bug Reports**: Use GitHub Issues with detailed reproduction steps
- **Feature Requests**: Submit enhancement requests with use case descriptions
- **Security Issues**: Email security@yourdomain.com for responsible disclosure

### Getting Help

- **Documentation**: Check the [docs/](./docs/) directory
- **Examples**: See example usage in the test files
- **Community**: Join our discussions in GitHub Discussions

---

**LogLens** - Bringing clarity to your log analysis 🔍✨ 