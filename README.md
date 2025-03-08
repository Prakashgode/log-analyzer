# LogAnalyzer - Security Log Analysis & Correlation Engine

A Python-based log analysis tool that parses, correlates, and detects anomalies across multiple log sources (syslog, auth.log, Apache/Nginx, Windows Event Logs). Built for SOC analysts and blue team operations.

## Features

- **Multi-format Log Parsing** - Unified parsing for syslog, auth.log, Apache/Nginx access logs, and Windows Event Logs (XML)
- **Anomaly Detection** - Identifies brute force attacks, privilege escalation attempts, suspicious commands (reverse shells, data exfiltration patterns)
- **Event Correlation** - Links related events across multiple log sources to reconstruct attack chains
- **Alert Generation** - Produces alerts with severity levels (LOW, MEDIUM, HIGH, CRITICAL) and supporting evidence
- **Statistical Analysis & Reporting** - Generates summary reports in console, JSON, and HTML formats
- **Timeline Visualization** - Builds chronological timelines of correlated security events

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Prakashgode/log-analyzer.git
cd log-analyzer

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Analyze a syslog file
loganalyzer analyze --source /var/log/syslog --format syslog

# Analyze auth.log with JSON output
loganalyzer analyze --source /var/log/auth.log --format authlog --output report.json

# Analyze with a custom time range
loganalyzer analyze --source /var/log/syslog --format syslog --timerange "2024-01-01 2024-01-31"
```

## Usage

### Command Line Interface

```bash
# Basic analysis
loganalyzer analyze --source <logfile> --format <format>

# Supported formats: syslog, authlog, apache, windows
loganalyzer analyze --source access.log --format apache

# Specify output format (console, json, html)
loganalyzer analyze --source auth.log --format authlog --output report.html

# Use custom detection rules
loganalyzer analyze --source syslog --format syslog --rules custom_rules.yaml

# Filter by time range
loganalyzer analyze --source auth.log --format authlog --timerange "2024-01-01 2024-01-15"
```

### Python API

```python
from log_analyzer.parsers import SyslogParser, AuthLogParser
from log_analyzer.detectors import BruteForceDetector, AnomalyDetector
from log_analyzer.correlator import EventCorrelator
from log_analyzer.reporter import Reporter

# Parse logs
parser = SyslogParser()
entries = parser.parse_file("/var/log/syslog")

# Detect threats
detector = BruteForceDetector(threshold=5, window_seconds=300)
alerts = detector.detect(entries)

# Correlate events across sources
correlator = EventCorrelator()
correlator.add_entries(entries)
chains = correlator.detect_attack_chains()

# Generate report
reporter = Reporter()
reporter.generate(alerts, format="json", output_path="report.json")
```

## Configuration

Detection thresholds and rules can be customized:

```python
# Brute force detection: 5 failed logins within 300 seconds (default)
brute_force = BruteForceDetector(threshold=5, window_seconds=300)

# Anomaly detection with custom sensitivity
anomaly = AnomalyDetector(
    unusual_hour_start=22,  # Flag logins after 10 PM
    unusual_hour_end=6,     # Flag logins before 6 AM
    zscore_threshold=2.0    # Statistical anomaly sensitivity
)
```

### Supported Log Formats

| Format | Flag | Description |
|--------|------|-------------|
| Syslog | `syslog` | Standard RFC 3164/5424 syslog |
| Auth Log | `authlog` | Linux authentication logs |
| Apache/Nginx | `apache` | Combined/common access log format |
| Windows Event | `windows` | Windows Event Log XML export |

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detector`)
3. Write tests for your changes
4. Ensure all tests pass (`pytest`)
5. Submit a pull request

Please follow PEP 8 style guidelines and include type hints for all function signatures.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
