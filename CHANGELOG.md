# Changelog

## Unreleased

- Fixed yearless syslog and auth.log timestamp parsing so Python 3.15 deprecation warnings are removed while December-to-January rollover is handled correctly.
- Migrated packaging metadata to `pyproject.toml` and added Ruff, mypy, and pytest configuration for local development and CI.
- Expanded automated coverage for the correlator, reporter, and CLI modules.
- Added contributor and security policy documentation.

## 1.0.0

- Added parsers for syslog, auth.log, Apache/Nginx access logs, and Windows Event Log XML exports.
- Added detectors for brute force activity, privilege escalation, suspicious commands, and anomalies.
- Added cross-source event correlation with attack chain reconstruction.
- Added console, JSON, and HTML reporting outputs.
