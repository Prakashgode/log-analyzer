# TODO

## Next Features

- Add JSON Lines output for streaming and pipeline-friendly workflows.
- Add CSV export for analysts who want spreadsheet-friendly output.
- Add SARIF output for integration with security tooling and dashboards.
- Add Sigma rule loading so custom detections can be defined in YAML.
- Add sampling and chunked processing paths for very large log files.

## Validation

- Add sample log files under `samples/` for demos and regression tests.
- Test against real-world `auth.log`, syslog, Apache, and Windows Event datasets.
- Benchmark large-file analysis paths and document expected throughput.

## Parser Improvements

- Handle multiline syslog-style entries when logs contain wrapped messages.
- Add optional debug logging for parser and detector troubleshooting.
- jsonl formatter
