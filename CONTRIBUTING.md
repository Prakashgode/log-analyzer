# Contributing

Thanks for contributing to LogAnalyzer.

## Development Setup

1. Use Python 3.11 or newer.
2. Install dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

## Local Checks

Run the same checks that CI runs before opening a pull request:

```bash
ruff check .
mypy log_analyzer
pytest tests/ -v
```

## Code Guidelines

- Preserve existing parser, detector, correlator, and reporter behavior unless the change is intentional and covered by tests.
- Add or update tests for bug fixes and new features.
- Keep public function signatures typed.
- Prefer small, focused pull requests over large unrelated batches of work.

## Pull Requests

- Describe the problem being solved and the behavior change.
- Include test coverage for new code paths.
- Call out user-facing output changes such as new report formats or CLI flags.

