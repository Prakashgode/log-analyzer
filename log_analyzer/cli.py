"""Command-line interface for LogAnalyzer.

Provides the ``loganalyzer`` CLI tool with an ``analyze`` subcommand
for parsing, detecting threats, correlating events, and generating
reports from security log files.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from log_analyzer import __version__
from log_analyzer.correlator import EventCorrelator
from log_analyzer.detectors import Alert, run_all_detectors
from log_analyzer.parsers import LogEntry, get_parser
from log_analyzer.reporter import Reporter


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="loganalyzer",
        description="LogAnalyzer - Security Log Analysis & Correlation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  loganalyzer analyze --source /var/log/syslog --format syslog\n"
            "  loganalyzer analyze --source /var/log/auth.log --format authlog --output report.json\n"
            "  loganalyzer analyze --source access.log --format apache --timerange '2024-01-01 2024-01-31'\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze subcommand
    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze log files for security threats",
        description="Parse, analyze, and correlate security log files.",
    )
    analyze.add_argument(
        "--source",
        required=True,
        type=str,
        help="Path to the log file or directory to analyze",
    )
    analyze.add_argument(
        "--format",
        required=True,
        choices=["syslog", "authlog", "apache", "windows"],
        help="Log format type (syslog, authlog, apache, windows)",
    )
    analyze.add_argument(
        "--output",
        type=str,
        default=None,
        help=(
            "Output file path. Format inferred from extension: "
            ".json for JSON, .html for HTML, default is console output"
        ),
    )
    analyze.add_argument(
        "--rules",
        type=str,
        default=None,
        help="Path to custom detection rules YAML file (optional)",
    )
    analyze.add_argument(
        "--timerange",
        type=str,
        default=None,
        help="Time range filter as 'START END' in YYYY-MM-DD format (e.g., '2024-01-01 2024-01-31')",
    )
    analyze.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Brute force detection threshold (default: 5)",
    )
    analyze.add_argument(
        "--window",
        type=int,
        default=300,
        help="Brute force detection window in seconds (default: 300)",
    )
    analyze.add_argument(
        "--correlate",
        action="store_true",
        default=False,
        help="Enable event correlation across log entries",
    )
    analyze.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose output",
    )

    return parser


def parse_timerange(timerange_str: str) -> tuple[datetime, datetime]:
    """Parse a time range string into start and end datetimes.

    Args:
        timerange_str: Time range as 'YYYY-MM-DD YYYY-MM-DD'.

    Returns:
        Tuple of (start_datetime, end_datetime).

    Raises:
        ValueError: If the time range format is invalid.
    """
    parts = timerange_str.strip().split()
    if len(parts) != 2:
        raise ValueError(
            f"Invalid time range format: '{timerange_str}'. "
            "Expected 'YYYY-MM-DD YYYY-MM-DD'."
        )

    try:
        start = datetime.strptime(parts[0], "%Y-%m-%d")
        end = datetime.strptime(parts[1], "%Y-%m-%d").replace(
            hour=23, minute=59, second=59
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid date in time range: {exc}. Expected YYYY-MM-DD format."
        ) from exc

    if start > end:
        raise ValueError(
            f"Start date ({parts[0]}) must be before end date ({parts[1]})."
        )

    return start, end


def filter_by_timerange(
    entries: List[LogEntry],
    start: datetime,
    end: datetime,
) -> List[LogEntry]:
    """Filter log entries by time range.

    Args:
        entries: List of parsed log entries.
        start: Start of the time range (inclusive).
        end: End of the time range (inclusive).

    Returns:
        Filtered list of entries within the time range.
    """
    return [e for e in entries if start <= e.timestamp <= end]


def run_analyze(args: argparse.Namespace) -> int:
    """Execute the analyze command.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    source_path = Path(args.source)

    # Validate source path
    if not source_path.exists():
        print(f"Error: Source path does not exist: {args.source}", file=sys.stderr)
        return 1

    # Get the appropriate parser
    try:
        log_parser = get_parser(args.format)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Parse log files
    if args.verbose:
        print(f"[*] Parsing {args.source} as {args.format}...")

    if source_path.is_dir():
        entries: List[LogEntry] = []
        for log_file in sorted(source_path.iterdir()):
            if log_file.is_file():
                try:
                    file_entries = log_parser.parse_file(log_file)
                    entries.extend(file_entries)
                    if args.verbose:
                        print(f"    Parsed {len(file_entries)} entries from {log_file.name}")
                except Exception as exc:
                    print(f"Warning: Failed to parse {log_file}: {exc}", file=sys.stderr)
    else:
        try:
            entries = log_parser.parse_file(source_path)
        except Exception as exc:
            print(f"Error: Failed to parse {args.source}: {exc}", file=sys.stderr)
            return 1

    if args.verbose:
        print(f"[*] Total entries parsed: {len(entries)}")

    # Apply time range filter
    if args.timerange:
        try:
            start, end = parse_timerange(args.timerange)
            entries = filter_by_timerange(entries, start, end)
            if args.verbose:
                print(f"[*] Entries after time filter: {len(entries)}")
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if not entries:
        print("No log entries found matching the criteria.", file=sys.stderr)
        return 0

    # Run detection
    if args.verbose:
        print("[*] Running threat detection...")

    alerts = run_all_detectors(
        entries,
        brute_force_threshold=args.threshold,
        brute_force_window=args.window,
    )

    if args.verbose:
        print(f"[*] Alerts generated: {len(alerts)}")

    # Run correlation if requested
    correlation_summary: Optional[dict] = None
    if args.correlate:
        if args.verbose:
            print("[*] Running event correlation...")

        correlator = EventCorrelator()
        correlator.add_entries(entries)
        correlator.add_alerts(alerts)
        correlation_summary = correlator.get_summary()

        if args.verbose:
            print(f"[*] Attack chains detected: {correlation_summary['attack_chains_detected']}")

    # Generate report
    reporter = Reporter()

    if args.output:
        output_path = Path(args.output)
        suffix = output_path.suffix.lower()

        if suffix == ".json":
            report_format = "json"
        elif suffix in (".html", ".htm"):
            report_format = "html"
        else:
            report_format = "json"

        reporter.generate(
            alerts=alerts,
            entries=entries,
            format=report_format,
            output_path=str(output_path),
            correlation_summary=correlation_summary,
        )
        print(f"Report written to {output_path}")
    else:
        reporter.generate(
            alerts=alerts,
            entries=entries,
            format="console",
            correlation_summary=correlation_summary,
        )

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Command-line arguments. Defaults to sys.argv[1:].

    Returns:
        Exit code.
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "analyze":
        return run_analyze(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
