"""Tests for the command-line interface."""

from __future__ import annotations

import argparse
from datetime import datetime

import pytest

from log_analyzer.cli import create_parser, filter_by_timerange, main, parse_timerange, run_analyze
from log_analyzer.detectors import Alert, AlertSeverity
from log_analyzer.parsers import LogEntry, Severity


def make_entry(*, day: int) -> LogEntry:
    timestamp = datetime(2026, 1, day, 12, 0, 0)
    return LogEntry(
        timestamp=timestamp,
        source="authlog",
        hostname="server-1",
        message=f"event on day {day}",
        severity=Severity.INFO,
        raw=f"raw log line {day}",
        program="sshd",
        metadata={"source_ip": "10.0.0.5", "event_type": "successful_login"},
    )


class TestCli:
    """Tests for parser creation and command execution."""

    def test_create_parser_parses_analyze_args(self) -> None:
        parser = create_parser()

        args = parser.parse_args(
            ["analyze", "--source", "/tmp/syslog", "--format", "syslog", "--correlate"]
        )

        assert args.command == "analyze"
        assert args.source == "/tmp/syslog"
        assert args.format == "syslog"
        assert args.correlate is True

    def test_parse_timerange_validates_inputs(self) -> None:
        start, end = parse_timerange("2026-01-01 2026-01-15")

        assert start == datetime(2026, 1, 1, 0, 0, 0)
        assert end == datetime(2026, 1, 15, 23, 59, 59)

        with pytest.raises(ValueError, match="Expected 'YYYY-MM-DD YYYY-MM-DD'"):
            parse_timerange("2026-01-01")

        with pytest.raises(ValueError, match="must be before end date"):
            parse_timerange("2026-02-01 2026-01-01")

    def test_filter_by_timerange_returns_matching_entries(self) -> None:
        entries = [make_entry(day=1), make_entry(day=10), make_entry(day=20)]

        filtered = filter_by_timerange(
            entries,
            datetime(2026, 1, 5, 0, 0, 0),
            datetime(2026, 1, 15, 23, 59, 59),
        )

        assert [entry.message for entry in filtered] == ["event on day 10"]

    def test_run_analyze_returns_error_for_missing_source(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        args = argparse.Namespace(
            source="does-not-exist.log",
            format="syslog",
            output=None,
            rules=None,
            timerange=None,
            threshold=5,
            window=300,
            correlate=False,
            verbose=False,
        )

        result = run_analyze(args)
        captured = capsys.readouterr()

        assert result == 1
        assert "Source path does not exist" in captured.err

    def test_run_analyze_processes_directory_and_writes_html_report(
        self,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "a.log").write_text("ignored", encoding="utf-8")
        (tmp_path / "b.log").write_text("ignored", encoding="utf-8")

        class FakeParser:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def parse_file(self, path) -> list[LogEntry]:
                self.calls.append(path.name)
                if path.name == "a.log":
                    return [make_entry(day=1)]
                return [make_entry(day=2)]

        fake_parser = FakeParser()
        alerts = [
            Alert(
                timestamp=datetime(2026, 1, 2, 12, 5, 0),
                alert_type="brute_force",
                severity=AlertSeverity.HIGH,
                source_ip="10.0.0.5",
                description="Detected brute force activity",
                evidence=["line 1"],
                metadata={},
            )
        ]
        reporter_calls: dict[str, object] = {}

        class FakeReporter:
            def generate(self, **kwargs):
                reporter_calls.update(kwargs)
                return "<html>report</html>"

        class FakeCorrelator:
            def __init__(self) -> None:
                self.entries: list[LogEntry] = []
                self.alerts: list[Alert] = []

            def add_entries(self, entries: list[LogEntry]) -> None:
                self.entries.extend(entries)

            def add_alerts(self, incoming_alerts: list[Alert]) -> None:
                self.alerts.extend(incoming_alerts)

            def get_summary(self) -> dict:
                return {"attack_chains_detected": 1, "chains": []}

        monkeypatch.setattr("log_analyzer.cli.get_parser", lambda _: fake_parser)
        monkeypatch.setattr("log_analyzer.cli.run_all_detectors", lambda *args, **kwargs: alerts)
        monkeypatch.setattr("log_analyzer.cli.Reporter", FakeReporter)
        monkeypatch.setattr("log_analyzer.cli.EventCorrelator", FakeCorrelator)

        output_path = tmp_path / "report.html"
        args = argparse.Namespace(
            source=str(tmp_path),
            format="syslog",
            output=str(output_path),
            rules=None,
            timerange=None,
            threshold=5,
            window=300,
            correlate=True,
            verbose=True,
        )

        result = run_analyze(args)
        captured = capsys.readouterr()

        assert result == 0
        assert fake_parser.calls == ["a.log", "b.log"]
        assert reporter_calls["format"] == "html"
        assert reporter_calls["output_path"] == str(output_path)
        assert reporter_calls["correlation_summary"] == {
            "attack_chains_detected": 1,
            "chains": [],
        }
        assert "Parsing" in captured.out
        assert "Attack chains detected: 1" in captured.out
        assert f"Report written to {output_path}" in captured.out

    def test_main_without_args_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = main([])
        captured = capsys.readouterr()

        assert result == 0
        assert "usage: loganalyzer" in captured.out
