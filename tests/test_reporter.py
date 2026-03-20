"""Tests for report generation."""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from log_analyzer.detectors import Alert, AlertSeverity
from log_analyzer.parsers import LogEntry, Severity
from log_analyzer.reporter import Reporter


def make_entry() -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 1, 15, 12, 0, 0),
        source="authlog",
        hostname="server-1",
        message="Accepted publickey for analyst from 10.0.0.5",
        severity=Severity.INFO,
        raw="raw log line",
        program="sshd",
        metadata={
            "event_type": "successful_login",
            "username": "analyst",
            "source_ip": "10.0.0.5",
        },
    )


def make_alert(*, description: str = "Suspicious activity", evidence: list[str] | None = None) -> Alert:
    return Alert(
        timestamp=datetime(2026, 1, 15, 12, 5, 0),
        alert_type="brute_force",
        severity=AlertSeverity.HIGH,
        source_ip="10.0.0.5",
        description=description,
        evidence=evidence or ["failed login 1", "failed login 2"],
        metadata={"attempts": 7},
    )


class TestReporter:
    """Tests for console, JSON, and HTML reports."""

    def test_generate_console_includes_summary_and_correlation(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        reporter = Reporter()
        correlation_summary = {
            "attack_chains_detected": 1,
            "chains": [
                {
                    "chain_id": "chain-0000",
                    "source_ip": "10.0.0.5",
                    "overall_severity": "HIGH",
                    "stages": ["initial_access", "privilege_escalation"],
                    "events": [{}, {}],
                    "first_seen": "2026-01-15T12:00:00",
                    "last_seen": "2026-01-15T12:05:00",
                    "description": "Correlated attack chain",
                }
            ],
        }

        content = reporter.generate(
            alerts=[make_alert()],
            entries=[make_entry()],
            format="console",
            correlation_summary=correlation_summary,
        )
        captured = capsys.readouterr()

        assert content is not None
        assert "Total log entries analyzed: 1" in content
        assert "ALERT DETAILS" in content
        assert "CORRELATION SUMMARY" in content
        assert "chain-0000" in content
        assert "LogAnalyzer - Security Analysis Report" in captured.out

    def test_generate_json_returns_serialized_content(self) -> None:
        reporter = Reporter()

        content = reporter.generate(
            alerts=[make_alert()],
            entries=[make_entry()],
            format="json",
            correlation_summary={"attack_chains_detected": 0, "chains": []},
        )

        assert content is not None
        data = json.loads(content)
        assert data["report"]["title"] == "LogAnalyzer Security Analysis Report"
        assert data["statistics"]["total_alerts"] == 1
        assert data["statistics"]["total_entries"] == 1
        assert data["alerts"][0]["severity"] == "HIGH"
        assert data["correlation"]["attack_chains_detected"] == 0

    def test_generate_html_escapes_alert_content(self) -> None:
        reporter = Reporter()
        alert = make_alert(
            description='payload <script>alert("xss")</script>',
            evidence=['curl "http://bad/?x=<script>"'],
        )
        correlation_summary = {
            "attack_chains_detected": 1,
            "chains": [
                {
                    "chain_id": "chain-0001",
                    "source_ip": "10.0.0.5",
                    "overall_severity": "HIGH",
                    "stages": ["initial_access"],
                    "events": [{}],
                    "description": 'Chain <script>alert("xss")</script>',
                }
            ],
        }

        content = reporter.generate(
            alerts=[alert],
            entries=[make_entry()],
            format="html",
            correlation_summary=correlation_summary,
        )

        assert content is not None
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in content
        assert "Attack Chains" in content
        assert 'payload <script>alert("xss")</script>' not in content

    def test_generate_writes_output_file(self, tmp_path) -> None:
        reporter = Reporter()
        output_path = tmp_path / "report.json"

        content = reporter.generate(
            alerts=[make_alert()],
            entries=[make_entry()],
            format="json",
            output_path=str(output_path),
        )

        assert content == output_path.read_text(encoding="utf-8")

    def test_generate_raises_for_unknown_format(self) -> None:
        reporter = Reporter()

        with pytest.raises(ValueError, match="Unknown report format"):
            reporter.generate(alerts=[make_alert()], format="yaml")
