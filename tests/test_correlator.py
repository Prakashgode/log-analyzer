"""Tests for the event correlator."""

from __future__ import annotations

from datetime import datetime, timedelta

from log_analyzer.correlator import AttackStage, EventCorrelator
from log_analyzer.detectors import Alert, AlertSeverity
from log_analyzer.parsers import LogEntry, Severity

BASE_TIME = datetime(2026, 1, 15, 12, 0, 0)


def make_entry(
    *,
    minutes: int,
    source: str = "authlog",
    hostname: str = "host-a",
    message: str = "event",
    severity: Severity = Severity.INFO,
    metadata: dict | None = None,
) -> LogEntry:
    return LogEntry(
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        source=source,
        hostname=hostname,
        message=message,
        severity=severity,
        raw=message,
        program="sshd",
        metadata=metadata or {},
    )


def make_alert(
    *,
    minutes: int,
    alert_type: str = "brute_force",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    source_ip: str | None = "10.0.0.5",
    description: str = "alert",
    metadata: dict | None = None,
) -> Alert:
    return Alert(
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        alert_type=alert_type,
        severity=severity,
        source_ip=source_ip,
        description=description,
        evidence=["line one", "line two"],
        metadata=metadata or {},
    )


class TestEventCorrelator:
    """Tests for event correlation and chain detection."""

    def test_build_timeline_filters_sorts_and_links_alerts(self) -> None:
        correlator = EventCorrelator()
        correlator.add_entries(
            [
                make_entry(
                    minutes=2,
                    message="failed login raw",
                    severity=Severity.WARNING,
                    metadata={
                        "event_type": "failed_login",
                        "username": "admin",
                        "source_ip": "10.0.0.5",
                    },
                ),
                make_entry(
                    minutes=5,
                    message="sudo raw",
                    severity=Severity.WARNING,
                    metadata={
                        "event_type": "sudo_command",
                        "username": "admin",
                        "target_user": "root",
                        "command": "/bin/bash",
                        "source_ip": "10.0.0.5",
                    },
                ),
                make_entry(
                    minutes=1,
                    hostname="host-b",
                    metadata={
                        "event_type": "failed_login",
                        "username": "guest",
                        "source_ip": "192.168.1.10",
                    },
                ),
            ]
        )
        alert = make_alert(minutes=3, description="Brute force confirmed")
        correlator.add_alerts([alert])

        timeline = correlator.build_timeline(
            source_ip="10.0.0.5",
            hostname="host-a",
            start_time=BASE_TIME + timedelta(minutes=2),
            end_time=BASE_TIME + timedelta(minutes=5),
        )

        assert [event.source for event in timeline] == ["authlog", "alert", "authlog"]
        assert timeline[0].description == "Failed login for admin from 10.0.0.5"
        assert timeline[0].stage == AttackStage.INITIAL_ACCESS
        assert timeline[1].related_alert == alert
        assert timeline[1].stage == AttackStage.INITIAL_ACCESS
        assert timeline[2].description == "sudo by admin as root: /bin/bash"
        assert timeline[2].stage == AttackStage.PRIVILEGE_ESCALATION

    def test_detect_attack_chains_requires_multiple_stages(self) -> None:
        correlator = EventCorrelator(correlation_window=600)
        correlator.add_entries(
            [
                make_entry(
                    minutes=0,
                    message="failed login",
                    severity=Severity.WARNING,
                    metadata={
                        "event_type": "failed_login",
                        "username": "admin",
                        "source_ip": "10.0.0.5",
                    },
                ),
                make_entry(
                    minutes=1,
                    message="sudo command",
                    severity=Severity.ERROR,
                    metadata={
                        "event_type": "sudo_command",
                        "username": "admin",
                        "target_user": "root",
                        "command": "/bin/bash",
                        "source_ip": "10.0.0.5",
                    },
                ),
                make_entry(
                    minutes=2,
                    message="failed login only",
                    severity=Severity.WARNING,
                    metadata={
                        "event_type": "failed_login",
                        "username": "guest",
                        "source_ip": "192.168.1.10",
                    },
                ),
            ]
        )
        correlator.add_alerts(
            [
                make_alert(
                    minutes=3,
                    alert_type="privilege_escalation",
                    severity=AlertSeverity.HIGH,
                    source_ip="10.0.0.5",
                    description="Privilege escalation confirmed",
                ),
            ]
        )

        chains = correlator.detect_attack_chains()

        assert len(chains) == 1
        chain = chains[0]
        assert chain.chain_id == "chain-0000"
        assert chain.source_ip == "10.0.0.5"
        assert chain.stages == [
            AttackStage.INITIAL_ACCESS,
            AttackStage.PRIVILEGE_ESCALATION,
        ]
        assert chain.overall_severity == AlertSeverity.HIGH
        assert chain.first_seen == BASE_TIME
        assert chain.last_seen == BASE_TIME + timedelta(minutes=3)
        assert "Multi-stage attack from 10.0.0.5" in chain.description

    def test_get_summary_counts_hosts_ips_and_serializes_chains(self) -> None:
        correlator = EventCorrelator(correlation_window=600)
        correlator.add_entries(
            [
                make_entry(
                    minutes=0,
                    message="failed login",
                    severity=Severity.WARNING,
                    metadata={
                        "event_type": "failed_login",
                        "username": "admin",
                        "source_ip": "10.0.0.5",
                    },
                ),
                make_entry(
                    minutes=2,
                    hostname="host-b",
                    source="syslog",
                    message="sudo command",
                    severity=Severity.ERROR,
                    metadata={
                        "event_type": "sudo_command",
                        "username": "admin",
                        "target_user": "root",
                        "command": "/bin/bash",
                        "source_ip": "10.0.0.5",
                    },
                ),
                make_entry(
                    minutes=4,
                    hostname="host-c",
                    metadata={
                        "event_type": "other",
                        "source_ip": "192.168.1.10",
                    },
                ),
            ]
        )
        correlator.add_alerts(
            [
                make_alert(
                    minutes=3,
                    alert_type="privilege_escalation",
                    severity=AlertSeverity.HIGH,
                    source_ip="10.0.0.5",
                    description="Privilege escalation confirmed",
                ),
            ]
        )

        summary = correlator.get_summary()

        assert summary["total_entries"] == 3
        assert summary["total_alerts"] == 1
        assert summary["total_timeline_events"] == 4
        assert summary["attack_chains_detected"] == 1
        assert summary["unique_source_ips"] == 2
        assert summary["unique_hosts"] == 3
        assert summary["chains"][0]["source_ip"] == "10.0.0.5"
        assert summary["chains"][0]["overall_severity"] == "HIGH"
