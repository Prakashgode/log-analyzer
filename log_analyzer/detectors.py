"""Threat detection engines for security log analysis.

Provides detectors for brute force attacks, privilege escalation,
suspicious commands, and statistical anomalies. Each detector
analyzes a list of LogEntry objects and returns Alert instances.
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional

from log_analyzer.parsers import LogEntry, Severity


class AlertSeverity(Enum):
    """Alert severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    """Structured representation of a detected security alert.

    Attributes:
        timestamp: When the alert was generated.
        alert_type: Category of the alert (e.g., 'brute_force').
        severity: Alert severity level.
        source_ip: Source IP address involved, if applicable.
        description: Human-readable description of the alert.
        evidence: List of raw log lines or entries supporting the alert.
        metadata: Additional structured data about the alert.
    """

    timestamp: datetime
    alert_type: str
    severity: AlertSeverity
    source_ip: Optional[str]
    description: str
    evidence: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize the alert to a dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "description": self.description,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


class BruteForceDetector:
    """Detect brute force login attempts.

    Identifies multiple failed authentication attempts from the same
    source IP within a configurable time window.

    Args:
        threshold: Number of failed attempts to trigger an alert.
        window_seconds: Time window in seconds to count failures.
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 300) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

    def detect(self, entries: List[LogEntry]) -> List[Alert]:
        """Analyze log entries for brute force patterns.

        Args:
            entries: List of parsed log entries.

        Returns:
            List of brute force alerts.
        """
        alerts: List[Alert] = []

        # Group failed login events by source IP
        failed_by_ip: defaultdict[str, List[LogEntry]] = defaultdict(list)

        for entry in entries:
            event_type = entry.metadata.get("event_type", "")
            source_ip = entry.metadata.get("source_ip")

            is_failed = (
                event_type == "failed_login"
                or event_type == "auth_failure"
                or (entry.source == "windows" and entry.metadata.get("event_id") == 4625)
            )

            if is_failed and source_ip:
                failed_by_ip[source_ip].append(entry)

        # Check each IP for brute force patterns
        for ip, failures in failed_by_ip.items():
            # Sort by timestamp
            failures.sort(key=lambda e: e.timestamp)

            # Sliding window detection
            window_start = 0
            for window_end in range(len(failures)):
                # Advance start of window
                while (
                    window_start < window_end
                    and (
                        failures[window_end].timestamp - failures[window_start].timestamp
                    ).total_seconds() > self.window_seconds
                ):
                    window_start += 1

                count = window_end - window_start + 1
                if count >= self.threshold:
                    # Determine severity based on volume
                    if count >= self.threshold * 4:
                        severity = AlertSeverity.CRITICAL
                    elif count >= self.threshold * 2:
                        severity = AlertSeverity.HIGH
                    else:
                        severity = AlertSeverity.MEDIUM

                    # Collect targeted usernames
                    targeted_users = set()
                    evidence_lines: List[str] = []
                    for f in failures[window_start : window_end + 1]:
                        evidence_lines.append(f.raw)
                        if f.metadata.get("username"):
                            targeted_users.add(f.metadata["username"])

                    alert = Alert(
                        timestamp=failures[window_end].timestamp,
                        alert_type="brute_force",
                        severity=severity,
                        source_ip=ip,
                        description=(
                            f"Brute force detected: {count} failed login attempts "
                            f"from {ip} within {self.window_seconds}s"
                        ),
                        evidence=evidence_lines,
                        metadata={
                            "attempt_count": count,
                            "window_seconds": self.window_seconds,
                            "targeted_users": sorted(targeted_users),
                            "first_attempt": failures[window_start].timestamp.isoformat(),
                            "last_attempt": failures[window_end].timestamp.isoformat(),
                        },
                    )
                    alerts.append(alert)
                    # Skip ahead to avoid duplicate alerts for the same cluster
                    break

        return alerts


class PrivilegeEscalationDetector:
    """Detect privilege escalation attempts.

    Identifies sudo abuse, unauthorized su usage, sensitive commands
    run as root, and Windows privilege assignment events.
    """

    _SENSITIVE_COMMANDS = [
        r"/bin/bash",
        r"/bin/sh",
        r"passwd",
        r"useradd",
        r"usermod",
        r"groupadd",
        r"visudo",
        r"chmod\s+[0-7]*[4-7][0-7]{2}",
        r"chown\s+root",
        r"/etc/shadow",
        r"/etc/sudoers",
    ]
    _SENSITIVE_PATTERN = re.compile("|".join(_SENSITIVE_COMMANDS), re.IGNORECASE)

    def detect(self, entries: List[LogEntry]) -> List[Alert]:
        """Analyze log entries for privilege escalation patterns.

        Args:
            entries: List of parsed log entries.

        Returns:
            List of privilege escalation alerts.
        """
        alerts: List[Alert] = []

        for entry in entries:
            event_type = entry.metadata.get("event_type", "")

            # Detect sudo to root with sensitive commands
            if event_type == "sudo_command":
                target_user = entry.metadata.get("target_user", "")
                command = entry.metadata.get("command", "")
                username = entry.metadata.get("username", "")

                if target_user == "root" and self._SENSITIVE_PATTERN.search(command):
                    alerts.append(Alert(
                        timestamp=entry.timestamp,
                        alert_type="privilege_escalation",
                        severity=AlertSeverity.HIGH,
                        source_ip=entry.metadata.get("source_ip"),
                        description=(
                            f"Sensitive sudo command by {username}: "
                            f"sudo -u {target_user} {command}"
                        ),
                        evidence=[entry.raw],
                        metadata={
                            "username": username,
                            "target_user": target_user,
                            "command": command,
                        },
                    ))

            # Detect su sessions to root
            elif event_type == "su_session":
                target_user = entry.metadata.get("target_user", "")
                action = entry.metadata.get("action", "")
                by_user = entry.metadata.get("by_user", "unknown")

                if target_user == "root" and action == "opened":
                    alerts.append(Alert(
                        timestamp=entry.timestamp,
                        alert_type="privilege_escalation",
                        severity=AlertSeverity.MEDIUM,
                        source_ip=entry.metadata.get("source_ip"),
                        description=(
                            f"su session to root opened by {by_user}"
                        ),
                        evidence=[entry.raw],
                        metadata={
                            "by_user": by_user,
                            "target_user": target_user,
                        },
                    ))

            # Detect Windows special privileges
            elif entry.source == "windows":
                event_id = entry.metadata.get("event_id")
                if event_id == 4672:
                    username = entry.metadata.get("SubjectUserName", "unknown")
                    alerts.append(Alert(
                        timestamp=entry.timestamp,
                        alert_type="privilege_escalation",
                        severity=AlertSeverity.MEDIUM,
                        source_ip=entry.metadata.get("IpAddress"),
                        description=(
                            f"Special privileges assigned to {username}"
                        ),
                        evidence=[entry.raw],
                        metadata={
                            "event_id": event_id,
                            "username": username,
                        },
                    ))

        return alerts


class SuspiciousCommandDetector:
    """Detect suspicious command execution patterns.

    Identifies reverse shell attempts, data exfiltration patterns,
    reconnaissance commands, and other indicators of compromise.
    """

    _REVERSE_SHELL_PATTERNS = [
        r"bash\s+-i\s+>&\s*/dev/tcp/",
        r"nc\s+-e\s+/bin/(ba)?sh",
        r"ncat\s.*-e\s+/bin/(ba)?sh",
        r"python\s+-c\s+.*socket.*connect",
        r"python3\s+-c\s+.*socket.*connect",
        r"perl\s+-e\s+.*socket.*INET",
        r"ruby\s+-rsocket\s+-e",
        r"php\s+-r\s+.*fsockopen",
        r"mkfifo\s+/tmp/",
        r"socat\s+.*exec:",
    ]

    _EXFIL_PATTERNS = [
        r"curl\s+.*-d\s+@",
        r"curl\s+.*--data.*@",
        r"wget\s+.*--post-file",
        r"scp\s+.*@.*:",
        r"rsync\s+.*@.*:",
        r"base64\s+.*\|\s*(curl|wget|nc)",
        r"tar\s+.*\|\s*(curl|wget|nc|ncat)",
        r"dd\s+if=/dev/sd",
    ]

    _RECON_PATTERNS = [
        r"cat\s+/etc/passwd",
        r"cat\s+/etc/shadow",
        r"cat\s+/etc/hosts",
        r"whoami",
        r"id\s*$",
        r"uname\s+-a",
        r"ifconfig\s*$",
        r"ip\s+addr",
        r"netstat\s+-",
        r"ss\s+-",
        r"ps\s+aux",
        r"find\s+/\s+.*-perm",
        r"find\s+.*-name\s+.*\.conf",
    ]

    def __init__(self) -> None:
        self._reverse_shell_re = re.compile(
            "|".join(self._REVERSE_SHELL_PATTERNS), re.IGNORECASE
        )
        self._exfil_re = re.compile(
            "|".join(self._EXFIL_PATTERNS), re.IGNORECASE
        )
        self._recon_re = re.compile(
            "|".join(self._RECON_PATTERNS), re.IGNORECASE
        )

    def detect(self, entries: List[LogEntry]) -> List[Alert]:
        """Analyze log entries for suspicious command patterns.

        Args:
            entries: List of parsed log entries.

        Returns:
            List of suspicious command alerts.
        """
        alerts: List[Alert] = []

        for entry in entries:
            command = entry.metadata.get("command", "")
            message = entry.message
            text_to_check = f"{command} {message}"

            # Check reverse shell patterns
            if self._reverse_shell_re.search(text_to_check):
                alerts.append(Alert(
                    timestamp=entry.timestamp,
                    alert_type="reverse_shell",
                    severity=AlertSeverity.CRITICAL,
                    source_ip=entry.metadata.get("source_ip"),
                    description=(
                        f"Reverse shell attempt detected: {command or message}"
                    ),
                    evidence=[entry.raw],
                    metadata={
                        "detection_type": "reverse_shell",
                        "command": command or message,
                        "hostname": entry.hostname,
                    },
                ))

            # Check data exfiltration patterns
            elif self._exfil_re.search(text_to_check):
                alerts.append(Alert(
                    timestamp=entry.timestamp,
                    alert_type="data_exfiltration",
                    severity=AlertSeverity.HIGH,
                    source_ip=entry.metadata.get("source_ip"),
                    description=(
                        f"Potential data exfiltration detected: {command or message}"
                    ),
                    evidence=[entry.raw],
                    metadata={
                        "detection_type": "data_exfiltration",
                        "command": command or message,
                        "hostname": entry.hostname,
                    },
                ))

            # Check reconnaissance patterns
            elif self._recon_re.search(text_to_check):
                alerts.append(Alert(
                    timestamp=entry.timestamp,
                    alert_type="reconnaissance",
                    severity=AlertSeverity.LOW,
                    source_ip=entry.metadata.get("source_ip"),
                    description=(
                        f"Reconnaissance command detected: {command or message}"
                    ),
                    evidence=[entry.raw],
                    metadata={
                        "detection_type": "reconnaissance",
                        "command": command or message,
                        "hostname": entry.hostname,
                    },
                ))

        return alerts


def run_all_detectors(
    entries,
    brute_force_threshold: int = 5,
    brute_force_window: int = 300,
    **kwargs,
):
    detectors = [
        BruteForceDetector(
            threshold=brute_force_threshold,
            window_seconds=brute_force_window,
        ),
        PrivilegeEscalationDetector(),
        SuspiciousCommandDetector(),
        # TODO: anomaly detection - need to figure out good z-score defaults
    ]

    all_alerts = []
    for detector in detectors:
        all_alerts.extend(detector.detect(entries))

    all_alerts.sort(key=lambda a: a.timestamp)
    return all_alerts
