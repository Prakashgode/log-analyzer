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


def run_all_detectors(
    entries,
    brute_force_threshold: int = 5,
    brute_force_window: int = 300,
    **kwargs,
):
    # TODO: add more detectors
    detectors = [
        BruteForceDetector(
            threshold=brute_force_threshold,
            window_seconds=brute_force_window,
        ),
    ]

    all_alerts = []
    for detector in detectors:
        all_alerts.extend(detector.detect(entries))

    all_alerts.sort(key=lambda a: a.timestamp)
    return all_alerts
