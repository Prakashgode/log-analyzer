"""Event correlation engine for cross-source log analysis.

Links related security events across multiple log sources,
builds timelines, and detects multi-stage attack chains.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional

from log_analyzer.detectors import Alert, AlertSeverity
from log_analyzer.parsers import LogEntry


class AttackStage(Enum):
    """Stages in a typical attack chain (Cyber Kill Chain simplified)."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    UNKNOWN = "unknown"


@dataclass
class TimelineEvent:
    """A single event in a correlated timeline.

    Attributes:
        timestamp: When the event occurred.
        source: The log source type.
        hostname: Host that generated the event.
        description: Human-readable event description.
        severity: Severity level of the event.
        related_alert: Associated alert, if any.
        stage: Identified attack chain stage, if applicable.
        metadata: Additional event metadata.
    """

    timestamp: datetime
    source: str
    hostname: str
    description: str
    severity: str
    related_alert: Optional[Alert] = None
    stage: AttackStage = AttackStage.UNKNOWN
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize the timeline event to a dictionary."""
        result = {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "hostname": self.hostname,
            "description": self.description,
            "severity": self.severity,
            "stage": self.stage.value,
            "metadata": self.metadata,
        }
        if self.related_alert:
            result["alert"] = self.related_alert.to_dict()
        return result


@dataclass
class AttackChain:
    """A correlated sequence of events forming an attack chain.

    Attributes:
        chain_id: Unique identifier for this attack chain.
        source_ip: The primary source IP associated with this chain.
        stages: List of identified attack stages in order.
        events: List of timeline events in this chain.
        first_seen: Timestamp of the earliest event.
        last_seen: Timestamp of the latest event.
        overall_severity: Highest severity among all events.
        description: Summary description of the attack chain.
    """

    chain_id: str
    source_ip: str
    stages: List[AttackStage] = field(default_factory=list)
    events: List[TimelineEvent] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    overall_severity: AlertSeverity = AlertSeverity.LOW
    description: str = ""

    def to_dict(self) -> dict:
        """Serialize the attack chain to a dictionary."""
        return {
            "chain_id": self.chain_id,
            "source_ip": self.source_ip,
            "stages": [s.value for s in self.stages],
            "events": [e.to_dict() for e in self.events],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "overall_severity": self.overall_severity.value,
            "description": self.description,
        }


class EventCorrelator:
    """Correlates events across multiple log sources.

    Links related events by source IP, username, hostname, and
    temporal proximity. Builds timelines and detects multi-stage
    attack chains.

    Args:
        correlation_window: Maximum time gap (in seconds) between
            events to consider them related.
    """

    # Mapping from alert types / event types to attack stages
    _STAGE_MAP: dict[str, AttackStage] = {
        "reconnaissance": AttackStage.RECONNAISSANCE,
        "brute_force": AttackStage.INITIAL_ACCESS,
        "failed_login": AttackStage.INITIAL_ACCESS,
        "successful_login": AttackStage.INITIAL_ACCESS,
        "privilege_escalation": AttackStage.PRIVILEGE_ESCALATION,
        "sudo_command": AttackStage.PRIVILEGE_ESCALATION,
        "su_session": AttackStage.PRIVILEGE_ESCALATION,
        "lateral_movement": AttackStage.LATERAL_MOVEMENT,
        "reverse_shell": AttackStage.PERSISTENCE,
        "data_exfiltration": AttackStage.EXFILTRATION,
    }

    _SEVERITY_RANK: dict[AlertSeverity, int] = {
        AlertSeverity.LOW: 0,
        AlertSeverity.MEDIUM: 1,
        AlertSeverity.HIGH: 2,
        AlertSeverity.CRITICAL: 3,
    }

    def __init__(self, correlation_window: int = 3600) -> None:
        self.correlation_window = correlation_window
        self._entries: List[LogEntry] = []
        self._alerts: List[Alert] = []

    def add_entries(self, entries: List[LogEntry]) -> None:
        """Add parsed log entries for correlation.

        Args:
            entries: List of LogEntry instances to include.
        """
        self._entries.extend(entries)

    def add_alerts(self, alerts: List[Alert]) -> None:
        """Add detected alerts for correlation.

        Args:
            alerts: List of Alert instances to include.
        """
        self._alerts.extend(alerts)

    def build_timeline(
        self,
        source_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[TimelineEvent]:
        """Build a chronological timeline of events.

        Optionally filter by source IP, hostname, and time range.

        Args:
            source_ip: Filter events by source IP.
            hostname: Filter events by hostname.
            start_time: Include events on or after this time.
            end_time: Include events on or before this time.

        Returns:
            Sorted list of TimelineEvent instances.
        """
        timeline: List[TimelineEvent] = []

        for entry in self._entries:
            # Apply filters
            if source_ip and entry.metadata.get("source_ip") != source_ip:
                continue
            if hostname and entry.hostname != hostname:
                continue
            if start_time and entry.timestamp < start_time:
                continue
            if end_time and entry.timestamp > end_time:
                continue

            event_type = entry.metadata.get("event_type", "other")
            stage = self._STAGE_MAP.get(event_type, AttackStage.UNKNOWN)

            description = self._build_event_description(entry)

            timeline.append(TimelineEvent(
                timestamp=entry.timestamp,
                source=entry.source,
                hostname=entry.hostname,
                description=description,
                severity=entry.severity.value,
                stage=stage,
                metadata=entry.metadata.copy(),
            ))

        # Add alert events to the timeline
        for alert in self._alerts:
            if source_ip and alert.source_ip != source_ip:
                continue
            if start_time and alert.timestamp < start_time:
                continue
            if end_time and alert.timestamp > end_time:
                continue

            stage = self._STAGE_MAP.get(alert.alert_type, AttackStage.UNKNOWN)

            timeline.append(TimelineEvent(
                timestamp=alert.timestamp,
                source="alert",
                hostname="",
                description=alert.description,
                severity=alert.severity.value,
                related_alert=alert,
                stage=stage,
                metadata=alert.metadata.copy(),
            ))

        timeline.sort(key=lambda e: e.timestamp)
        return timeline

    def detect_attack_chains(self) -> List[AttackChain]:
        """Detect multi-stage attack chains.

        Groups events by source IP and identifies sequences that span
        multiple attack stages, indicating a coordinated attack.

        Returns:
            List of detected AttackChain instances.
        """
        # Group events and alerts by source IP
        ip_events: defaultdict[str, List[TimelineEvent]] = defaultdict(list)

        for entry in self._entries:
            ip = entry.metadata.get("source_ip")
            if not ip:
                continue

            event_type = entry.metadata.get("event_type", "other")
            stage = self._STAGE_MAP.get(event_type, AttackStage.UNKNOWN)

            ip_events[ip].append(TimelineEvent(
                timestamp=entry.timestamp,
                source=entry.source,
                hostname=entry.hostname,
                description=self._build_event_description(entry),
                severity=entry.severity.value,
                stage=stage,
                metadata=entry.metadata.copy(),
            ))

        for alert in self._alerts:
            if not alert.source_ip:
                continue

            stage = self._STAGE_MAP.get(alert.alert_type, AttackStage.UNKNOWN)
            ip_events[alert.source_ip].append(TimelineEvent(
                timestamp=alert.timestamp,
                source="alert",
                hostname="",
                description=alert.description,
                severity=alert.severity.value,
                related_alert=alert,
                stage=stage,
                metadata=alert.metadata.copy(),
            ))

        chains: List[AttackChain] = []
        chain_counter = 0

        for ip, events in ip_events.items():
            events.sort(key=lambda e: e.timestamp)

            # Group events into chains using the correlation window
            current_chain_events: List[TimelineEvent] = []

            for event in events:
                if (
                    current_chain_events
                    and (
                        event.timestamp - current_chain_events[-1].timestamp
                    ).total_seconds() > self.correlation_window
                ):
                    # Gap too large: finalize current chain if multi-stage
                    chain = self._build_chain(
                        chain_counter, ip, current_chain_events
                    )
                    if chain is not None:
                        chains.append(chain)
                        chain_counter += 1
                    current_chain_events = []

                current_chain_events.append(event)

            # Finalize remaining events
            if current_chain_events:
                chain = self._build_chain(
                    chain_counter, ip, current_chain_events
                )
                if chain is not None:
                    chains.append(chain)
                    chain_counter += 1

        # Sort chains by severity (highest first), then by first_seen
        chains.sort(
            key=lambda c: (
                -self._SEVERITY_RANK.get(c.overall_severity, 0),
                c.first_seen or datetime.min,
            )
        )

        return chains

    def _build_chain(
        self, counter: int, ip: str, events: List[TimelineEvent]
    ) -> Optional[AttackChain]:
        """Build an AttackChain from a group of events.

        Only creates a chain if there are at least two distinct
        attack stages (indicating a multi-stage attack).

        Args:
            counter: Chain counter for ID generation.
            ip: Source IP for the chain.
            events: List of timeline events.

        Returns:
            An AttackChain if multi-stage, otherwise None.
        """
        stages: List[AttackStage] = list(dict.fromkeys(
            e.stage for e in events if e.stage != AttackStage.UNKNOWN
        ))

        if len(stages) < 2:
            return None

        # Determine overall severity
        max_severity = AlertSeverity.LOW
        for event in events:
            if event.related_alert:
                sev = event.related_alert.severity
                if self._SEVERITY_RANK.get(sev, 0) > self._SEVERITY_RANK.get(max_severity, 0):
                    max_severity = sev

        # Also check severity strings for non-alert events
        severity_str_map: dict[str, AlertSeverity] = {
            "CRITICAL": AlertSeverity.CRITICAL,
            "ERROR": AlertSeverity.HIGH,
            "ALERT": AlertSeverity.HIGH,
            "WARNING": AlertSeverity.MEDIUM,
        }
        for event in events:
            mapped = severity_str_map.get(event.severity)
            if mapped and self._SEVERITY_RANK.get(mapped, 0) > self._SEVERITY_RANK.get(max_severity, 0):
                max_severity = mapped

        stage_names = " -> ".join(s.value for s in stages)
        description = (
            f"Multi-stage attack from {ip}: {stage_names} "
            f"({len(events)} events over "
            f"{(events[-1].timestamp - events[0].timestamp).total_seconds():.0f}s)"
        )

        return AttackChain(
            chain_id=f"chain-{counter:04d}",
            source_ip=ip,
            stages=stages,
            events=events,
            first_seen=events[0].timestamp,
            last_seen=events[-1].timestamp,
            overall_severity=max_severity,
            description=description,
        )

    def _build_event_description(self, entry: LogEntry) -> str:
        """Build a human-readable description from a log entry."""
        event_type = entry.metadata.get("event_type", "")
        username = entry.metadata.get("username", "")
        source_ip = entry.metadata.get("source_ip", "")

        if event_type == "failed_login":
            return f"Failed login for {username} from {source_ip}"
        elif event_type == "successful_login":
            method = entry.metadata.get("auth_method", "unknown")
            return f"Successful {method} login for {username} from {source_ip}"
        elif event_type == "sudo_command":
            command = entry.metadata.get("command", "")
            target = entry.metadata.get("target_user", "")
            return f"sudo by {username} as {target}: {command}"
        elif event_type == "su_session":
            action = entry.metadata.get("action", "")
            target = entry.metadata.get("target_user", "")
            return f"su session {action} for {target}"
        else:
            return entry.message[:200]

    def get_summary(self) -> dict:
        """Generate a correlation summary.

        Returns:
            Dictionary with counts and high-level statistics.
        """
        chains = self.detect_attack_chains()
        timeline = self.build_timeline()

        unique_ips: set[str] = set()
        for entry in self._entries:
            ip = entry.metadata.get("source_ip")
            if ip:
                unique_ips.add(ip)

        unique_hosts: set[str] = set()
        for entry in self._entries:
            unique_hosts.add(entry.hostname)

        return {
            "total_entries": len(self._entries),
            "total_alerts": len(self._alerts),
            "total_timeline_events": len(timeline),
            "attack_chains_detected": len(chains),
            "unique_source_ips": len(unique_ips),
            "unique_hosts": len(unique_hosts),
            "chains": [c.to_dict() for c in chains],
        }
