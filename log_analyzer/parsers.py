"""Log parsers for multiple formats.

Provides parsers for syslog, auth.log, Apache/Nginx access logs,
and Windows Event Log XML exports. Each parser returns structured
LogEntry dataclass instances.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import IO, List, Optional, Union


class Severity(Enum):
    """Log entry severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"
    EMERGENCY = "EMERGENCY"


@dataclass
class LogEntry:
    """Structured representation of a parsed log entry.

    Attributes:
        timestamp: When the event occurred.
        source: The log source type (e.g., 'syslog', 'authlog').
        hostname: The host that generated the entry.
        message: The parsed message content.
        severity: Severity level of the entry.
        raw: The original raw log line.
        program: The program or service that generated the entry.
        pid: Process ID if available.
        metadata: Additional key-value metadata extracted during parsing.
    """

    timestamp: datetime
    source: str
    hostname: str
    message: str
    severity: Severity
    raw: str
    program: Optional[str] = None
    pid: Optional[int] = None
    metadata: dict = field(default_factory=dict)


class BaseParser(ABC):
    """Abstract base class for all log parsers.

    Subclasses must implement ``parse_line`` to handle their specific
    log format. ``parse_file`` and ``parse_stream`` are provided for
    convenience.
    """

    source_type: str = "unknown"

    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line into a LogEntry.

        Args:
            line: A single raw log line.

        Returns:
            A LogEntry if the line was successfully parsed, otherwise None.
        """

    def parse_file(self, filepath: Union[str, Path]) -> List[LogEntry]:
        """Parse all lines in a log file.

        Args:
            filepath: Path to the log file.

        Returns:
            List of successfully parsed LogEntry instances.
        """
        filepath = Path(filepath)
        entries: List[LogEntry] = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            entries = self.parse_stream(fh)
        return entries

    def parse_stream(self, stream: IO[str]) -> List[LogEntry]:
        """Parse lines from a text stream.

        Args:
            stream: A readable text stream.

        Returns:
            List of successfully parsed LogEntry instances.
        """
        entries: List[LogEntry] = []
        for line in stream:
            line = line.rstrip("\n\r")
            if not line:
                continue
            entry = self.parse_line(line)
            if entry is not None:
                entries.append(entry)
        return entries


class SyslogParser(BaseParser):
    """Parser for standard RFC 3164 syslog format.

    Expected format::

        Jan  5 14:23:01 webserver01 sshd[12345]: Accepted publickey for user ...

    Handles the common BSD syslog format with month, day, time, hostname,
    program[pid], and message fields.
    """

    source_type: str = "syslog"

    # RFC 3164 pattern: "Mon DD HH:MM:SS hostname program[pid]: message"
    _PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>[\w\-\.\/]+)"
        r"(?:\[(?P<pid>\d+)\])?"
        r":\s+"
        r"(?P<message>.+)$"
    )

    _SEVERITY_KEYWORDS = {
        "emerg": Severity.EMERGENCY,
        "alert": Severity.ALERT,
        "crit": Severity.CRITICAL,
        "err": Severity.ERROR,
        "error": Severity.ERROR,
        "warn": Severity.WARNING,
        "warning": Severity.WARNING,
        "notice": Severity.NOTICE,
        "info": Severity.INFO,
        "debug": Severity.DEBUG,
    }

    def _infer_severity(self, message: str) -> Severity:
        """Infer severity from message keywords."""
        msg_lower = message.lower()
        for keyword, severity in self._SEVERITY_KEYWORDS.items():
            if keyword in msg_lower:
                return severity
        return Severity.INFO

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single syslog line.

        Args:
            line: A raw syslog line.

        Returns:
            A LogEntry if parsing succeeds, otherwise None.
        """
        match = self._PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp (syslog has no year, assume current year)
        try:
            ts = datetime.strptime(groups["timestamp"], "%b %d %H:%M:%S")
            ts = ts.replace(year=datetime.now().year)
        except ValueError:
            try:
                ts = datetime.strptime(groups["timestamp"], "%b  %d %H:%M:%S")
                ts = ts.replace(year=datetime.now().year)
            except ValueError:
                return None

        pid = int(groups["pid"]) if groups["pid"] else None
        message = groups["message"]

        return LogEntry(
            timestamp=ts,
            source=self.source_type,
            hostname=groups["hostname"],
            message=message,
            severity=self._infer_severity(message),
            raw=line,
            program=groups["program"],
            pid=pid,
        )


def get_parser(format_name: str) -> BaseParser:
    parsers: dict[str, type[BaseParser]] = {
        "syslog": SyslogParser,
    }

    if format_name not in parsers:
        valid = ", ".join(sorted(parsers.keys()))
        raise ValueError(f"Unknown log format '{format_name}'. Valid formats: {valid}")

    return parsers[format_name]()
