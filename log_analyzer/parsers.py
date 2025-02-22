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


class AuthLogParser(BaseParser):
    """Parser for Linux auth.log files.

    Handles SSH login attempts, sudo commands, su sessions, and other
    PAM authentication events. Extracts additional metadata such as
    source IP addresses, usernames, and authentication methods.

    Expected format::

        Jan  5 14:23:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
    """

    source_type: str = "authlog"

    _PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>[\w\-\.\/]+)"
        r"(?:\[(?P<pid>\d+)\])?"
        r":\s+"
        r"(?P<message>.+)$"
    )

    _FAILED_SSH = re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+)\s+"
        r"from (?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )
    _ACCEPTED_SSH = re.compile(
        r"Accepted (?P<method>\S+) for (?P<user>\S+)\s+"
        r"from (?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )
    _SUDO_COMMAND = re.compile(
        r"(?P<user>\S+)\s+:\s+TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*"
        r"COMMAND=(?P<command>.+)$"
    )
    _SU_SESSION = re.compile(
        r"pam_unix\(su(?:-l)?:session\):\s+session (?P<action>opened|closed)\s+"
        r"for user (?P<target_user>\S+)(?:\s+by\s+(?P<by_user>\S+))?"
    )

    def _classify_auth_event(self, message: str) -> tuple[Severity, dict]:
        """Classify the auth event and extract metadata."""
        metadata: dict = {}

        failed_match = self._FAILED_SSH.search(message)
        if failed_match:
            metadata["event_type"] = "failed_login"
            metadata["username"] = failed_match.group("user")
            metadata["source_ip"] = failed_match.group("ip")
            metadata["port"] = int(failed_match.group("port"))
            return Severity.WARNING, metadata

        accepted_match = self._ACCEPTED_SSH.search(message)
        if accepted_match:
            metadata["event_type"] = "successful_login"
            metadata["username"] = accepted_match.group("user")
            metadata["source_ip"] = accepted_match.group("ip")
            metadata["port"] = int(accepted_match.group("port"))
            metadata["auth_method"] = accepted_match.group("method")
            return Severity.INFO, metadata

        sudo_match = self._SUDO_COMMAND.search(message)
        if sudo_match:
            metadata["event_type"] = "sudo_command"
            metadata["username"] = sudo_match.group("user")
            metadata["target_user"] = sudo_match.group("target_user")
            metadata["command"] = sudo_match.group("command")
            severity = Severity.NOTICE
            if sudo_match.group("target_user") == "root":
                severity = Severity.WARNING
            return severity, metadata

        su_match = self._SU_SESSION.search(message)
        if su_match:
            metadata["event_type"] = "su_session"
            metadata["action"] = su_match.group("action")
            metadata["target_user"] = su_match.group("target_user")
            if su_match.group("by_user"):
                metadata["by_user"] = su_match.group("by_user")
            return Severity.NOTICE, metadata

        if "authentication failure" in message.lower():
            metadata["event_type"] = "auth_failure"
            return Severity.WARNING, metadata

        metadata["event_type"] = "other"
        return Severity.INFO, metadata

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single auth.log line.

        Args:
            line: A raw auth.log line.

        Returns:
            A LogEntry if parsing succeeds, otherwise None.
        """
        match = self._PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

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
        severity, metadata = self._classify_auth_event(message)

        return LogEntry(
            timestamp=ts,
            source=self.source_type,
            hostname=groups["hostname"],
            message=message,
            severity=severity,
            raw=line,
            program=groups["program"],
            pid=pid,
            metadata=metadata,
        )


class ApacheParser(BaseParser):
    """Parser for Apache/Nginx combined and common access log formats.

    Combined log format::

        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref.com" "Mozilla/5.0"

    Common log format::

        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326
    """

    source_type: str = "apache"

    # Combined log format regex
    _PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    _SUSPICIOUS_PATHS = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"\.\./",
        r"/wp-admin",
        r"/phpmyadmin",
        r"/admin",
        r"\.env",
        r"/\.git",
        r"/shell",
        r"/cmd",
        r"/eval",
    ]
    _SUSPICIOUS_PATTERN = re.compile("|".join(_SUSPICIOUS_PATHS), re.IGNORECASE)

    def _status_to_severity(self, status: int, path: str) -> Severity:
        """Map HTTP status code and path to severity."""
        if self._SUSPICIOUS_PATTERN.search(path):
            return Severity.WARNING
        if status >= 500:
            return Severity.ERROR
        if status == 403:
            return Severity.WARNING
        if status == 404:
            return Severity.NOTICE
        if status >= 400:
            return Severity.NOTICE
        return Severity.INFO

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single Apache/Nginx access log line.

        Args:
            line: A raw access log line.

        Returns:
            A LogEntry if parsing succeeds, otherwise None.
        """
        match = self._PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Parse Apache timestamp: 10/Oct/2000:13:55:36 -0700
        try:
            ts = datetime.strptime(groups["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
            # Convert to naive datetime for consistent comparison
            ts = ts.replace(tzinfo=None)
        except ValueError:
            try:
                # Try without timezone
                ts_str = groups["timestamp"].rsplit(" ", 1)[0]
                ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None

        status = int(groups["status"])
        path = groups["path"]
        size = int(groups["size"]) if groups["size"] != "-" else 0

        message = f'{groups["method"]} {path} {groups["protocol"]} {status}'

        metadata: dict = {
            "source_ip": groups["ip"],
            "method": groups["method"],
            "path": path,
            "protocol": groups["protocol"],
            "status_code": status,
            "response_size": size,
            "ident": groups["ident"],
            "remote_user": groups["user"],
        }

        if groups.get("referrer"):
            metadata["referrer"] = groups["referrer"]
        if groups.get("user_agent"):
            metadata["user_agent"] = groups["user_agent"]

        return LogEntry(
            timestamp=ts,
            source=self.source_type,
            hostname=groups["ip"],
            message=message,
            severity=self._status_to_severity(status, path),
            raw=line,
            metadata=metadata,
        )


class WindowsEventParser(BaseParser):
    """Parser for Windows Event Log XML exports.

    Handles the XML format produced by ``wevtutil qe`` or exported
    from Event Viewer. Each ``<Event>`` element is parsed into a
    LogEntry with extracted metadata.

    Expected XML structure::

        <Events>
          <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
              <Provider Name="..." />
              <EventID>4625</EventID>
              <Level>0</Level>
              <TimeCreated SystemTime="2024-01-05T14:23:01.000Z" />
              <Computer>WORKSTATION01</Computer>
            </System>
            <EventData>
              <Data Name="TargetUserName">admin</Data>
              ...
            </EventData>
          </Event>
        </Events>
    """

    source_type: str = "windows"

    _NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

    _LEVEL_MAP: dict[int, Severity] = {
        0: Severity.INFO,       # LogAlways
        1: Severity.CRITICAL,   # Critical
        2: Severity.ERROR,      # Error
        3: Severity.WARNING,    # Warning
        4: Severity.INFO,       # Informational
        5: Severity.DEBUG,      # Verbose
    }

    # Security event IDs of interest
    _SECURITY_EVENTS: dict[int, str] = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4634: "Logoff",
        4648: "Logon Using Explicit Credentials",
        4672: "Special Privileges Assigned",
        4688: "Process Creation",
        4697: "Service Installed",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4724: "Password Reset Attempted",
        4732: "Member Added to Security Group",
        4768: "Kerberos TGT Requested",
        4769: "Kerberos Service Ticket Requested",
        4776: "NTLM Authentication",
    }

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse is not used for XML; use parse_file or parse_xml instead.

        This method attempts to parse a single-line XML Event element.
        For multi-line XML, use ``parse_xml_string`` or ``parse_file``.
        """
        # Attempt to parse a single <Event>...</Event> line
        return self._parse_event_xml(line)

    def parse_file(self, filepath: Union[str, Path]) -> List[LogEntry]:
        """Parse a Windows Event Log XML export file.

        Handles both single-root ``<Events>`` documents and files
        containing multiple ``<Event>`` elements.

        Args:
            filepath: Path to the XML event log file.

        Returns:
            List of successfully parsed LogEntry instances.
        """
        filepath = Path(filepath)
        content = filepath.read_text(encoding="utf-8", errors="replace")
        return self.parse_xml_string(content)

    def parse_xml_string(self, xml_content: str) -> List[LogEntry]:
        """Parse a Windows Event Log XML string.

        Args:
            xml_content: XML string containing Event elements.

        Returns:
            List of successfully parsed LogEntry instances.
        """
        entries: List[LogEntry] = []

        # Wrap in root if needed
        stripped = xml_content.strip()
        if not stripped.startswith("<Events"):
            if stripped.startswith("<Event"):
                xml_content = f"<Events>{xml_content}</Events>"
            else:
                return entries

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return entries

        # Find all Event elements (with or without namespace)
        events = root.findall("evt:Event", self._NS)
        if not events:
            events = root.findall("Event")
        if not events:
            events = root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Event")

        for event_elem in events:
            entry = self._parse_event_element(event_elem)
            if entry is not None:
                entries.append(entry)

        return entries

    def _parse_event_xml(self, xml_line: str) -> Optional[LogEntry]:
        """Parse a single Event XML element from a string."""
        try:
            elem = ET.fromstring(xml_line)
            return self._parse_event_element(elem)
        except ET.ParseError:
            return None

    @staticmethod
    def _find_element(parent: ET.Element, ns_name: str, bare_name: str, ns: dict) -> Optional[ET.Element]:
        """Find an element by namespaced name first, then bare name.

        Uses explicit ``is None`` checks to avoid issues with
        ElementTree elements whose boolean evaluation depends on
        child count.
        """
        elem = parent.find(ns_name, ns)
        if elem is None:
            elem = parent.find(bare_name)
        return elem

    def _parse_event_element(self, event: ET.Element) -> Optional[LogEntry]:
        """Parse an ET Event element into a LogEntry."""
        ns = self._NS

        # Try namespaced first, then bare
        system = self._find_element(event, "evt:System", "System", ns)
        if system is None:
            return None

        # Extract fields from System
        provider_elem = self._find_element(system, "evt:Provider", "Provider", ns)
        provider_name = ""
        if provider_elem is not None:
            provider_name = provider_elem.get("Name", "")

        event_id_elem = self._find_element(system, "evt:EventID", "EventID", ns)
        event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

        level_elem = self._find_element(system, "evt:Level", "Level", ns)
        level = int(level_elem.text) if level_elem is not None and level_elem.text else 4

        time_elem = self._find_element(system, "evt:TimeCreated", "TimeCreated", ns)
        if time_elem is None:
            return None

        time_str = time_elem.get("SystemTime", "")
        try:
            # Handle various timestamp formats
            if time_str.endswith("Z"):
                ts = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                ts = ts.replace(tzinfo=None)
            else:
                ts = datetime.fromisoformat(time_str)
                ts = ts.replace(tzinfo=None)
        except ValueError:
            return None

        computer_elem = self._find_element(system, "evt:Computer", "Computer", ns)
        hostname = computer_elem.text if computer_elem is not None and computer_elem.text else "unknown"

        # Extract EventData
        metadata: dict = {
            "event_id": event_id,
            "provider": provider_name,
        }

        event_data = self._find_element(event, "evt:EventData", "EventData", ns)
        if event_data is not None:
            for data_elem in event_data:
                name = data_elem.get("Name", "")
                value = data_elem.text or ""
                if name:
                    metadata[name] = value

        # Build message
        event_description = self._SECURITY_EVENTS.get(event_id, f"Event {event_id}")
        message = f"[{provider_name}] {event_description}"

        severity = self._LEVEL_MAP.get(level, Severity.INFO)
        # Elevate severity for known security events
        if event_id in (4625, 4648, 4672, 4697, 4720, 4732):
            if severity.value in ("INFO", "DEBUG"):
                severity = Severity.WARNING

        return LogEntry(
            timestamp=ts,
            source=self.source_type,
            hostname=hostname,
            message=message,
            severity=severity,
            raw=ET.tostring(event, encoding="unicode"),
            program=provider_name,
            metadata=metadata,
        )


def get_parser(format_name: str) -> BaseParser:
    """Factory function to get a parser by format name.

    Args:
        format_name: One of 'syslog', 'authlog', 'apache', 'windows'.

    Returns:
        An instance of the appropriate parser.

    Raises:
        ValueError: If the format name is not recognized.
    """
    parsers: dict[str, type[BaseParser]] = {
        "syslog": SyslogParser,
        "authlog": AuthLogParser,
        "apache": ApacheParser,
        "windows": WindowsEventParser,
    }

    if format_name not in parsers:
        valid = ", ".join(sorted(parsers.keys()))
        raise ValueError(f"Unknown log format '{format_name}'. Valid formats: {valid}")

    return parsers[format_name]()
