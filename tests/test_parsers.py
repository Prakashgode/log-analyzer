"""Tests for log parsers."""

from __future__ import annotations

import os
import tempfile
import textwrap
from datetime import datetime
from io import StringIO

import pytest

from log_analyzer.parsers import (
    ApacheParser,
    AuthLogParser,
    LogEntry,
    Severity,
    SyslogParser,
    WindowsEventParser,
    get_parser,
)


# ---------------------------------------------------------------------------
# SyslogParser tests
# ---------------------------------------------------------------------------

class TestSyslogParser:
    """Tests for the SyslogParser class."""

    def setup_method(self) -> None:
        self.parser = SyslogParser()
        self.year = datetime.now().year

    def test_parse_standard_syslog_line(self) -> None:
        line = "Jan  5 14:23:01 webserver01 sshd[12345]: Accepted publickey for user1 from 10.0.0.1 port 22 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 5
        assert entry.timestamp.hour == 14
        assert entry.timestamp.minute == 23
        assert entry.timestamp.second == 1
        assert entry.hostname == "webserver01"
        assert entry.program == "sshd"
        assert entry.pid == 12345
        assert entry.source == "syslog"
        assert "Accepted publickey" in entry.message
        assert entry.raw == line

    def test_parse_syslog_without_pid(self) -> None:
        line = "Jan 10 08:00:00 myhost kernel: some kernel message"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.program == "kernel"
        assert entry.pid is None
        assert entry.hostname == "myhost"

    def test_parse_syslog_error_severity(self) -> None:
        line = "Feb  3 12:00:00 server1 app[999]: ERROR: Connection refused"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.severity == Severity.ERROR

    def test_parse_syslog_warning_severity(self) -> None:
        line = "Mar 15 09:30:00 server1 app[100]: WARNING: Disk space low"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.severity == Severity.WARNING

    def test_parse_invalid_line_returns_none(self) -> None:
        entry = self.parser.parse_line("this is not a valid syslog line")
        assert entry is None

    def test_parse_empty_line_returns_none(self) -> None:
        entry = self.parser.parse_line("")
        assert entry is None

    def test_parse_stream(self) -> None:
        log_data = textwrap.dedent("""\
            Jan  5 14:23:01 host1 sshd[123]: message one
            Jan  5 14:23:02 host1 sshd[124]: message two
            Jan  5 14:23:03 host1 sshd[125]: message three
        """)
        stream = StringIO(log_data)
        entries = self.parser.parse_stream(stream)

        assert len(entries) == 3
        assert entries[0].message == "message one"
        assert entries[2].message == "message three"

    def test_parse_file(self) -> None:
        fd, path = tempfile.mkstemp(suffix=".log")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("Jan  1 00:00:00 host svc[1]: test entry\n")
                f.write("Jan  1 00:00:01 host svc[2]: second entry\n")
            entries = self.parser.parse_file(path)

            assert len(entries) == 2
            assert entries[0].message == "test entry"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# AuthLogParser tests
# ---------------------------------------------------------------------------

class TestAuthLogParser:
    """Tests for the AuthLogParser class."""

    def setup_method(self) -> None:
        self.parser = AuthLogParser()

    def test_parse_failed_password(self) -> None:
        line = "Jan  5 14:23:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["event_type"] == "failed_login"
        assert entry.metadata["username"] == "root"
        assert entry.metadata["source_ip"] == "192.168.1.100"
        assert entry.metadata["port"] == 22
        assert entry.severity == Severity.WARNING

    def test_parse_failed_password_invalid_user(self) -> None:
        line = "Jan  5 14:23:01 server sshd[12345]: Failed password for invalid user admin from 10.0.0.5 port 4444 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["event_type"] == "failed_login"
        assert entry.metadata["username"] == "admin"
        assert entry.metadata["source_ip"] == "10.0.0.5"

    def test_parse_accepted_login(self) -> None:
        line = "Jan  5 14:23:01 server sshd[12345]: Accepted publickey for user1 from 10.0.0.1 port 22 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["event_type"] == "successful_login"
        assert entry.metadata["username"] == "user1"
        assert entry.metadata["source_ip"] == "10.0.0.1"
        assert entry.metadata["auth_method"] == "publickey"
        assert entry.severity == Severity.INFO

    def test_parse_sudo_command(self) -> None:
        line = "Jan  5 14:23:01 server sudo[999]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["event_type"] == "sudo_command"
        assert entry.metadata["username"] == "admin"
        assert entry.metadata["target_user"] == "root"
        assert entry.metadata["command"] == "/bin/bash"
        assert entry.severity == Severity.WARNING  # root target

    def test_parse_su_session(self) -> None:
        line = "Jan  5 14:23:01 server su[500]: pam_unix(su:session): session opened for user root by admin(uid=1000)"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["event_type"] == "su_session"
        assert entry.metadata["target_user"] == "root"
        assert entry.metadata["action"] == "opened"

    def test_parse_auth_failure_generic(self) -> None:
        line = "Jan  5 14:23:01 server login[300]: authentication failure; logname= uid=0 euid=0 tty=tty1"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["event_type"] == "auth_failure"
        assert entry.severity == Severity.WARNING


# ---------------------------------------------------------------------------
# ApacheParser tests
# ---------------------------------------------------------------------------
