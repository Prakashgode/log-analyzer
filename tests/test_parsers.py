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

    def test_parse_syslog_december_rolls_back_during_january(self, monkeypatch: pytest.MonkeyPatch) -> None:
        reference_time = datetime(2026, 1, 2, 9, 0, 0)
        monkeypatch.setattr(self.parser, "_current_time", lambda: reference_time)

        line = "Dec 31 23:59:59 host1 sshd[123]: year rollover check"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.timestamp == datetime(2025, 12, 31, 23, 59, 59)

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

class TestApacheParser:
    """Tests for the ApacheParser class."""

    def setup_method(self) -> None:
        self.parser = ApacheParser()

    def test_parse_combined_log_format(self) -> None:
        line = (
            '192.168.1.50 - frank [10/Oct/2024:13:55:36 -0700] '
            '"GET /index.html HTTP/1.1" 200 2326 '
            '"http://www.example.com/" "Mozilla/5.0 (X11; Linux x86_64)"'
        )
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["source_ip"] == "192.168.1.50"
        assert entry.metadata["method"] == "GET"
        assert entry.metadata["path"] == "/index.html"
        assert entry.metadata["status_code"] == 200
        assert entry.metadata["response_size"] == 2326
        assert entry.metadata["remote_user"] == "frank"
        assert entry.metadata["referrer"] == "http://www.example.com/"
        assert "Mozilla" in entry.metadata["user_agent"]
        assert entry.severity == Severity.INFO

    def test_parse_common_log_format(self) -> None:
        line = '127.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "GET /page HTTP/1.0" 200 1234'
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.metadata["source_ip"] == "127.0.0.1"
        assert entry.metadata["path"] == "/page"

    def test_parse_404_severity(self) -> None:
        line = '10.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "GET /missing HTTP/1.1" 404 0'
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.severity == Severity.NOTICE

    def test_parse_500_severity(self) -> None:
        line = '10.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "POST /api HTTP/1.1" 500 128'
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.severity == Severity.ERROR

    def test_parse_suspicious_path(self) -> None:
        line = '10.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "GET /etc/passwd HTTP/1.1" 200 0'
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.severity == Severity.WARNING

    def test_parse_directory_traversal(self) -> None:
        line = '10.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "GET /../../etc/shadow HTTP/1.1" 403 0'
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.severity == Severity.WARNING

    def test_parse_invalid_line(self) -> None:
        entry = self.parser.parse_line("not an access log line")
        assert entry is None


# ---------------------------------------------------------------------------
# WindowsEventParser tests
# ---------------------------------------------------------------------------

class TestWindowsEventParser:
    """Tests for the WindowsEventParser class."""

    def setup_method(self) -> None:
        self.parser = WindowsEventParser()

    def test_parse_failed_logon_event(self) -> None:
        xml = textwrap.dedent("""\
            <Events>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" />
                <EventID>4625</EventID>
                <Level>0</Level>
                <TimeCreated SystemTime="2024-01-05T14:23:01.000Z" />
                <Computer>WORKSTATION01</Computer>
              </System>
              <EventData>
                <Data Name="TargetUserName">admin</Data>
                <Data Name="IpAddress">192.168.1.50</Data>
              </EventData>
            </Event>
            </Events>
        """)
        entries = self.parser.parse_xml_string(xml)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata["event_id"] == 4625
        assert entry.metadata["TargetUserName"] == "admin"
        assert entry.metadata["IpAddress"] == "192.168.1.50"
        assert entry.hostname == "WORKSTATION01"
        assert entry.severity == Severity.WARNING  # 4625 elevated

    def test_parse_successful_logon_event(self) -> None:
        xml = textwrap.dedent("""\
            <Events>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" />
                <EventID>4624</EventID>
                <Level>0</Level>
                <TimeCreated SystemTime="2024-01-05T10:00:00.000Z" />
                <Computer>DC01</Computer>
              </System>
              <EventData>
                <Data Name="TargetUserName">jdoe</Data>
                <Data Name="IpAddress">10.0.0.5</Data>
                <Data Name="LogonType">10</Data>
              </EventData>
            </Event>
            </Events>
        """)
        entries = self.parser.parse_xml_string(xml)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.metadata["event_id"] == 4624
        assert "Successful Logon" in entry.message

    def test_parse_multiple_events(self) -> None:
        xml = textwrap.dedent("""\
            <Events>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="Provider1" />
                <EventID>4624</EventID>
                <Level>4</Level>
                <TimeCreated SystemTime="2024-01-05T10:00:00.000Z" />
                <Computer>HOST1</Computer>
              </System>
              <EventData />
            </Event>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="Provider2" />
                <EventID>4625</EventID>
                <Level>0</Level>
                <TimeCreated SystemTime="2024-01-05T10:01:00.000Z" />
                <Computer>HOST2</Computer>
              </System>
              <EventData />
            </Event>
            </Events>
        """)
        entries = self.parser.parse_xml_string(xml)
        assert len(entries) == 2

    def test_parse_invalid_xml(self) -> None:
        entries = self.parser.parse_xml_string("not xml at all")
        assert entries == []

    def test_parse_file(self) -> None:
        xml_content = textwrap.dedent("""\
            <Events>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="TestProvider" />
                <EventID>1000</EventID>
                <Level>4</Level>
                <TimeCreated SystemTime="2024-06-15T08:30:00.000Z" />
                <Computer>TESTPC</Computer>
              </System>
              <EventData />
            </Event>
            </Events>
        """)
        fd, path = tempfile.mkstemp(suffix=".xml")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(xml_content)
            entries = self.parser.parse_file(path)
            assert len(entries) == 1
            assert entries[0].hostname == "TESTPC"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Factory function tests
# ---------------------------------------------------------------------------

class TestGetParser:
    """Tests for the get_parser factory function."""

    def test_get_syslog_parser(self) -> None:
        parser = get_parser("syslog")
        assert isinstance(parser, SyslogParser)

    def test_get_authlog_parser(self) -> None:
        parser = get_parser("authlog")
        assert isinstance(parser, AuthLogParser)

    def test_get_apache_parser(self) -> None:
        parser = get_parser("apache")
        assert isinstance(parser, ApacheParser)

    def test_get_windows_parser(self) -> None:
        parser = get_parser("windows")
        assert isinstance(parser, WindowsEventParser)

    def test_get_unknown_parser_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown log format"):
            get_parser("unknown_format")
