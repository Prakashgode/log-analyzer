#!/usr/bin/env python3
"""quick syslog parser experiment"""

import re
from datetime import datetime

# RFC 3164: "Mon DD HH:MM:SS hostname program[pid]: message"
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[\w\-\.\/]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s+"
    r"(?P<message>.+)$"
)

def parse_line(line):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    # no year in syslog, just assume current year for now
    ts = datetime.strptime(d["timestamp"], "%b %d %H:%M:%S")
    ts = ts.replace(year=datetime.now().year)
    return {
        "timestamp": ts,
        "hostname": d["hostname"],
        "program": d["program"],
        "pid": int(d["pid"]) if d["pid"] else None,
        "message": d["message"],
    }

if __name__ == "__main__":
    # test with a sample line
    test = "Jan  5 14:23:01 webserver01 sshd[12345]: Accepted publickey for user1 from 10.0.0.1 port 22 ssh2"
    result = parse_line(test)
    if result:
        print(f"parsed: {result['program']}[{result['pid']}] on {result['hostname']}")
        print(f"  msg: {result['message']}")
    else:
        print("failed to parse")
