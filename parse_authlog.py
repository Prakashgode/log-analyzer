#!/usr/bin/env python3
"""auth.log parser - extracts failed/successful logins"""

import re
from datetime import datetime

AUTH_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[\w\-\.\/]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s+"
    r"(?P<message>.+)$"
)

FAILED_SSH = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+)\s+"
    r"from (?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

ACCEPTED_SSH = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+)\s+"
    r"from (?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

def classify(message):
    """figure out what kind of auth event this is"""
    m = FAILED_SSH.search(message)
    if m:
        return "failed_login", m.groupdict()
    m = ACCEPTED_SSH.search(message)
    if m:
        return "successful_login", m.groupdict()
    return "other", {}

# TODO: add sudo command parsing
# TODO: add su session parsing
