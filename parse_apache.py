#!/usr/bin/env python3
"""apache/nginx combined log format parser

format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "ref" "ua"

the timestamp format is different from syslog which is annoying
had to handle the timezone offset separately
"""

import re
from datetime import datetime

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

def parse_apache_line(line):
    m = APACHE_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    # timestamp format: 10/Oct/2000:13:55:36 -0700
    # this was a pain to get right
    try:
        ts = datetime.strptime(d["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        ts = ts.replace(tzinfo=None)  # strip tz for now
    except ValueError:
        # try without timezone
        ts_str = d["timestamp"].rsplit(" ", 1)[0]
        ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
    
    return {
        "ip": d["ip"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "size": int(d["size"]) if d["size"] != "-" else 0,
        "timestamp": ts,
    }

# TODO: detect suspicious paths like /etc/passwd, ../
# TODO: flag 4xx and 5xx status codes differently
