"""base parser class - all format parsers will inherit from this"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, List

class Severity(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class LogEntry:
    timestamp: datetime
    source: str
    hostname: str
    message: str
    severity: Severity
    raw: str
    program: Optional[str] = None
    pid: Optional[int] = None
    metadata: dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class BaseParser(ABC):
    source_type: str = "unknown"
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        pass
    
    def parse_file(self, filepath: str) -> List[LogEntry]:
        entries = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                entry = self.parse_line(line)
                if entry:
                    entries.append(entry)
        return entries

# will move syslog, authlog, apache, windows parsers to use this
