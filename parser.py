import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"[^"]*" "[^"]*"$'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    response_size: int


def parse_line(line: str) -> Optional[LogEntry]:
    match = LOG_PATTERN.match(line.strip())

    if match is None:
        return None

    try:
        size = (
            0
            if match.group("size") == "-"
            else int(match.group("size"))
        )

        return LogEntry(
            ip=match.group("ip"),
            timestamp=datetime.strptime(
                match.group("timestamp"),
                TIMESTAMP_FORMAT,
            ),
            method=match.group("method"),
            path=match.group("path"),
            protocol=match.group("protocol"),
            status=int(match.group("status")),
            response_size=size,
        )

    except (ValueError, OverflowError):
        return None