from collections import Counter

from parser import LogEntry


class LogAnalyzer:
    def __init__(self) -> None:
        self.total_requests = 0
        self.malformed_lines = 0

        self.unique_ips: set[str] = set()

        self.endpoint_counts: Counter[str] = Counter()
        self.hourly_counts: Counter[int] = Counter()

        self.error_count = 0

    def process(self, entry: LogEntry) -> None:
        self.total_requests += 1

        self.unique_ips.add(entry.ip)

        self.endpoint_counts[entry.path] += 1

        self.hourly_counts[entry.timestamp.hour] += 1

        if 400 <= entry.status < 600:
            self.error_count += 1

    def record_malformed(self) -> None:
        self.malformed_lines += 1

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0

        return self.error_count / self.total_requests * 100