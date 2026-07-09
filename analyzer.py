from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median

from parser import LogEntry


ERROR_BUCKET_MINUTES = 5


@dataclass
class ErrorBucket:
    total_requests: int = 0
    server_errors: int = 0

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0

        return (
            self.server_errors
            / self.total_requests
            * 100
        )


@dataclass
class ErrorSpike:
    start: datetime
    end: datetime
    error_rate: float


class LogAnalyzer:
    def __init__(self) -> None:
        self.total_requests = 0
        self.malformed_lines = 0

        self.unique_ips: set[str] = set()

        self.endpoint_counts: Counter[str] = Counter()
        self.hourly_counts: list[int] = [0] * 24

        self.error_count = 0

        self.failed_login_counts: Counter[str] = Counter()

        self.server_error_buckets: defaultdict[
            datetime,
            ErrorBucket,
        ] = defaultdict(ErrorBucket)

    def process(self, entry: LogEntry) -> None:
        self.total_requests += 1

        self.unique_ips.add(entry.ip)

        self.endpoint_counts[entry.path] += 1

        self.hourly_counts[entry.timestamp.hour] += 1

        if 400 <= entry.status < 600:
            self.error_count += 1

        if entry.path == "/login" and entry.status == 401:
            self.failed_login_counts[entry.ip] += 1

        bucket_start = entry.timestamp.replace(
            minute=(
                entry.timestamp.minute
                // ERROR_BUCKET_MINUTES
            )
            * ERROR_BUCKET_MINUTES,
            second=0,
            microsecond=0,
        )

        bucket = self.server_error_buckets[bucket_start]

        bucket.total_requests += 1

        if 500 <= entry.status < 600:
            bucket.server_errors += 1

    def record_malformed(self) -> None:
        self.malformed_lines += 1

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0

        return (
            self.error_count
            / self.total_requests
            * 100
        )

    def suspicious_login_ips(
            self,
            threshold: int = 100,
    ) -> list[tuple[str, int]]:
        suspicious_ips = [
            (ip, count)
            for ip, count in self.failed_login_counts.items()
            if count >= threshold
        ]

        return sorted(
            suspicious_ips,
            key=lambda item: item[1],
            reverse=True,
        )

    def detect_5xx_spikes(
            self,
            min_requests: int = 100,
            rate_multiplier: float = 3.0,
            min_rate: float = 10.0,
    ) -> list[ErrorSpike]:
        eligible_buckets = [
            bucket
            for bucket in self.server_error_buckets.values()
            if bucket.total_requests >= min_requests
        ]

        if not eligible_buckets:
            return []

        baseline_rate = median(
            bucket.error_rate
            for bucket in eligible_buckets
        )

        spike_threshold = max(
            min_rate,
            baseline_rate * rate_multiplier,
        )

        anomalous_buckets = [
            (start, bucket)
            for start, bucket in self.server_error_buckets.items()
            if (
                    bucket.total_requests >= min_requests
                    and bucket.error_rate >= spike_threshold
            )
        ]

        anomalous_buckets.sort(
            key=lambda item: item[0]
        )

        bucket_duration = timedelta(
            minutes=ERROR_BUCKET_MINUTES
        )

        return [
            ErrorSpike(
                start=start,
                end=start + bucket_duration,
                error_rate=bucket.error_rate,
            )
            for start, bucket in anomalous_buckets
        ]