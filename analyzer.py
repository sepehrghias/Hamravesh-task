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


@dataclass(frozen=True)
class ErrorSpike:
    start: datetime
    end: datetime
    peak_rate: float


class LogAnalyzer:
    def __init__(self) -> None:
        self.total_requests = 0
        self.malformed_lines = 0

        self.unique_ips: set[str] = set()

        self.endpoint_counts: Counter[str] = Counter()
        self.hourly_counts: Counter[int] = Counter()

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
        return [
            (ip, count)
            for ip, count
            in self.failed_login_counts.most_common()
            if count >= threshold
        ]

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
            for start, bucket
            in sorted(self.server_error_buckets.items())
            if bucket.total_requests >= min_requests
            and bucket.error_rate >= spike_threshold
        ]

        if not anomalous_buckets:
            return []

        bucket_duration = timedelta(
            minutes=ERROR_BUCKET_MINUTES
        )

        spikes: list[ErrorSpike] = []

        current_start, first_bucket = anomalous_buckets[0]

        current_last_start = current_start
        peak_rate = first_bucket.error_rate

        for start, bucket in anomalous_buckets[1:]:
            if start == current_last_start + bucket_duration:
                current_last_start = start

                peak_rate = max(
                    peak_rate,
                    bucket.error_rate,
                )

                continue

            spikes.append(
                ErrorSpike(
                    start=current_start,
                    end=current_last_start + bucket_duration,
                    peak_rate=peak_rate,
                )
            )

            current_start = start
            current_last_start = start
            peak_rate = bucket.error_rate

        spikes.append(
            ErrorSpike(
                start=current_start,
                end=current_last_start + bucket_duration,
                peak_rate=peak_rate,
            )
        )

        return spikes