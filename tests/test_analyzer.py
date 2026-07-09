import unittest
from datetime import datetime, timezone

from analyzer import LogAnalyzer
from parser import LogEntry


class LogAnalyzerTests(unittest.TestCase):
    def create_entry(
            self,
            ip: str = "1.1.1.1",
            path: str = "/",
            status: int = 200,
            hour: int = 10,
            minute: int = 0,
    ) -> LogEntry:
        return LogEntry(
            ip=ip,
            timestamp=datetime(
                2026,
                6,
                1,
                hour,
                minute,
                tzinfo=timezone.utc,
            ),
            method="GET",
            path=path,
            protocol="HTTP/1.1",
            status=status,
            response_size=100,
        )

    def test_counts_requests(self) -> None:
        analyzer = LogAnalyzer()

        analyzer.process(
            self.create_entry(
                "1.1.1.1",
                "/",
                200,
                10,
            )
        )

        analyzer.process(
            self.create_entry(
                "2.2.2.2",
                "/products",
                404,
                11,
            )
        )

        self.assertEqual(
            analyzer.total_requests,
            2,
        )

    def test_counts_unique_ips(self) -> None:
        analyzer = LogAnalyzer()

        analyzer.process(
            self.create_entry(
                "1.1.1.1",
                "/",
                200,
                10,
            )
        )

        analyzer.process(
            self.create_entry(
                "1.1.1.1",
                "/products",
                200,
                11,
            )
        )

        self.assertEqual(
            len(analyzer.unique_ips),
            1,
        )

    def test_calculates_error_rate(self) -> None:
        analyzer = LogAnalyzer()

        analyzer.process(
            self.create_entry(
                "1.1.1.1",
                "/",
                200,
                10,
            )
        )

        analyzer.process(
            self.create_entry(
                "1.1.1.1",
                "/login",
                401,
                10,
            )
        )

        self.assertEqual(
            analyzer.error_rate,
            50.0,
        )

    def test_counts_requests_by_hour(self) -> None:
        analyzer = LogAnalyzer()

        analyzer.process(
            self.create_entry(
                "1.1.1.1",
                "/",
                200,
                10,
            )
        )

        analyzer.process(
            self.create_entry(
                "2.2.2.2",
                "/",
                200,
                10,
            )
        )

        self.assertEqual(
            analyzer.hourly_counts[10],
            2,
        )

    def test_detects_5xx_spike_intervals(self) -> None:
        analyzer = LogAnalyzer()

        for minute in [0, 5, 10]:
            for _ in range(98):
                analyzer.process(
                    self.create_entry(
                        status=200,
                        hour=4,
                        minute=minute,
                    )
                )

            for _ in range(2):
                analyzer.process(
                    self.create_entry(
                        status=500,
                        hour=4,
                        minute=minute,
                    )
                )

        for minute in [15, 20]:
            for _ in range(50):
                analyzer.process(
                    self.create_entry(
                        status=200,
                        hour=4,
                        minute=minute,
                    )
                )

            for _ in range(50):
                analyzer.process(
                    self.create_entry(
                        status=500,
                        hour=4,
                        minute=minute,
                    )
                )

        spikes = analyzer.detect_5xx_spikes()

        self.assertEqual(len(spikes), 2)

        self.assertEqual(spikes[0].start.minute, 15)
        self.assertEqual(spikes[0].end.minute, 20)
        self.assertEqual(spikes[0].error_rate, 50.0)

        self.assertEqual(spikes[1].start.minute, 20)
        self.assertEqual(spikes[1].end.minute, 25)
        self.assertEqual(spikes[1].error_rate, 50.0)

    def test_detects_suspicious_login_ip(self) -> None:
        analyzer = LogAnalyzer()

        for _ in range(3):
            analyzer.process(
                self.create_entry(
                    ip="10.0.0.1",
                    path="/login",
                    status=401,
                )
            )

        analyzer.process(
            self.create_entry(
                ip="10.0.0.2",
                path="/login",
                status=401,
            )
        )

        self.assertEqual(
            analyzer.suspicious_login_ips(threshold=3),
            [("10.0.0.1", 3)],
        )


if __name__ == "__main__":
    unittest.main()