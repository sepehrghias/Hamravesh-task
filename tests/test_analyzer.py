import unittest
from datetime import datetime, timezone

from analyzer import LogAnalyzer
from parser import LogEntry


class LogAnalyzerTests(unittest.TestCase):
    def create_entry(
        self,
        ip: str,
        path: str,
        status: int,
        hour: int,
    ) -> LogEntry:
        return LogEntry(
            ip=ip,
            timestamp=datetime(
                2026,
                6,
                1,
                hour,
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


if __name__ == "__main__":
    unittest.main()