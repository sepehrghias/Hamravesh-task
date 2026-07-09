import unittest

from parser import parse_line


class ParseLineTests(unittest.TestCase):
    def test_parses_valid_log_line(self) -> None:
        line = (
            '203.0.113.42 - - '
            '[01/Jun/2026:09:14:22 +0000] '
            '"GET /products/1877 HTTP/1.1" '
            '200 5324 "-" "Mozilla/5.0"'
        )

        entry = parse_line(line)

        self.assertIsNotNone(entry)

        assert entry is not None

        self.assertEqual(entry.ip, "203.0.113.42")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/products/1877")
        self.assertEqual(entry.protocol, "HTTP/1.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.response_size, 5324)
        self.assertEqual(entry.timestamp.hour, 9)

    def test_rejects_malformed_line(self) -> None:
        entry = parse_line(
            "garbage-144 <<< malformed line"
        )

        self.assertIsNone(entry)

    def test_dash_response_size_becomes_zero(self) -> None:
        line = (
            '203.0.113.42 - - '
            '[01/Jun/2026:09:14:22 +0000] '
            '"GET / HTTP/1.1" '
            '200 - "-" "Mozilla/5.0"'
        )

        entry = parse_line(line)

        self.assertIsNotNone(entry)

        assert entry is not None

        self.assertEqual(entry.response_size, 0)


if __name__ == "__main__":
    unittest.main()