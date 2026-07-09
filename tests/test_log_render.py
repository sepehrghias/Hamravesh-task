import gzip
import tempfile
import unittest
from pathlib import Path

from log_reader import open_log_file


class LogReaderTests(unittest.TestCase):
    def test_reads_gzip_file_as_text(self) -> None:
        content = "first line\nsecond line\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "access.log.gz"

            with gzip.open(
                path,
                mode="wt",
                encoding="utf-8",
            ) as gzip_file:
                gzip_file.write(content)

            with open_log_file(path) as log_file:
                result = log_file.read()

        self.assertEqual(result, content)


if __name__ == "__main__":
    unittest.main()