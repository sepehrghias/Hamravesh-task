import argparse
from pathlib import Path
from time import perf_counter

from analyzer import LogAnalyzer
from parser import parse_line
from reporter import print_report
from log_reader import open_log_file


def positive_int(value: str) -> int:
    number = int(value)

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "value must be greater than zero"
        )

    return number


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze a web server access log.",
    )

    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the access log file",
    )

    parser.add_argument(
        "--top",
        type=positive_int,
        default=10,
        help="Number of top endpoints to display",
    )

    return parser.parse_args()


def analyze_file(path: Path) -> LogAnalyzer:
    analyzer = LogAnalyzer()

    with open_log_file(path) as log_file:
        for line in log_file:
            entry = parse_line(line)

            if entry is None:
                analyzer.record_malformed()
                continue

            analyzer.process(entry)

    return analyzer


def main() -> None:
    args = parse_arguments()

    started_at = perf_counter()

    try:
        analyzer = analyze_file(args.log_file)
    except OSError as error:
        raise SystemExit(
            f"Error reading '{args.log_file}': {error}"
        ) from error

    elapsed_seconds = perf_counter() - started_at

    print_report(
        analyzer=analyzer,
        top_n=args.top,
        elapsed_seconds=elapsed_seconds,
    )


if __name__ == "__main__":
    main()