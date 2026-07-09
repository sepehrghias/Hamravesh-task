from analyzer import LogAnalyzer
from parser import parse_line


def analyze_file(path: str) -> LogAnalyzer:
    analyzer = LogAnalyzer()

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:

        for line in log_file:
            entry = parse_line(line)

            if entry is None:
                analyzer.record_malformed()
                continue

            analyzer.process(entry)

    return analyzer


if __name__ == "__main__":
    analyzer = analyze_file("access.log")

    print(f"Total requests: {analyzer.total_requests:,}")
    print(f"Malformed lines: {analyzer.malformed_lines:,}")
    print(f"Unique IPs: {len(analyzer.unique_ips):,}")
    print(f"Error rate: {analyzer.error_rate:.2f}%")

    print("Top 10 endpoints:")

    for path, count in analyzer.endpoint_counts.most_common(10):
        print(f"  {path}: {count:,}")