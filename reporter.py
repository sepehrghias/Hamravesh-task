from analyzer import LogAnalyzer


BAR_WIDTH = 40


def print_report(
    analyzer: LogAnalyzer,
    top_n: int,
    elapsed_seconds: float,
) -> None:
    print()
    print("=" * 50)
    print("LOG ANALYSIS SUMMARY")
    print("=" * 50)

    print(f"Total requests  : {analyzer.total_requests:,}")
    print(f"Malformed lines : {analyzer.malformed_lines:,}")
    print(f"Unique IPs      : {len(analyzer.unique_ips):,}")
    print(f"Error rate      : {analyzer.error_rate:.2f}%")

    print_top_endpoints(analyzer, top_n)
    print_hourly_distribution(analyzer)
    print_suspicious_activity(analyzer)
    print_5xx_spikes(analyzer)

    print("\nPERFORMANCE REPORT")
    print("-" * 50)

    total_lines = (
            analyzer.total_requests
            + analyzer.malformed_lines
    )

    processing_speed = (
        total_lines / elapsed_seconds
        if elapsed_seconds > 0
        else 0.0
    )

    print(f"Processing time : {elapsed_seconds:.2f} s")

    print(
        f"Processing speed: "
        f"{processing_speed:,.0f} lines/s"
    )


def print_top_endpoints(
    analyzer: LogAnalyzer,
    top_n: int,
) -> None:
    print()
    print(f"TOP {top_n} ENDPOINTS")
    print("-" * 50)

    for path, count in analyzer.endpoint_counts.most_common(top_n):
        print(f"{path:<35} {count:>12,}")


def print_hourly_distribution(
    analyzer: LogAnalyzer,
) -> None:
    print()
    print("REQUESTS BY HOUR")
    print("-" * 70)

    max_count = max(
        analyzer.hourly_counts.values(),
        default=0,
    )

    for hour in range(24):
        count = analyzer.hourly_counts[hour]

        if max_count == 0:
            bar_length = 0
        else:
            bar_length = round(
                count / max_count * BAR_WIDTH
            )

        bar = "#" * bar_length

        print(
            f"{hour:02d}:00 | "
            f"{bar:<{BAR_WIDTH}} "
            f"{count:>10,}"
        )

def print_suspicious_activity(
    analyzer: LogAnalyzer,
) -> None:
    suspicious_ips = analyzer.suspicious_login_ips()

    print()
    print("SUSPICIOUS LOGIN ACTIVITY")
    print("-" * 50)

    if not suspicious_ips:
        print("No suspicious login activity detected.")
        return

    for ip, count in suspicious_ips:
        print(
            f"{ip:<20} "
            f"{count:>10,} failed logins"
        )


def print_5xx_spikes(
    analyzer: LogAnalyzer,
) -> None:
    spikes = analyzer.detect_5xx_spikes()

    print()
    print("5XX ERROR SPIKES")
    print("-" * 50)

    if not spikes:
        print("No 5xx error spikes detected.")
        return

    for spike in spikes:
        print(
            f"{spike.start:%Y-%m-%d %H:%M} -> "
            f"{spike.end:%H:%M} "
            f"| error rate: {spike.error_rate:.2f}%"
        )