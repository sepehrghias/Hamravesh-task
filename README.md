# Access Log Analyzer

A command-line tool for analyzing web server access logs.

The analyzer processes the input file line by line and generates a readable report containing request statistics, traffic distribution, and detected anomalies without loading the entire log file into memory.

## Requirements

- Python 3.10+
- No third-party dependencies

Only the Python standard library is used.

## Run

Run the analyzer by passing the log file path:

```bash
python main.py access.log
```

To change the number of top endpoints displayed:

```bash
python main.py access.log --top 5
```

Gzip-compressed log files are also supported:

```bash
python main.py access.log.gz
```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Features

- Total valid request count
- Malformed line count
- Unique IP count
- Top requested endpoints
- HTTP 4xx/5xx error rate
- Request distribution by hour
- Suspicious failed login detection
- 5xx error spike detection
- Direct `.gz` file support
- Processing time and throughput reporting

## Design Decisions

### Streaming Processing

The log file is processed line by line instead of being loaded entirely into memory.

Each line is parsed, used to update aggregated statistics, and then discarded. The analyzer only stores the state required for the final report, such as unique IPs, counters, and time buckets.

This keeps memory usage dependent on aggregated values rather than the total number of log lines.

### Parsing and Malformed Lines

A compiled regular expression is used to parse the expected Combined Log Format.

The parser returns a `LogEntry` for valid lines and `None` for malformed lines. Invalid records are counted and skipped, so a broken log line does not stop processing the rest of the file.

### Counting Data

`Counter` is used for values with dynamic keys where frequency counting is required, such as endpoints and failed logins per IP.

Hourly request counts are stored in a fixed-size list of 24 elements because the possible hour values are known in advance.

Endpoints are counted exactly as they appear in the access log. Dynamic route normalization is not performed because the application's routing information is not available.

### Suspicious Login Detection

The analyzer counts `401` responses on `/login` for each IP address.

An IP with at least 100 failed login responses is reported as suspicious. This threshold is a heuristic signal and does not necessarily prove malicious activity.

### 5xx Spike Detection

Requests are grouped into five-minute time buckets. Each bucket stores its total request count and number of 5xx responses.

The median 5xx error rate is used as a baseline because it is less affected by anomalies than the mean.

A bucket is reported as anomalous when:

- It contains at least 100 requests
- Its 5xx rate is at least 10%
- Its 5xx rate is at least three times the median baseline

Each anomalous five-minute interval is reported separately.

## Challenge Faced

One challenge was detecting 5xx error spikes without hard-coding a specific time range or relying on a fixed error rate that only works for the provided sample.

I solved this by dividing requests into five-minute buckets and calculating a baseline from the median 5xx rate of active buckets. The detector then compares each bucket against both a relative threshold and a minimum absolute error rate.

This approach detects unusual periods based on the log's normal behavior while avoiding misleading high rates from very low-traffic intervals.