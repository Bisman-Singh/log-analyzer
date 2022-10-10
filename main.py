#!/usr/bin/env python3
"""Parse log files, detect anomalies, and generate summary reports."""

import re
import argparse
import json
import sys
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path

LOG_PATTERNS = {
    "apache": re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\S+)'
    ),
    "nginx": re.compile(
        r'(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
    ),
    "syslog": re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<host>\S+) (?P<service>\S+?)(\[(?P<pid>\d+)\])?: (?P<message>.*)'
    ),
    "generic": re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<message>.*)'
    ),
}

ANOMALY_THRESHOLDS = {
    "error_rate": 0.1,
    "requests_per_ip_burst": 100,
    "large_response_size": 10_000_000,
}


class LogAnalyzer:
    def __init__(self):
        self.entries = []
        self.errors = []
        self.ip_counter = Counter()
        self.status_counter = Counter()
        self.path_counter = Counter()
        self.method_counter = Counter()
        self.hourly_counter = Counter()
        self.level_counter = Counter()
        self.service_counter = Counter()
        self.anomalies = []
        self.log_format = None

    def detect_format(self, line: str) -> str | None:
        for fmt, pattern in LOG_PATTERNS.items():
            if pattern.match(line):
                return fmt
        return None

    def parse_file(self, filepath: Path):
        print(f"  Parsing: {filepath.name}")
        line_count = 0
        parse_errors = 0

        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                line_count += 1

                if self.log_format is None:
                    self.log_format = self.detect_format(line)
                    if self.log_format:
                        print(f"  Detected format: {self.log_format}")

                if self.log_format is None:
                    self.log_format = "generic"

                pattern = LOG_PATTERNS[self.log_format]
                match = pattern.match(line)
                if not match:
                    parse_errors += 1
                    continue

                data = match.groupdict()
                self.entries.append(data)
                self._process_entry(data)

        print(f"  Lines: {line_count} | Parsed: {len(self.entries)} | Errors: {parse_errors}")

    def _process_entry(self, data: dict):
        if "ip" in data:
            self.ip_counter[data["ip"]] += 1
        if "status" in data:
            self.status_counter[data["status"]] += 1
            if data["status"].startswith(("4", "5")):
                self.errors.append(data)
        if "path" in data:
            self.path_counter[data["path"]] += 1
        if "method" in data:
            self.method_counter[data["method"]] += 1
        if "level" in data:
            self.level_counter[data["level"].upper()] += 1
        if "service" in data:
            self.service_counter[data["service"]] += 1

        timestamp = data.get("timestamp", "")
        hour = self._extract_hour(timestamp)
        if hour:
            self.hourly_counter[hour] += 1

    def _extract_hour(self, timestamp: str) -> str | None:
        for fmt in ["%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
            try:
                dt = datetime.strptime(timestamp.strip(), fmt)
                return dt.strftime("%Y-%m-%d %H:00")
            except ValueError:
                continue
        return None

    def detect_anomalies(self):
        total = len(self.entries)
        if total == 0:
            return

        error_count = len(self.errors)
        error_rate = error_count / total
        if error_rate > ANOMALY_THRESHOLDS["error_rate"]:
            self.anomalies.append({
                "type": "HIGH_ERROR_RATE",
                "detail": f"Error rate {error_rate:.1%} exceeds threshold {ANOMALY_THRESHOLDS['error_rate']:.0%}",
                "severity": "HIGH",
            })

        for ip, count in self.ip_counter.most_common(10):
            if count > ANOMALY_THRESHOLDS["requests_per_ip_burst"]:
                self.anomalies.append({
                    "type": "IP_BURST",
                    "detail": f"IP {ip} made {count} requests (threshold: {ANOMALY_THRESHOLDS['requests_per_ip_burst']})",
                    "severity": "MEDIUM",
                })

        for status, count in self.status_counter.items():
            if status in ("500", "502", "503") and count > 10:
                self.anomalies.append({
                    "type": "SERVER_ERRORS",
                    "detail": f"HTTP {status} occurred {count} times",
                    "severity": "HIGH",
                })

    def generate_report(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("                    LOG ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"  Format:       {self.log_format}")
        lines.append(f"  Total entries: {len(self.entries)}")
        lines.append(f"  Total errors:  {len(self.errors)}")
        lines.append(f"  Unique IPs:    {len(self.ip_counter)}")
        lines.append("")

        if self.status_counter:
            lines.append("--- HTTP Status Codes ---")
            for status, count in sorted(self.status_counter.items()):
                bar = "█" * min(count, 50)
                lines.append(f"  {status}: {count:>6} {bar}")
            lines.append("")

        if self.method_counter:
            lines.append("--- HTTP Methods ---")
            for method, count in self.method_counter.most_common():
                lines.append(f"  {method:>7}: {count}")
            lines.append("")

        if self.level_counter:
            lines.append("--- Log Levels ---")
            for level, count in self.level_counter.most_common():
                lines.append(f"  {level:>8}: {count}")
            lines.append("")

        if self.ip_counter:
            lines.append("--- Top 10 IPs ---")
            for ip, count in self.ip_counter.most_common(10):
                lines.append(f"  {ip:>20}: {count}")
            lines.append("")

        if self.path_counter:
            lines.append("--- Top 10 Paths ---")
            for path, count in self.path_counter.most_common(10):
                lines.append(f"  {path:>40}: {count}")
            lines.append("")

        if self.hourly_counter:
            lines.append("--- Hourly Traffic ---")
            for hour, count in sorted(self.hourly_counter.items()):
                bar = "█" * min(count // 5, 50)
                lines.append(f"  {hour}: {count:>6} {bar}")
            lines.append("")

        if self.anomalies:
            lines.append("--- ANOMALIES DETECTED ---")
            for a in self.anomalies:
                icon = "🔴" if a["severity"] == "HIGH" else "🟡"
                lines.append(f"  {icon} [{a['severity']}] {a['type']}: {a['detail']}")
            lines.append("")
        else:
            lines.append("--- No anomalies detected ---\n")

        return "\n".join(lines)

    def export_json(self, filepath: str):
        report = {
            "summary": {
                "format": self.log_format,
                "total_entries": len(self.entries),
                "total_errors": len(self.errors),
                "unique_ips": len(self.ip_counter),
            },
            "status_codes": dict(self.status_counter),
            "top_ips": dict(self.ip_counter.most_common(20)),
            "top_paths": dict(self.path_counter.most_common(20)),
            "methods": dict(self.method_counter),
            "hourly_traffic": dict(sorted(self.hourly_counter.items())),
            "anomalies": self.anomalies,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  JSON report exported to {filepath}")


def generate_sample_log(filepath: str, count: int = 500):
    """Generate a sample Apache-style log file for testing."""
    import random

    ips = [f"192.168.1.{i}" for i in range(1, 20)] + ["10.0.0.1", "172.16.0.5"]
    paths = ["/", "/api/users", "/api/posts", "/login", "/dashboard", "/static/style.css",
             "/api/search", "/health", "/admin", "/api/data"]
    methods = ["GET"] * 7 + ["POST"] * 2 + ["PUT"]
    statuses = ["200"] * 15 + ["301"] * 2 + ["404"] * 3 + ["500"] * 1

    with open(filepath, "w") as f:
        base = datetime(2025, 1, 15, 0, 0, 0)
        for i in range(count):
            ts = base.replace(hour=i * 24 // count % 24, minute=random.randint(0, 59))
            ip = random.choice(ips)
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choice(statuses)
            size = random.randint(200, 50000)
            line = f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size}\n'
            f.write(line)
    print(f"  Generated sample log: {filepath} ({count} entries)")


def main():
    parser = argparse.ArgumentParser(description="Log Analyzer - Parse, analyze, and detect anomalies")
    parser.add_argument("files", nargs="*", help="Log file(s) to analyze")
    parser.add_argument("--generate-sample", help="Generate a sample log file at this path")
    parser.add_argument("--sample-count", type=int, default=500, help="Number of sample log entries")
    parser.add_argument("--export-json", help="Export report as JSON")
    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_log(args.generate_sample, args.sample_count)
        if not args.files:
            args.files = [args.generate_sample]

    if not args.files:
        print("Usage: python main.py <logfile> [logfile2 ...]")
        print("       python main.py --generate-sample sample.log")
        sys.exit(1)

    analyzer = LogAnalyzer()
    for filepath in args.files:
        p = Path(filepath)
        if not p.exists():
            print(f"  File not found: {filepath}")
            continue
        analyzer.parse_file(p)

    analyzer.detect_anomalies()
    print(analyzer.generate_report())

    if args.export_json:
        analyzer.export_json(args.export_json)


if __name__ == "__main__":
    main()
