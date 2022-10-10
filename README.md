# Log Analyzer

Parse log files, detect anomalies, and generate comprehensive summary reports.

## Features

- Auto-detects log format (Apache, Nginx, Syslog, generic timestamp)
- HTTP status code distribution
- Top IPs and request paths
- Hourly traffic analysis
- Anomaly detection (high error rates, IP bursts, server errors)
- JSON export
- Built-in sample log generator for testing

## Usage

```bash
# Generate a sample log and analyze it
python main.py --generate-sample sample.log

# Analyze existing log files
python main.py /var/log/access.log

# Analyze multiple files
python main.py access.log error.log

# Export report as JSON
python main.py access.log --export-json report.json
```

## No external dependencies required!
