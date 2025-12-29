# Log Security Analyzer

A Python tool for analyzing log files and detecting security threats. It identifies brute force attacks, suspicious login patterns, and potential security incidents by analyzing authentication logs and access patterns.

## 🎯 Overview

This tool helps security teams quickly identify threats in log files. Instead of manually scanning through thousands of log entries, it automatically detects patterns like brute force attacks, multiple username attempts, and suspicious access patterns. It supports common log formats like SSH authentication logs and Apache access logs.

## ✨ Features

- **Brute Force Detection** - Identifies rapid login attempts using two methods:
  - Simple threshold: Flags IPs with many total failures
  - Time-window: Detects bursts of attacks within short time periods
  
- **Multiple Username Detection** - Spots when an IP tries different usernames, which often indicates reconnaissance

- **Failed Login Analysis** - Tracks authentication failures and groups them by IP address

- **Flexible Configuration** - Adjust detection thresholds and keywords via JSON config file

- **Multi-format Support** - Works with SSH logs, Apache logs, and other common formats

- **Detailed Reports** - Generates security reports with alerts, statistics, and time ranges

## 💡 Why This Tool?

Manually analyzing log files for security threats is time-consuming and error-prone. This tool automates the process, helping security teams quickly identify potential attacks without having to scan through thousands of log entries manually.

## 📋 Requirements

- Python 3.x
- No external dependencies (uses Python standard library only)

## 🚀 Installation

1. Clone this repository:
```bash
git clone https://github.com/awais-ramzan/log-security-analyzer.git
cd log-security-analyzer
```

2. No additional installation required - all dependencies are part of Python standard library.

## 💻 Usage

### Quick Start

Analyze a log file:
```bash
python analyzer.py --log-file sample_logs/ssh_auth.log
```

### Get Help

See all available options and examples:
```bash
python analyzer.py --help
```

### Examples

**Analyze SSH authentication logs:**
```bash
python analyzer.py --log-file sample_logs/ssh_auth.log
```

**Analyze Apache access logs:**
```bash
python analyzer.py --log-file sample_logs/apache_access.log
```

**Save report to file:**
```bash
python analyzer.py --log-file sample_logs/ssh_auth.log --output reports/security_report.txt
```
The `reports/` directory will be created automatically if it doesn't exist.

**Use custom configuration:**
```bash
python analyzer.py --log-file logs/app.log --config my_config.json
```

### Command Line Options

- `--log-file`, `-f`: Path to log file to analyze (required)
- `--output`, `-o`: Save report to file instead of displaying on console
- `--config`, `-c`: Path to configuration file (defaults to `config.json`)
- `--help`, `-h`: Show help message with examples

## ⚙️ Configuration

The analyzer uses `config.json` for customizable detection settings:

```json
{
  "detection": {
    "brute_force_threshold": 3,
    "time_window_threshold": 5,
    "time_window_minutes": 5,
    "multiple_username_threshold": 3
  },
  "failed_login_keywords": [
    "failed password",
    "invalid user",
    "authentication failure",
    "401",
    "403",
    "unauthorized"
  ]
}
```

### Configuration Options

- **`brute_force_threshold`**: Minimum total failed attempts to flag as brute force (default: 3)
- **`time_window_threshold`**: Minimum failures within time window to flag (default: 5)
- **`time_window_minutes`**: Duration of time window in minutes (default: 5)
- **`multiple_username_threshold`**: Minimum unique usernames to flag (default: 3)
- **`failed_login_keywords`**: Keywords to identify failed login attempts

## 📊 Example Output

```
============================================================
Log Security Analysis Report
============================================================
Generated: 2025-12-29 21:59:13
Log File: sample_logs/ssh_auth.log
Total Entries Analyzed: 19
Time Range: 2025-01-15 10:30:45 - 2025-01-15 12:00:00

=== Security Summary ===
Failed Login Attempts: 16
Potential Brute Force Attacks: 2
Time-Window Attacks (5 min): 2
Multiple Username Attempts: 1

=== Failed Logins by IP ===
  192.168.1.100: 10 failed attempts
  192.168.1.50: 5 failed attempts

=== ⚠️  MULTIPLE USERNAME ATTEMPTS ===
  🔍 IP: 192.168.1.100
     Unique Usernames Attempted: 7
     Usernames: admin, administrator, guest, root, test, ubuntu, user

=== 🚨 TIME-WINDOW BRUTE FORCE ATTACKS ===
  ⚠️  IP: 192.168.1.100
     Failed Attempts: 9 in 5 minutes
     Window Start: 2025-01-15 10:30:45

=== ⚠️  BRUTE FORCE ATTACKS (Threshold) ===
  🚨 IP: 192.168.1.100
     Failed Attempts: 10
============================================================
```

## 📁 Project Structure

```
log-security-analyzer/
├── analyzer.py              # Main entry point
├── config.py                # Configuration management
├── log_parser.py            # Log file parsing
├── security_detector.py     # Security detection logic
├── report_generator.py      # Report generation
├── config.json              # Configuration file
├── README.md                # This file
└── sample_logs/             # Sample log files for testing
    ├── ssh_auth.log         # SSH authentication log sample
    └── apache_access.log    # Apache access log sample
```

## 🔍 How Detection Works

The tool uses three main detection methods:

**Simple Threshold Detection** - Counts all failed attempts from an IP. Flags IPs that exceed the configured threshold (default: 3). This catches slow, persistent attacks.

**Time-Window Detection** - More sophisticated. It only flags attacks when failures happen close together within a configurable time window (default: 5 failures within 5 minutes). This distinguishes real attacks from legitimate user mistakes.

**Multiple Username Detection** - Flags IPs that try different usernames (configurable threshold, default: 3). If someone tries multiple different usernames like "root", "admin", "user", etc., that's a red flag for reconnaissance or brute force attempts.

## 🛠️ Built With

- Python 3.x
- Regular expressions for log parsing
- JSON for configuration
- Datetime for time-based analysis

## 📝 Supported Log Formats

The tool automatically detects log formats, but works best with:

- SSH authentication logs (like `/var/log/auth.log`)
- Apache/Nginx access logs
- Generic log formats with timestamps and IP addresses

## 🤝 Contributing

Feel free to open issues or submit pull requests if you have suggestions for improvements.

## 📄 License

This project is open source and available for educational use.

## 📚 Learning Resources

This project applies concepts from the [Google Cybersecurity Professional Certificate](https://www.coursera.org/professional-certificates/google-cybersecurity), particularly:
- **Course 2: Play It Safe** - SIEM tools and security monitoring
- **Course 6: Automate Cybersecurity Tasks with Python** - Python-based log parsing and automation techniques
- **Course 7: Sound the Alarm** - Log analysis and incident detection
---