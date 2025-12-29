#!/usr/bin/env python3
"""
Log Security Analyzer - Main script
"""

import argparse
from log_parser import read_log_file, get_time_range
from security_detector import detect_failed_logins, count_failed_logins_by_ip, detect_brute_force_attacks, detect_brute_force_time_window, detect_multiple_username_attempts
from report_generator import generate_report, save_report
from config import Config


def main():
    parser = argparse.ArgumentParser(
        description='Log Security Analyzer - Detect security threats in log files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze SSH log and display results
  python analyzer.py --log-file sample_logs/ssh_auth.log
  
  # Analyze Apache log and save report
  python analyzer.py --log-file sample_logs/apache_access.log --output report.txt
  
  # Use custom configuration
  python analyzer.py --log-file logs/app.log --config my_config.json

Supported Log Formats:
  - SSH authentication logs (/var/log/auth.log format)
  - Apache/Nginx access logs
  - Generic log formats (auto-detected)

Detection Features:
  - Failed login attempts
  - Brute force attacks (simple threshold)
  - Time-window brute force attacks
  - Multiple username attempts
        """
    )
    parser.add_argument('--log-file', '-f', required=True,
                       metavar='FILE',
                       help='Path to log file to analyze (required)')
    parser.add_argument('--output', '-o',
                       metavar='FILE',
                       help='Save report to file instead of displaying on console')
    parser.add_argument('--config', '-c',
                       metavar='FILE',
                       help='Path to configuration file (default: config.json)')
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config(args.config if args.config else "config.json")
    
    # Read log file
    if args.output:
        print(f"Analyzing: {args.log_file}...")
    log_lines = read_log_file(args.log_file)
    
    if not log_lines:
        print("No log entries found.")
        return
    
    # Analyze the content of the log file
    failed_logins = detect_failed_logins(log_lines, config)
    ip_failures = count_failed_logins_by_ip(log_lines, config)
    brute_force_ips = detect_brute_force_attacks(log_lines, config)
    time_window_attacks = detect_brute_force_time_window(log_lines, config)
    multiple_username_ips = detect_multiple_username_attempts(log_lines, config)
    time_range = get_time_range(log_lines)
    
    # Generate report of the analysis
    report = generate_report(
        log_file=args.log_file,
        total_entries=len(log_lines),
        failed_logins_count=len(failed_logins),
        ip_failures=ip_failures,
        brute_force_ips=brute_force_ips,
        time_window_attacks=time_window_attacks if time_window_attacks else {},
        multiple_username_ips=multiple_username_ips if multiple_username_ips else {},
        time_range=time_range
    )
    
    # Save or display report of the analysis
    if args.output:
        save_report(report, args.output)
        print(f"✅ Report saved to: {args.output}")
    else:
        print(report)


if __name__ == '__main__':
    main()

