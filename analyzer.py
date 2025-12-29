#!/usr/bin/env python3
"""
Log Security Analyzer - Main script
"""

import argparse
from log_parser import read_log_file, get_time_range
from security_detector import detect_failed_logins, count_failed_logins_by_ip, detect_brute_force_attacks, detect_brute_force_time_window
from report_generator import generate_report, save_report
from config import Config


def main():
    parser = argparse.ArgumentParser(description='Log Security Analyzer')
    parser.add_argument('--log-file', '-f', required=True,
                       help='Path to log file to analyze')
    parser.add_argument('--output', '-o',
                       help='Save report to file (optional)')
    parser.add_argument('--config', '-c',
                       help='Path to custom configuration file (default: config.json)')
    
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
    time_range = get_time_range(log_lines)
    
    # Generate report of the analysis
    report = generate_report(
        log_file=args.log_file,
        total_entries=len(log_lines),
        failed_logins_count=len(failed_logins),
        ip_failures=ip_failures,
        brute_force_ips=brute_force_ips,
        time_window_attacks=time_window_attacks if time_window_attacks else {},
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

