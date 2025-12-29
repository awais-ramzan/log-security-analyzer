"""
Report generator module.
Creates security analysis reports.
"""

from datetime import datetime


def generate_report(log_file, total_entries, failed_logins_count, ip_failures, brute_force_ips, time_window_attacks={}, time_range=None):
    """
    Generate a security analysis report.
    
    Args:
        log_file: Path to analyzed log file
        total_entries: Total number of log entries
        failed_logins_count: Number of failed login attempts
        ip_failures: Dictionary of IP failures
        brute_force_ips: Dictionary of brute force IPs
        time_window_attacks: Dictionary of time-window based attacks
        time_range: Tuple of (start_time, end_time) or None
        
    Returns:
        Formatted report string
    """
    report_lines = []
    
    report_lines.append("=" * 60)
    report_lines.append("Log Security Analysis Report")
    report_lines.append("=" * 60)
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"Log File: {log_file}")
    report_lines.append(f"Total Entries Analyzed: {total_entries}")
    
    if time_range and time_range[0] and time_range[1]:
        report_lines.append(f"Time Range: {time_range[0]} - {time_range[1]}")
    
    report_lines.append("")
    
    # Security Summary
    report_lines.append("=== Security Summary ===")
    report_lines.append(f"Failed Login Attempts: {failed_logins_count}")
    report_lines.append(f"Potential Brute Force Attacks: {len(brute_force_ips)}")
    if time_window_attacks:
        # Get window minutes from first attack (all should have same window)
        window_mins = list(time_window_attacks.values())[0].get('window_minutes', 5) if time_window_attacks else 5
        report_lines.append(f"Time-Window Attacks ({window_mins} min): {len(time_window_attacks)}")
    report_lines.append("")
    
    # Failed Logins by IP
    if ip_failures:
        report_lines.append("=== Failed Logins by IP ===")
        for ip, count in sorted(ip_failures.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"  {ip}: {count} failed attempts")
        report_lines.append("")
    
    # Time-Window Attacks (more sophisticated)
    if time_window_attacks:
        report_lines.append("=== 🚨 TIME-WINDOW BRUTE FORCE ATTACKS ===")
        for ip, details in sorted(time_window_attacks.items(), key=lambda x: x[1]['count'], reverse=True):
            report_lines.append(f"  ⚠️  IP: {ip}")
            report_lines.append(f"     Failed Attempts: {details['count']} in {details['window_minutes']} minutes")
            report_lines.append(f"     Window Start: {details['window_start']}")
        report_lines.append("")
    
    # Brute Force Alerts (simple threshold)
    if brute_force_ips:
        report_lines.append("=== ⚠️  BRUTE FORCE ATTACKS (Threshold) ===")
        for ip, count in sorted(brute_force_ips.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"  🚨 IP: {ip}")
            report_lines.append(f"     Failed Attempts: {count}")
        report_lines.append("")
    
    if not brute_force_ips and not time_window_attacks:
        report_lines.append("=== Security Status ===")
        report_lines.append("✅ No brute force attacks detected")
        report_lines.append("")
    
    report_lines.append("=" * 60)
    
    return "\n".join(report_lines)


def save_report(report, output_file):
    """
    Save report to file.
    
    Args:
        report: Report string
        output_file: Path to output file
    """
    import os
    
    # Create directory if needed
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

