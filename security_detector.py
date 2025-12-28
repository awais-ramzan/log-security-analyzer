"""
Security detector module.
Detects security threats in log entries.
"""


def detect_failed_logins(log_lines):
    """
    Detect failed login attempts in log lines.
    
    Args:
        log_lines: List of log line strings
        
    Returns:
        List of failed login entries
    """
    failed_login_keywords = [
        'failed password',
        'invalid user',
        'authentication failure',
        '401',
        '403',
        'unauthorized'
    ]
    
    failed_logins = []
    
    for line in log_lines:
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in failed_login_keywords):
            failed_logins.append(line)
    
    return failed_logins


def count_failed_logins_by_ip(log_lines):
    """
    Count failed login attempts grouped by IP address.
    
    Args:
        log_lines: List of log line strings
        
    Returns:
        Dictionary mapping IP addresses to failure counts
    """
    import re
    
    failed_logins = detect_failed_logins(log_lines)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ip_counts = {}
    
    for line in failed_logins:
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    return ip_counts


def detect_brute_force_attacks(log_lines, threshold=5):
    """
    Detect potential brute force attacks.
    IPs with multiple failed login attempts above threshold.
    
    Args:
        log_lines: List of log line strings
        threshold: Minimum number of failed attempts to flag (default: 5)
        
    Returns:
        Dictionary of suspicious IPs with their failure counts
    """
    ip_failures = count_failed_logins_by_ip(log_lines)
    brute_force_ips = {}
    
    for ip, count in ip_failures.items():
        if count >= threshold:
            brute_force_ips[ip] = count
    
    return brute_force_ips


def detect_brute_force_time_window(log_lines, threshold=10, window_minutes=5):
    """
    Detect brute force attacks within a time window.
    More sophisticated: detects attacks where multiple failures occur within X minutes.
    
    Args:
        log_lines: List of log line strings
        threshold: Minimum number of failed attempts in time window (default: 10)
        window_minutes: Time window in minutes (default: 5)
        
    Returns:
        Dictionary of suspicious IPs with attack details
    """
    import re
    from datetime import datetime, timedelta
    from log_parser import extract_timestamps
    
    # Get failed logins with their timestamps
    failed_logins = detect_failed_logins(log_lines)
    timestamps = extract_timestamps(log_lines)
    
    # Pair failed logins with timestamps
    failed_with_time = []
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    
    for i, line in enumerate(log_lines):
        if line in failed_logins:
            timestamp_str = timestamps[i] if i < len(timestamps) and timestamps[i] else None
            ip_match = re.search(ip_pattern, line)
            if ip_match and timestamp_str:
                try:
                    # Parse timestamp string to datetime
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    ip = ip_match.group(1)
                    failed_with_time.append((ip, timestamp, line))
                except:
                    pass
    
    # Group by IP and check time windows
    brute_force_attacks = {}
    
    # Group failures by IP
    from collections import defaultdict
    ip_failures = defaultdict(list)
    for ip, timestamp, line in failed_with_time:
        ip_failures[ip].append((timestamp, line))
    
    # Check each IP for time-window violations
    for ip, failures in ip_failures.items():
        if len(failures) < threshold:
            continue
        
        # Sort by timestamp
        failures.sort(key=lambda x: x[0])
        
        # Check for threshold violations within time windows
        for i in range(len(failures)):
            window_start = failures[i][0]
            window_end = window_start + timedelta(minutes=window_minutes)
            
            # Count failures in this window
            failures_in_window = [
                f for f in failures
                if window_start <= f[0] <= window_end
            ]
            
            if len(failures_in_window) >= threshold:
                brute_force_attacks[ip] = {
                    'count': len(failures_in_window),
                    'window_start': window_start.strftime("%Y-%m-%d %H:%M:%S"),
                    'window_minutes': window_minutes
                }
                break  # Only report once per IP
    
    return brute_force_attacks

