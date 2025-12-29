"""
Security detector module.
Detects security threats in log entries.
"""


def detect_failed_logins(log_lines, config=None):
    """
    Detect failed login attempts in log lines.
    
    Args:
        log_lines: List of log line strings
        config: Config object (optional, uses defaults if not provided)
        
    Returns:
        List of failed login entries
    """
    if config:
        failed_login_keywords = config.get_failed_login_keywords()
    else:
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


def count_failed_logins_by_ip(log_lines, config=None):
    """
    Count failed login attempts grouped by IP address.
    
    Args:
        log_lines: List of log line strings
        config: Config object (optional)
        
    Returns:
        Dictionary mapping IP addresses to failure counts
    """
    import re
    
    failed_logins = detect_failed_logins(log_lines, config)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ip_counts = {}
    
    for line in failed_logins:
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    return ip_counts


def detect_brute_force_attacks(log_lines, config=None, threshold=None):
    """
    Detect potential brute force attacks.
    IPs with multiple failed login attempts above threshold.
    
    Args:
        log_lines: List of log line strings
        config: Config object (optional)
        threshold: Minimum number of failed attempts to flag (uses config if not provided)
        
    Returns:
        Dictionary of suspicious IPs with their failure counts
    """
    if threshold is None:
        threshold = config.get_brute_force_threshold() if config else 5
    
    ip_failures = count_failed_logins_by_ip(log_lines, config)
    brute_force_ips = {}
    
    for ip, count in ip_failures.items():
        if count >= threshold:
            brute_force_ips[ip] = count
    
    return brute_force_ips


def detect_brute_force_time_window(log_lines, config=None, threshold=None, window_minutes=None):
    """
    Detect brute force attacks within a time window.
    More sophisticated: detects attacks where multiple failures occur within X minutes.
    
    Args:
        log_lines: List of log line strings
        config: Config object (optional)
        threshold: Minimum number of failed attempts in time window (uses config if not provided)
        window_minutes: Time window in minutes (uses config if not provided)
        
    Returns:
        Dictionary of suspicious IPs with attack details
    """
    import re
    from datetime import datetime, timedelta
    from log_parser import extract_timestamps
    
    if threshold is None:
        threshold = config.get_time_window_threshold() if config else 10
    if window_minutes is None:
        window_minutes = config.get_time_window_minutes() if config else 5
    
    # Get failed logins with their timestamps
    failed_logins = detect_failed_logins(log_lines, config)
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


def extract_usernames_from_line(line):
    """
    Extract username from a log line.
    Tries common patterns found in SSH and web server logs.
    
    Args:
        line: Log line string
        
    Returns:
        Username string or None if not found
    """
    import re
    
    patterns = [
        r'for\s+(\w+)\s+from',            # "for root from"
        r'user\s+(\w+)',                  # "user admin"
        r'username[:\s]+(\w+)',           # "username: user"
        r'login[:\s]+(\w+)',              # "login: user"
        r'Invalid user\s+(\w+)',          # "Invalid user test"
        r'Failed password for\s+(\w+)',   # "Failed password for root"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            username = match.group(1).lower()
            # Filter out common non-username words
            if username not in ['invalid', 'failed', 'authentication', 'password', 'from']:
                return username
    
    return None


def detect_multiple_username_attempts(log_lines, config=None, threshold=3):
    """
    Detect when same IP tries multiple different usernames.
    This indicates reconnaissance or brute force attempts.
    
    Args:
        log_lines: List of log line strings
        config: Config object (optional)
        threshold: Minimum number of unique usernames to flag (uses config if not provided)
        
    Returns:
        Dictionary of suspicious IPs with username details
    """
    import re
    from collections import defaultdict
    
    if threshold is None:
        threshold = config.get_multiple_username_threshold() if config else 3
    
    # Extract IPs and usernames from failed logins
    failed_logins = detect_failed_logins(log_lines, config)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    
    # Group usernames by IP
    ip_usernames = defaultdict(set)
    
    for line in failed_logins:
        ip_match = re.search(ip_pattern, line)
        username = extract_usernames_from_line(line)
        
        if ip_match and username:
            ip = ip_match.group(1)
            ip_usernames[ip].add(username)
    
    # Find IPs with multiple username attempts
    suspicious_ips = {}
    
    for ip, usernames in ip_usernames.items():
        if len(usernames) >= threshold:
            suspicious_ips[ip] = {
                'unique_usernames': len(usernames),
                'usernames': sorted(list(usernames))
            }
    
    return suspicious_ips

