"""
Simple log parser module.
Reads log files and extracts basic information.
"""


def read_log_file(file_path):
    """
    Read a log file and return list of lines.
    
    Args:
        file_path: Path to the log file
        
    Returns:
        List of log lines
    """
    log_lines = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    log_lines.append(line)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []
    
    return log_lines


def extract_ip_addresses(log_lines):
    """
    Extract IP addresses from log lines.
    
    Args:
        log_lines: List of log line strings
        
    Returns:
        List of IP addresses found
    """
    import re
    
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ip_addresses = []
    
    for line in log_lines:
        matches = re.findall(ip_pattern, line)
        ip_addresses.extend(matches)
    
    return ip_addresses


def extract_timestamps(log_lines):
    """
    Extract timestamps from log lines.
    Supports common formats like SSH and Apache.
    
    Args:
        log_lines: List of log line strings
        
    Returns:
        List of timestamp strings found (or None if not found)
    """
    import re
    from datetime import datetime
    
    timestamps = []
    
    for line in log_lines:
        timestamp = None
        
        # Trying to parse SSH format: "Jan 15 10:30:45"
        ssh_pattern = r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})'
        ssh_match = re.search(ssh_pattern, line)
        if ssh_match:
            month_str, day, hour, minute, second = ssh_match.groups()
            month_map = {
                'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
            }
            try:
                current_year = datetime.now().year
                month = month_map.get(month_str, 1)
                timestamp = f"{current_year}-{month:02d}-{int(day):02d} {hour}:{minute}:{second}"
            except:
                pass
        
        # Trying to parse Apache format: "[15/Jan/2025:10:30:45 +0000]"
        if not timestamp:
            apache_pattern = r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})'
            apache_match = re.search(apache_pattern, line)
            if apache_match:
                day, month_str, year, hour, minute, second = apache_match.groups()
                month_map = {
                    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                }
                try:
                    month = month_map.get(month_str, 1)
                    timestamp = f"{year}-{month:02d}-{int(day):02d} {hour}:{minute}:{second}"
                except:
                    pass
        
        timestamps.append(timestamp)
    
    return timestamps


def get_time_range(log_lines):
    """
    Get the time range covered by log entries.
    
    Args:
        log_lines: List of log line strings
        
    Returns:
        Tuple of (start_time, end_time) as strings, or (None, None) if not found
    """
    timestamps = extract_timestamps(log_lines)
    valid_timestamps = [ts for ts in timestamps if ts]
    
    if not valid_timestamps:
        return (None, None)
    
    valid_timestamps.sort()
    return (valid_timestamps[0], valid_timestamps[-1])

