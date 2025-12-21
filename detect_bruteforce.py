"""brute force detection - count failed logins per IP in a sliding window"""

from collections import defaultdict
from datetime import timedelta

def detect_brute_force(entries, threshold=5, window_seconds=300):
    """
    look for IPs with too many failed logins in a time window
    
    basic sliding window approach:
    - group failed logins by source IP
    - sort by time
    - slide a window and count
    """
    alerts = []
    
    # group failed logins by IP
    failed_by_ip = defaultdict(list)
    for entry in entries:
        if entry.get("event_type") == "failed_login" and entry.get("source_ip"):
            failed_by_ip[entry["source_ip"]].append(entry)
    
    for ip, failures in failed_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])
        
        # sliding window
        start = 0
        for end in range(len(failures)):
            while start < end and (failures[end]["timestamp"] - failures[start]["timestamp"]).total_seconds() > window_seconds:
                start += 1
            
            count = end - start + 1
            if count >= threshold:
                alerts.append({
                    "type": "brute_force",
                    "ip": ip,
                    "count": count,
                    "window": window_seconds,
                    "timestamp": failures[end]["timestamp"],
                })
                break  # don't spam alerts for same IP
    
    return alerts

# TODO: severity levels based on attempt count
# TODO: track targeted usernames
