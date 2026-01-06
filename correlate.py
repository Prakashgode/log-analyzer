"""event correlation - link related events across log sources

idea: group events by source IP and look for multi-stage patterns
like recon -> brute force -> successful login -> priv escalation

this is a rough prototype, will need to clean up
"""

from collections import defaultdict
from datetime import timedelta

# attack stages (simplified cyber kill chain)
STAGES = {
    "reconnaissance": 1,
    "failed_login": 2,
    "successful_login": 3,
    "sudo_command": 4,
    "su_session": 4,
    # TODO: add lateral movement, persistence, exfiltration
}

def correlate_by_ip(events, window_hours=1):
    """group events by source IP and detect multi-stage chains"""
    ip_events = defaultdict(list)
    
    for event in events:
        ip = event.get("source_ip")
        if ip:
            ip_events[ip].append(event)
    
    chains = []
    for ip, ip_evts in ip_events.items():
        ip_evts.sort(key=lambda e: e["timestamp"])
        
        # check if we see multiple stages from same IP
        stages_seen = set()
        for evt in ip_evts:
            event_type = evt.get("event_type", "")
            if event_type in STAGES:
                stages_seen.add(event_type)
        
        if len(stages_seen) >= 2:
            chains.append({
                "source_ip": ip,
                "stages": sorted(stages_seen, key=lambda s: STAGES.get(s, 99)),
                "event_count": len(ip_evts),
                "first_seen": ip_evts[0]["timestamp"],
                "last_seen": ip_evts[-1]["timestamp"],
            })
    
    return chains
