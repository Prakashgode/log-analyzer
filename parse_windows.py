#!/usr/bin/env python3
"""windows event log xml parser - experimental

parsing the xml format from wevtutil qe exports
this is way more complex than syslog/apache

relevant security event IDs:
  4624 - successful logon
  4625 - failed logon  
  4672 - special privileges assigned
  4688 - process creation
"""

import xml.etree.ElementTree as ET
from datetime import datetime

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

# security events we care about
SECURITY_EVENTS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
}

def parse_event_xml(xml_string):
    """parse a single <Event> element"""
    try:
        event = ET.fromstring(xml_string)
    except ET.ParseError:
        return None
    
    system = event.find("evt:System", NS)
    if system is None:
        system = event.find("System")
    if system is None:
        return None
    
    # get event id
    eid_elem = system.find("evt:EventID", NS) or system.find("EventID")
    event_id = int(eid_elem.text) if eid_elem is not None and eid_elem.text else 0
    
    # get timestamp
    tc = system.find("evt:TimeCreated", NS) or system.find("TimeCreated")
    if tc is None:
        return None
    time_str = tc.get("SystemTime", "")
    
    # get computer name
    comp = system.find("evt:Computer", NS) or system.find("Computer")
    hostname = comp.text if comp is not None else "unknown"
    
    return {
        "event_id": event_id,
        "hostname": hostname,
        "timestamp_raw": time_str,
        "description": SECURITY_EVENTS.get(event_id, f"Event {event_id}"),
    }

# TODO: extract EventData fields (username, IP, etc)
# TODO: handle level mapping to severity
