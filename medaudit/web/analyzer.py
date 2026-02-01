"""
Enhanced PCAP Analyzer for Web UI
Returns structured data for display in the web interface.
"""

from typing import Dict, List, Any, Optional
from scapy.all import rdpcap, TCP, UDP, Raw
from scapy.layers.inet import IP
from datetime import datetime

# Lazy load the PII analyzer to avoid slow startup
_pii_analyzer = None


def get_pii_analyzer():
    """Get or create the PII analyzer (lazy loading)."""
    global _pii_analyzer
    if _pii_analyzer is None:
        try:
            from ..analysis.pii.pii_check import create_analyzer
            _pii_analyzer = create_analyzer()
        except Exception as e:
            print(f"Warning: Could not initialize PII analyzer: {e}")
            _pii_analyzer = None
    return _pii_analyzer


def parse_hl7_message(raw_message: str) -> Dict[str, Any]:
    """
    Parse an HL7 v2.x message into structured segments and fields.
    
    Args:
        raw_message: The raw HL7 message string
        
    Returns:
        Dictionary with parsed segments and metadata
    """
    # Remove MLLP framing if present
    message = raw_message.strip()
    if message.startswith('\x0b'):
        message = message[1:]
    if '\x1c' in message:
        message = message.split('\x1c')[0]
    
    # Split into segments (HL7 uses \r as segment delimiter)
    segment_delimiters = ['\r\n', '\r', '\n']
    segments_raw = None
    for delim in segment_delimiters:
        if delim in message:
            segments_raw = message.split(delim)
            break
    
    if not segments_raw:
        segments_raw = [message]
    
    parsed_segments = []
    message_type = None
    message_control_id = None
    sending_app = None
    receiving_app = None
    message_datetime = None
    patient_info = {}
    
    for segment_str in segments_raw:
        segment_str = segment_str.strip()
        if not segment_str:
            continue
            
        # Parse segment
        fields = segment_str.split('|')
        segment_name = fields[0] if fields else ""
        
        segment_data = {
            "name": segment_name,
            "raw": segment_str,
            "fields": []
        }
        
        # Parse fields based on segment type
        if segment_name == "MSH":
            # MSH segment has special handling - field 1 is the field separator
            segment_data["fields"] = parse_msh_segment(fields)
            # Extract key info
            if len(fields) > 2:
                sending_app = fields[2]
            if len(fields) > 4:
                receiving_app = fields[4]
            if len(fields) > 6:
                message_datetime = fields[6]
            if len(fields) > 8:
                message_type = fields[8]
            if len(fields) > 9:
                message_control_id = fields[9]
                
        elif segment_name == "PID":
            segment_data["fields"] = parse_pid_segment(fields)
            patient_info = extract_patient_info(fields)
            
        elif segment_name == "PV1":
            segment_data["fields"] = parse_pv1_segment(fields)
            
        elif segment_name == "OBR":
            segment_data["fields"] = parse_obr_segment(fields)
            
        elif segment_name == "OBX":
            segment_data["fields"] = parse_obx_segment(fields)
            
        elif segment_name == "ORC":
            segment_data["fields"] = parse_orc_segment(fields)
            
        elif segment_name == "MSA":
            segment_data["fields"] = parse_msa_segment(fields)
            
        else:
            # Generic field parsing
            segment_data["fields"] = [
                {"index": i, "value": f, "name": f"Field {i}"}
                for i, f in enumerate(fields[1:], start=1)
                if f
            ]
        
        parsed_segments.append(segment_data)
    
    return {
        "message_type": message_type,
        "message_control_id": message_control_id,
        "sending_application": sending_app,
        "receiving_application": receiving_app,
        "message_datetime": message_datetime,
        "patient_info": patient_info if patient_info else None,
        "segments": parsed_segments,
        "segment_count": len(parsed_segments),
        "raw_message": raw_message[:1000]  # Truncate for display
    }


def parse_msh_segment(fields: List[str]) -> List[Dict]:
    """Parse MSH (Message Header) segment fields."""
    field_names = [
        "Segment ID", "Encoding Characters", "Sending Application",
        "Sending Facility", "Receiving Application", "Receiving Facility",
        "Date/Time of Message", "Security", "Message Type",
        "Message Control ID", "Processing ID", "Version ID",
        "Sequence Number", "Continuation Pointer", "Accept Acknowledgment Type",
        "Application Acknowledgment Type", "Country Code", "Character Set",
        "Principal Language of Message"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field
            })
    return parsed


def parse_pid_segment(fields: List[str]) -> List[Dict]:
    """Parse PID (Patient Identification) segment fields."""
    field_names = [
        "Segment ID", "Set ID", "Patient ID (External)",
        "Patient ID (Internal)", "Alternate Patient ID", "Patient Name",
        "Mother's Maiden Name", "Date/Time of Birth", "Sex",
        "Patient Alias", "Race", "Patient Address",
        "County Code", "Phone Number - Home", "Phone Number - Business",
        "Primary Language", "Marital Status", "Religion",
        "Patient Account Number", "SSN Number", "Driver's License",
        "Mother's Identifier", "Ethnic Group", "Birth Place",
        "Multiple Birth Indicator", "Birth Order", "Citizenship",
        "Veteran Status", "Nationality", "Patient Death Date/Time",
        "Patient Death Indicator"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field,
                "is_pii": i in [2, 3, 4, 5, 6, 7, 11, 13, 14, 18, 19, 20]  # PII fields
            })
    return parsed


def parse_pv1_segment(fields: List[str]) -> List[Dict]:
    """Parse PV1 (Patient Visit) segment fields."""
    field_names = [
        "Segment ID", "Set ID", "Patient Class",
        "Assigned Patient Location", "Admission Type", "Preadmit Number",
        "Prior Patient Location", "Attending Doctor", "Referring Doctor",
        "Consulting Doctor", "Hospital Service", "Temporary Location",
        "Preadmit Test Indicator", "Re-admission Indicator", "Admit Source",
        "Ambulatory Status", "VIP Indicator", "Admitting Doctor",
        "Patient Type", "Visit Number", "Financial Class"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field
            })
    return parsed


def parse_obr_segment(fields: List[str]) -> List[Dict]:
    """Parse OBR (Observation Request) segment fields."""
    field_names = [
        "Segment ID", "Set ID", "Placer Order Number",
        "Filler Order Number", "Universal Service ID", "Priority",
        "Requested Date/Time", "Observation Date/Time", "Observation End Date/Time",
        "Collection Volume", "Collector Identifier", "Specimen Action Code",
        "Danger Code", "Relevant Clinical Info", "Specimen Received Date/Time",
        "Specimen Source", "Ordering Provider", "Order Callback Phone Number"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field
            })
    return parsed


def parse_obx_segment(fields: List[str]) -> List[Dict]:
    """Parse OBX (Observation/Result) segment fields."""
    field_names = [
        "Segment ID", "Set ID", "Value Type",
        "Observation Identifier", "Observation Sub-ID", "Observation Value",
        "Units", "Reference Range", "Abnormal Flags",
        "Probability", "Nature of Abnormal Test", "Observation Result Status",
        "Date Last Observed Normal", "User Defined Access Checks", "Date/Time of Observation",
        "Producer's ID", "Responsible Observer", "Observation Method"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field
            })
    return parsed


def parse_orc_segment(fields: List[str]) -> List[Dict]:
    """Parse ORC (Common Order) segment fields."""
    field_names = [
        "Segment ID", "Order Control", "Placer Order Number",
        "Filler Order Number", "Placer Group Number", "Order Status",
        "Response Flag", "Quantity/Timing", "Parent Order",
        "Date/Time of Transaction", "Entered By", "Verified By",
        "Ordering Provider", "Enterer's Location", "Call Back Phone Number"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field
            })
    return parsed


def parse_msa_segment(fields: List[str]) -> List[Dict]:
    """Parse MSA (Message Acknowledgment) segment fields."""
    field_names = [
        "Segment ID", "Acknowledgment Code", "Message Control ID",
        "Text Message", "Expected Sequence Number", "Delayed Acknowledgment Type",
        "Error Condition"
    ]
    
    parsed = []
    for i, field in enumerate(fields):
        if i < len(field_names) and field:
            parsed.append({
                "index": i,
                "name": field_names[i],
                "value": field
            })
    return parsed


def extract_patient_info(pid_fields: List[str]) -> Dict:
    """Extract patient information from PID segment."""
    info = {}
    
    if len(pid_fields) > 5 and pid_fields[5]:
        # Parse name (format: LAST^FIRST^MIDDLE^SUFFIX^PREFIX)
        name_parts = pid_fields[5].split('^')
        info["name"] = {
            "last": name_parts[0] if len(name_parts) > 0 else "",
            "first": name_parts[1] if len(name_parts) > 1 else "",
            "middle": name_parts[2] if len(name_parts) > 2 else "",
            "full": " ".join(filter(None, [
                name_parts[1] if len(name_parts) > 1 else "",
                name_parts[2] if len(name_parts) > 2 else "",
                name_parts[0] if len(name_parts) > 0 else ""
            ]))
        }
    
    if len(pid_fields) > 3 and pid_fields[3]:
        info["patient_id"] = pid_fields[3]
    
    if len(pid_fields) > 7 and pid_fields[7]:
        info["date_of_birth"] = pid_fields[7]
    
    if len(pid_fields) > 8 and pid_fields[8]:
        info["sex"] = pid_fields[8]
    
    if len(pid_fields) > 11 and pid_fields[11]:
        info["address"] = pid_fields[11]
    
    if len(pid_fields) > 13 and pid_fields[13]:
        info["phone_home"] = pid_fields[13]
    
    if len(pid_fields) > 19 and pid_fields[19]:
        info["ssn"] = pid_fields[19]
    
    return info


def detect_pii_in_text(text: str, analyzer=None) -> List[Dict]:
    """
    Detect PII in text using Presidio analyzer.
    
    Args:
        text: Text to analyze
        analyzer: Presidio analyzer instance (optional)
        
    Returns:
        List of detected PII with entity type and value
    """
    pii_found = []
    
    if analyzer is None:
        analyzer = get_pii_analyzer()
    
    if analyzer:
        try:
            results = analyzer.analyze(text=text, language='en')
            for result in results:
                pii_found.append({
                    "entity_type": result.entity_type,
                    "value": text[result.start:result.end],
                    "score": round(result.score, 2),
                    "start": result.start,
                    "end": result.end
                })
        except Exception as e:
            print(f"PII analysis error: {e}")
    
    return pii_found


def is_likely_encrypted(payload: bytes) -> bool:
    """Check if payload appears to be encrypted based on entropy."""
    if len(payload) < 10:
        return False
    
    # Calculate byte entropy
    unique_bytes = len(set(payload))
    entropy = unique_bytes / len(payload)
    
    # High entropy suggests encryption
    return entropy > 0.8


def extract_hl7_from_payload(payload: bytes) -> Optional[str]:
    """
    Extract HL7 message from raw payload.
    Handles both plain HL7 and MLLP-wrapped messages.
    """
    try:
        text = payload.decode('utf-8', errors='ignore')
        
        # Check for MLLP framing (0x0B ... 0x1C 0x0D)
        if '\x0b' in text:
            start = text.find('\x0b') + 1
            end = text.find('\x1c')
            if end > start:
                text = text[start:end]
        
        # Check if it's an HL7 message
        if 'MSH|' in text:
            # Find the start of MSH
            msh_start = text.find('MSH|')
            return text[msh_start:]
        
        return None
    except:
        return None


def analyze_pcap_detailed(pcap_file: str) -> Dict[str, Any]:
    """
    Analyze PCAP file and return detailed structured results.
    
    Args:
        pcap_file: Path to the PCAP file
        
    Returns:
        Dictionary with analysis results
    """
    # Initialize PII analyzer
    analyzer = get_pii_analyzer()
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to read PCAP file: {str(e)}"
        }
    
    # Analysis counters
    total_packets = len(packets)
    encrypted_packets = 0
    unencrypted_packets = 0
    
    # Collected data
    hl7_messages = []
    all_pii = []
    connections = {}  # Track unique connections
    
    for i, packet in enumerate(packets):
        if IP not in packet:
            continue
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        is_encrypted = False
        protocol = "unknown"
        src_port = None
        dst_port = None
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check for common SSL/TLS ports
            ssl_ports = [443, 993, 995, 465, 587, 8443]
            if dst_port in ssl_ports or src_port in ssl_ports:
                is_encrypted = True
            
            # Check payload entropy if present
            if Raw in packet and not is_encrypted:
                payload = packet[Raw].load
                if is_likely_encrypted(payload):
                    is_encrypted = True
                    
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Track connection
        conn_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        if conn_key not in connections:
            connections[conn_key] = {
                "source_ip": src_ip,
                "source_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "protocol": protocol,
                "packet_count": 0,
                "encrypted": is_encrypted
            }
        connections[conn_key]["packet_count"] += 1
        
        if is_encrypted:
            encrypted_packets += 1
        elif Raw in packet:
            unencrypted_packets += 1
            payload = packet[Raw].load
            
            # Try to extract HL7 message
            hl7_text = extract_hl7_from_payload(payload)
            if hl7_text:
                parsed = parse_hl7_message(hl7_text)
                parsed["packet_index"] = i
                parsed["source"] = f"{src_ip}:{src_port}"
                parsed["destination"] = f"{dst_ip}:{dst_port}"
                hl7_messages.append(parsed)
                
                # Detect PII in the HL7 message
                pii_results = detect_pii_in_text(hl7_text, analyzer)
                for pii in pii_results:
                    pii["source_message"] = len(hl7_messages)
                    pii["packet_index"] = i
                    all_pii.append(pii)
    
    # Calculate encryption status
    total_analyzed = encrypted_packets + unencrypted_packets
    if total_analyzed == 0:
        encryption_status = "unknown"
        encryption_percentage = 0
    elif encrypted_packets == total_analyzed:
        encryption_status = "fully_encrypted"
        encryption_percentage = 100
    elif encrypted_packets == 0:
        encryption_status = "unencrypted"
        encryption_percentage = 0
    else:
        encryption_status = "partially_encrypted"
        encryption_percentage = round((encrypted_packets / total_analyzed) * 100, 1)
    
    # Build summary
    return {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_packets": total_packets,
            "analyzed_packets": total_analyzed,
            "encrypted_packets": encrypted_packets,
            "unencrypted_packets": unencrypted_packets,
            "encryption_status": encryption_status,
            "encryption_percentage": encryption_percentage,
            "hl7_message_count": len(hl7_messages),
            "pii_count": len(all_pii),
            "unique_connections": len(connections)
        },
        "encryption": {
            "status": encryption_status,
            "percentage": encryption_percentage,
            "encrypted_count": encrypted_packets,
            "unencrypted_count": unencrypted_packets,
            "risk_level": "high" if encryption_status == "unencrypted" else 
                         ("medium" if encryption_status == "partially_encrypted" else "low"),
            "reason": (
                f"All {total_analyzed} analyzed packets are unencrypted - PHI exposure risk!" 
                if encryption_status == "unencrypted" else
                f"{encrypted_packets}/{total_analyzed} packets encrypted ({encryption_percentage}%)"
                if encryption_status == "partially_encrypted" else
                f"All {total_analyzed} analyzed packets appear encrypted"
                if encryption_status == "fully_encrypted" else
                "No analyzable traffic found"
            )
        },
        "hl7_messages": hl7_messages,
        "pii_findings": all_pii,
        "connections": list(connections.values())
    }
