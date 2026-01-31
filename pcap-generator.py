#!/usr/bin/env python3
"""
Generate synthetic HL7 v2.x traffic in PCAP format
Uses raw struct operations to build packets (no scapy dependency)
"""

import struct
import socket
from datetime import datetime
import random

# MLLP framing characters
MLLP_START = b'\x0b'  # Vertical Tab (VT)
MLLP_END = b'\x1c\x0d'  # File Separator + Carriage Return

class PcapWriter:
    """Simple PCAP file writer"""
    
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        # PCAP global header
        # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
        header = struct.pack('<IHHiIII', 
            0xa1b2c3d4,  # magic number
            2,           # version major
            4,           # version minor
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            1            # network (LINKTYPE_ETHERNET)
        )
        self.file.write(header)
    
    def write_packet(self, timestamp, packet_data):
        """Write a packet with timestamp"""
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        incl_len = len(packet_data)
        orig_len = len(packet_data)
        
        # Packet header
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
        self.file.write(pkt_header)
        self.file.write(packet_data)
    
    def close(self):
        self.file.close()

def ip_to_bytes(ip_str):
    """Convert IP string to bytes"""
    return socket.inet_aton(ip_str)

def mac_to_bytes(mac_str):
    """Convert MAC string to bytes"""
    return bytes.fromhex(mac_str.replace(':', ''))

def calculate_ip_checksum(header):
    """Calculate IP header checksum"""
    if len(header) % 2:
        header += b'\x00'
    
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i+1]
    
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    return ~total & 0xFFFF

def calculate_tcp_checksum(src_ip, dst_ip, tcp_header, payload):
    """Calculate TCP checksum including pseudo-header"""
    # Pseudo header
    pseudo = src_ip + dst_ip + struct.pack('>BBH', 0, 6, len(tcp_header) + len(payload))
    
    data = pseudo + tcp_header + payload
    if len(data) % 2:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i+1]
    
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    return ~total & 0xFFFF

def create_ethernet_frame(src_mac, dst_mac, payload):
    """Create Ethernet frame"""
    return dst_mac + src_mac + struct.pack('>H', 0x0800) + payload

def create_ip_packet(src_ip, dst_ip, protocol, payload):
    """Create IP packet"""
    version_ihl = (4 << 4) | 5
    dscp_ecn = 0
    total_length = 20 + len(payload)
    identification = random.randint(0, 65535)
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    
    # Header without checksum
    header = struct.pack('>BBHHHBBH',
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        0  # checksum placeholder
    ) + src_ip + dst_ip
    
    checksum = calculate_ip_checksum(header)
    
    # Rebuild with correct checksum
    header = struct.pack('>BBHHHBBH',
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum
    ) + src_ip + dst_ip
    
    return header + payload

def create_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
    """Create TCP segment"""
    data_offset = 5  # 20 bytes, no options
    reserved = 0
    
    # Flags: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10
    flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10}
    flag_byte = sum(flag_map.get(f, 0) for f in flags)
    
    window = 65535
    urgent = 0
    
    # Header without checksum
    header = struct.pack('>HHIIHHHH',
        src_port,
        dst_port,
        seq,
        ack,
        (data_offset << 12) | flag_byte,
        window,
        0,  # checksum placeholder
        urgent
    )
    
    checksum = calculate_tcp_checksum(src_ip, dst_ip, header, payload)
    
    # Rebuild with correct checksum
    header = struct.pack('>HHIIHHHH',
        src_port,
        dst_port,
        seq,
        ack,
        (data_offset << 12) | flag_byte,
        window,
        checksum,
        urgent
    )
    
    return header + payload

def create_full_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
    """Create a complete Ethernet frame with IP and TCP"""
    src_ip_bytes = ip_to_bytes(src_ip)
    dst_ip_bytes = ip_to_bytes(dst_ip)
    src_mac_bytes = mac_to_bytes(src_mac)
    dst_mac_bytes = mac_to_bytes(dst_mac)
    
    tcp = create_tcp_segment(src_ip_bytes, dst_ip_bytes, src_port, dst_port, seq, ack, flags, payload)
    ip = create_ip_packet(src_ip_bytes, dst_ip_bytes, 6, tcp)  # 6 = TCP
    eth = create_ethernet_frame(src_mac_bytes, dst_mac_bytes, ip)
    
    return eth

# HL7 Message generators
def create_hl7_adt_a01():
    """ADT^A01 - Patient Admission"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    msg_id = f"MSG{random.randint(100000, 999999)}"
    
    msg = f"""MSH|^~\\&|EPIC|HOSPITAL|LAB_SYS|LAB_FAC|{timestamp}||ADT^A01^ADT_A01|{msg_id}|P|2.5.1|||AL|NE||UNICODE UTF-8|||
EVN|A01|{timestamp}|||JSMITH^SMITH^JOHN^^^DR|||
PID|1||MRN12345^^^HOSP^MR~SSN123456789^^^SS||DOE^JOHN^MICHAEL^^^^L||19850315|M|||123 MAIN ST^^ANYTOWN^CA^90210^USA^^H||(555)123-4567^PRN^PH~(555)987-6543^WPN^PH~john.doe@email.com^NET^Internet||ENG|M|CHR|ACCT98765^^^HOSP^AN|SSN123456789|||NON-HISPANIC||||||||N||
PD1|||ANYTOWN MEDICAL GROUP^^12345|1234567890^JONES^MARY^^^DR^^^NPI||||||||N|
NK1|1|DOE^JANE^M|SPO^Spouse^HL70063|||(555)123-4568||EC|||||||||||||||||||||||||||
PV1|1|I|ICU^0101^01^HOSP^^^^ICU|||||||MED||||7|||1234567890^JONES^MARY^^^DR^^^NPI|IP||||||||||||||||||||||||||{timestamp}|||||||V|
AL1|1|DA|846^PENICILLIN^RXNORM|SV^Severe^HL70128|ANAPHYLAXIS||20200101|
AL1|2|DA|2670^CODEINE^RXNORM|MO^Moderate^HL70128|NAUSEA, VOMITING||20190515|
DG1|1||I10^ESSENTIAL HYPERTENSION^ICD10|||A|||||||||1||
DG1|2||E11.9^TYPE 2 DIABETES^ICD10|||A|||||||||2||
IN1|1|BCBS001|BCBS^BLUE CROSS BLUE SHIELD|PO BOX 12345^^INSURANCE CITY^NY^10001|||GRP12345|||||||DOE^JOHN^M|SEL|19850315|123 MAIN ST^^ANYTOWN^CA^90210|||1||||||||||||||POL456789|||||||M|||"""
    
    return msg.replace('\n', '\r'), msg_id

def create_hl7_ack(original_msg_id, msg_type="A01"):
    """ACK message"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    ack_id = f"ACK{random.randint(100000, 999999)}"
    
    msg = f"""MSH|^~\\&|LAB_SYS|LAB_FAC|EPIC|HOSPITAL|{timestamp}||ACK^{msg_type}^ACK|{ack_id}|P|2.5.1|||AL|NE|||
MSA|AA|{original_msg_id}||"""
    
    return msg.replace('\n', '\r')

def create_hl7_orm_o01():
    """ORM^O01 - General Order"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    msg_id = f"ORD{random.randint(100000, 999999)}"
    
    msg = f"""MSH|^~\\&|CPOE|HOSPITAL|LAB_SYS|LAB_FAC|{timestamp}||ORM^O01^ORM_O01|{msg_id}|P|2.5.1|||AL|NE||UNICODE UTF-8|||
PID|1||MRN12345^^^HOSP^MR||DOE^JOHN^MICHAEL^^^^L||19850315|M|||123 MAIN ST^^ANYTOWN^CA^90210|||(555)123-4567|||||||||||||||||||
PV1|1|I|ICU^0101^01||||1234567890^JONES^MARY^^^DR|||MED||||||||IP||||||||||||||||||HOSP||||||||||{timestamp}|
ORC|NW|ORD001^CPOE|ORD001^LAB||SC||^^^{timestamp}^^R||{timestamp}|JSMITH^SMITH^JOHN|ICU^0101|(555)123-9999||{timestamp}||||||HOSP|
OBR|1|ORD001^CPOE|ORD001^LAB|80053^COMPREHENSIVE METABOLIC PANEL^CPT|||{timestamp}|||||||||1234567890^JONES^MARY^^^DR||||||{timestamp}|||F||^^^{timestamp}^^R||||||||||||||||
OBR|2|ORD002^CPOE|ORD002^LAB|85025^CBC WITH DIFFERENTIAL^CPT|||{timestamp}|||||||||1234567890^JONES^MARY^^^DR||||||{timestamp}|||F||^^^{timestamp}^^R||||||||||||||||
NTE|1||STAT order - patient in ICU|
OBR|3|ORD003^CPOE|ORD003^LAB|82565^CREATININE^CPT|||{timestamp}|||||||||1234567890^JONES^MARY^^^DR||||||{timestamp}|||F||^^^{timestamp}^^R||||||||||||||||"""
    
    return msg.replace('\n', '\r'), msg_id

def create_hl7_oru_r01():
    """ORU^R01 - Observation Result (Lab Results)"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    msg_id = f"RES{random.randint(100000, 999999)}"
    
    msg = f"""MSH|^~\\&|LAB_SYS|LAB_FAC|EPIC|HOSPITAL|{timestamp}||ORU^R01^ORU_R01|{msg_id}|P|2.5.1|||AL|NE||UNICODE UTF-8|||
PID|1||MRN12345^^^HOSP^MR||DOE^JOHN^MICHAEL^^^^L||19850315|M|||123 MAIN ST^^ANYTOWN^CA^90210|||(555)123-4567|||||||||||||||||||
PV1|1|I|ICU^0101^01||||1234567890^JONES^MARY^^^DR|||MED|||||||IP|||||||||||||||||||||||{timestamp}|
ORC|RE|ORD001^CPOE|ORD001^LAB||CM||^^^{timestamp}||{timestamp}||||{timestamp}||||||HOSP|
OBR|1|ORD001^CPOE|ORD001^LAB|80053^COMPREHENSIVE METABOLIC PANEL^CPT|||{timestamp}|||||||{timestamp}|^Blood|1234567890^JONES^MARY^^^DR||||||{timestamp}|||F|||||||||||||||
OBX|1|NM|2345-7^GLUCOSE^LN||98|mg/dL|70-100||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|2|NM|3094-0^BUN^LN||18|mg/dL|7-20||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|3|NM|2160-0^CREATININE^LN||1.1|mg/dL|0.7-1.3||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|4|NM|17861-6^CALCIUM^LN||9.5|mg/dL|8.5-10.5||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|5|NM|2951-2^SODIUM^LN||140|mEq/L|136-145||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|6|NM|2823-3^POTASSIUM^LN||4.2|mEq/L|3.5-5.0||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|7|NM|2075-0^CHLORIDE^LN||102|mEq/L|98-106||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|8|NM|1963-8^BICARBONATE^LN||24|mEq/L|22-29||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|9|NM|1742-6^ALT^LN||35|U/L|7-56||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|10|NM|1920-8^AST^LN||28|U/L|10-40||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|11|NM|6768-6^ALP^LN||75|U/L|44-147||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|12|NM|1751-7^ALBUMIN^LN||4.0|g/dL|3.5-5.0||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|13|NM|1975-2^BILIRUBIN TOTAL^LN||0.8|mg/dL|0.1-1.2||||F|||{timestamp}||LAB_TECH^TECH^LAB|
OBX|14|NM|2339-0^GLUCOSE FASTING^LN||142|mg/dL|70-100|H|||F|||{timestamp}||LAB_TECH^TECH^LAB|
NTE|1||Elevated glucose - recommend follow-up|"""
    
    return msg.replace('\n', '\r'), msg_id

def create_hl7_adt_a08():
    """ADT^A08 - Patient Update"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    msg_id = f"UPD{random.randint(100000, 999999)}"
    
    msg = f"""MSH|^~\\&|EPIC|HOSPITAL|LAB_SYS|LAB_FAC|{timestamp}||ADT^A08^ADT_A01|{msg_id}|P|2.5.1|||AL|NE||UNICODE UTF-8|||
EVN|A08|{timestamp}|||JSMITH^SMITH^JOHN^^^DR|||
PID|1||MRN12345^^^HOSP^MR||DOE^JOHN^MICHAEL^^^^L||19850315|M|||456 NEW ADDRESS^^NEWTOWN^CA^90220^USA^^H||(555)999-8888^PRN^PH||ENG|M|CHR|ACCT98765^^^HOSP^AN||||||||||||N||
PV1|1|I|ICU^0102^01^HOSP^^^^ICU|||||||MED||||7|||1234567890^JONES^MARY^^^DR^^^NPI|IP||||||||||||||||||||||||||{timestamp}|||||||V|"""
    
    return msg.replace('\n', '\r'), msg_id

def wrap_mllp(hl7_msg):
    """Wrap HL7 message in MLLP framing"""
    return MLLP_START + hl7_msg.encode('utf-8') + MLLP_END

def generate_hl7_pcap(output_file):
    """Generate PCAP with multiple HL7 message exchanges"""
    
    # Network parameters
    client_ip = "10.0.0.100"
    server_ip = "10.0.0.200"
    client_mac = "00:11:22:33:44:55"
    server_mac = "00:aa:bb:cc:dd:ee"
    client_port = 54321
    server_port = 2575  # Standard MLLP port
    
    pcap = PcapWriter(output_file)
    base_time = 1706600000.0  # Base timestamp
    seq_client = 1000000000
    seq_server = 2000000000
    
    def add_packet(is_client_to_server, flags, payload=b'', time_offset=0):
        nonlocal seq_client, seq_server
        
        if is_client_to_server:
            pkt = create_full_packet(client_mac, server_mac, client_ip, server_ip,
                                    client_port, server_port, seq_client, seq_server, flags, payload)
            if payload:
                seq_client += len(payload)
            elif 'S' in flags or 'F' in flags:
                seq_client += 1
        else:
            pkt = create_full_packet(server_mac, client_mac, server_ip, client_ip,
                                    server_port, client_port, seq_server, seq_client, flags, payload)
            if payload:
                seq_server += len(payload)
            elif 'S' in flags or 'F' in flags:
                seq_server += 1
        
        pcap.write_packet(base_time + time_offset, pkt)
    
    time_offset = 0.0
    
    # TCP 3-way handshake
    add_packet(True, 'S', b'', time_offset)
    time_offset += 0.001
    add_packet(False, 'SA', b'', time_offset)
    time_offset += 0.001
    add_packet(True, 'A', b'', time_offset)
    time_offset += 0.1
    
    # Message 1: ADT^A01 (Patient Admission)
    adt_msg, adt_id = create_hl7_adt_a01()
    adt_payload = wrap_mllp(adt_msg)
    add_packet(True, 'PA', adt_payload, time_offset)
    time_offset += 0.05
    add_packet(False, 'A', b'', time_offset)
    time_offset += 0.05
    
    # HL7 ACK response
    adt_ack = create_hl7_ack(adt_id, "A01")
    adt_ack_payload = wrap_mllp(adt_ack)
    add_packet(False, 'PA', adt_ack_payload, time_offset)
    time_offset += 0.05
    add_packet(True, 'A', b'', time_offset)
    time_offset += 1.0
    
    # Message 2: ORM^O01 (Order)
    orm_msg, orm_id = create_hl7_orm_o01()
    orm_payload = wrap_mllp(orm_msg)
    add_packet(True, 'PA', orm_payload, time_offset)
    time_offset += 0.05
    add_packet(False, 'A', b'', time_offset)
    time_offset += 0.05
    
    orm_ack = create_hl7_ack(orm_id, "O01")
    orm_ack_payload = wrap_mllp(orm_ack)
    add_packet(False, 'PA', orm_ack_payload, time_offset)
    time_offset += 0.05
    add_packet(True, 'A', b'', time_offset)
    time_offset += 2.0
    
    # Message 3: ORU^R01 (Lab Results) - from server
    oru_msg, oru_id = create_hl7_oru_r01()
    oru_payload = wrap_mllp(oru_msg)
    add_packet(False, 'PA', oru_payload, time_offset)
    time_offset += 0.05
    add_packet(True, 'A', b'', time_offset)
    time_offset += 0.05
    
    oru_ack = create_hl7_ack(oru_id, "R01")
    oru_ack_payload = wrap_mllp(oru_ack)
    add_packet(True, 'PA', oru_ack_payload, time_offset)
    time_offset += 0.05
    add_packet(False, 'A', b'', time_offset)
    time_offset += 1.5
    
    # Message 4: ADT^A08 (Patient Update)
    upd_msg, upd_id = create_hl7_adt_a08()
    upd_payload = wrap_mllp(upd_msg)
    add_packet(True, 'PA', upd_payload, time_offset)
    time_offset += 0.05
    add_packet(False, 'A', b'', time_offset)
    time_offset += 0.05
    
    upd_ack = create_hl7_ack(upd_id, "A08")
    upd_ack_payload = wrap_mllp(upd_ack)
    add_packet(False, 'PA', upd_ack_payload, time_offset)
    time_offset += 0.05
    add_packet(True, 'A', b'', time_offset)
    time_offset += 0.5
    
    # TCP connection teardown
    add_packet(True, 'FA', b'', time_offset)
    time_offset += 0.01
    add_packet(False, 'FA', b'', time_offset)
    time_offset += 0.01
    add_packet(True, 'A', b'', time_offset)
    
    pcap.close()
    
    print(f"Generated {output_file}")
    print(f"\nHL7 Messages included:")
    print("  - ADT^A01 (Patient Admission) with ACK")
    print("  - ORM^O01 (Lab Order) with ACK")  
    print("  - ORU^R01 (Lab Results with 14 OBX segments) with ACK")
    print("  - ADT^A08 (Patient Update) with ACK")
    print(f"\nNetwork: {client_ip}:{client_port} <-> {server_ip}:{server_port} (MLLP)")
    print("\nOpen with: wireshark hl7_sample_traffic.pcap")
    print("Filter: tcp.port == 2575")

if __name__ == "__main__":
    generate_hl7_pcap("hl7_sample_traffic1.pcap")
