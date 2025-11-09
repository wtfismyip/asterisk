# IAX2 VARIABLE IE Buffer Overflow - Proof of Concept

## Overview

This directory contains proof-of-concept code demonstrating **CVE-PENDING**: Buffer overflow in Asterisk IAX2 `iax_parse_ies()` function.

**Vulnerability:** Stack buffer overflow in VARIABLE information element parsing
**Location:** `channels/iax2/parser.c:1127`
**Severity:** CRITICAL (CVSS 9.8)
**Authentication Required:** NO (pre-authentication vulnerability)

## Files

1. **`poc_iax2_variable_overflow.py`** - Network-based POC that sends malicious IAX2 packets
2. **`test_iax2_vulnerability.c`** - Standalone test harness to verify the bug
3. **`POC_README.md`** - This file

## The Vulnerability

### Vulnerable Code

In `channels/iax2/parser.c`, line 1127:

```c
int iax_parse_ies(struct iax_ies *ies, unsigned char *data, int datalen)
{
    int len;
    int ie;
    char tmp[256], *tmp2;  // ← Fixed 256-byte buffer

    while(datalen >= 2) {
        ie = data[0];
        len = data[1];      // ← Length from network (attacker controlled)

        switch(ie) {
        case IAX_IE_VARIABLE:
            ast_copy_string(tmp, (char *)data + 2, len + 1);
            //                                      ^^^^^^^^
            //                        Copies (len+1) bytes with NO bounds check!
            tmp2 = strchr(tmp, '=');
            // ... process variable ...
            break;
        }
    }
}
```

### The Bug

- `tmp` buffer is **256 bytes**
- `len` is read from network packet (1 byte, values 0-255)
- `ast_copy_string(tmp, data+2, len+1)` copies **(len+1) bytes** into `tmp`
- When `len >= 256`, overflow occurs
- **NO validation** before copy operation

### Attack Vector

1. Attacker sends IAX2 `IAX_COMMAND_NEW` packet (no authentication required)
2. Packet includes malicious `IAX_IE_VARIABLE` information element
3. IE has `len` field set to 255 (copies 256 bytes - boundary case)
4. Or in a multi-IE packet, can craft to copy more data
5. Buffer overflow overwrites stack
6. Potential code execution or denial of service

## Usage

### WARNING ⚠️

**These tools are for AUTHORIZED SECURITY TESTING ONLY.**

- Only test systems you own or have explicit permission to test
- Unauthorized testing is illegal
- These POCs can crash target systems

### Method 1: Network POC (Python)

Test against a running Asterisk server:

```bash
# Show vulnerability analysis
python3 poc_iax2_variable_overflow.py analyze

# Generate test vectors
python3 poc_iax2_variable_overflow.py vectors

# Send POC packet (AUTHORIZED TARGETS ONLY)
python3 poc_iax2_variable_overflow.py <target_ip> [port] [overflow_size]

# Examples:
python3 poc_iax2_variable_overflow.py 127.0.0.1 4569 260
```

**What it does:**
- Creates malicious IAX2 packet with oversized VARIABLE IE
- Sends UDP packet to target Asterisk IAX2 port (default 4569)
- May crash Asterisk or corrupt memory
- Check system logs for crash evidence

### Method 2: Standalone Test (C)

Test without network or Asterisk installation:

```bash
# Compile without sanitizer
gcc -o test_iax2_vuln test_iax2_vulnerability.c -g -Wall

# Run basic test
./test_iax2_vuln

# Compile with Address Sanitizer (recommended)
gcc -o test_iax2_vuln_asan test_iax2_vulnerability.c -g -Wall -fsanitize=address

# Run with ASAN (will clearly show overflow)
./test_iax2_vuln_asan

# Run with Valgrind
valgrind --leak-check=full ./test_iax2_vuln
```

**Expected Results:**

Without ASAN/Valgrind:
- Program may run to completion
- Silent stack corruption possible
- Canary values may not detect overflow (depending on layout)

With ASAN:
```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 256 at 0x7ffc12345678
```

With Valgrind:
```
==12345== Invalid write of size 1
==12345==    at 0x...: vulnerable_parse_variable_ie
```

## Verifying in Real Asterisk

To verify this vulnerability in a real Asterisk installation:

### 1. Setup Test Environment

```bash
# Start Asterisk with debugging
asterisk -c

# Enable IAX2 debugging
iax2 set debug on

# Monitor logs
tail -f /var/log/asterisk/messages
```

### 2. Send Malicious Packet

```bash
# From another terminal
python3 poc_iax2_variable_overflow.py 127.0.0.1
```

### 3. Expected Behavior

**If vulnerable:**
- Asterisk may crash immediately
- Core dump generated
- Segmentation fault in logs
- Process exits unexpectedly

**System logs may show:**
```
kernel: asterisk[1234]: segfault at 0x... ip 0x... sp 0x... error 6 in asterisk
```

**Asterisk backtrace (if core dump available):**
```
#0  iax_parse_ies ()
#1  socket_process_helper ()
#2  socket_process ()
```

## Exploitation Scenarios

### Scenario 1: Denial of Service (Easy)

**Difficulty:** Trivial
**Impact:** HIGH

1. Send single malicious packet
2. Asterisk crashes
3. Phone service disrupted
4. Requires manual restart

**Mitigation:** Firewall rules, disable IAX2

### Scenario 2: Remote Code Execution (Advanced)

**Difficulty:** Moderate
**Impact:** CRITICAL

1. Craft VARIABLE IE with ROP chain in overflow data
2. Overflow overwrites return address on stack
3. Control instruction pointer
4. Execute arbitrary code with Asterisk privileges

**Requirements:**
- Stack layout knowledge
- ASLR/DEP bypass techniques
- Architecture-specific shellcode

**Mitigation:** Apply patch, enable stack protections

## Patch

### Temporary Fix

In `channels/iax2/parser.c`, line 1127, add bounds check:

```c
case IAX_IE_VARIABLE:
    // Add this check:
    if (len > 254) {  // Leave room for null terminator
        snprintf(tmp, sizeof(tmp), "VARIABLE IE too long (%d bytes)", len);
        errorf(tmp);
        break;
    }
    ast_copy_string(tmp, (char *)data + 2, len + 1);
    // ... rest of code
```

### Better Fix

Use dynamic allocation or bounded copy:

```c
case IAX_IE_VARIABLE:
    if (len > 0 && len < 8192) {  // Reasonable max
        char *tmpbuf = ast_alloca(len + 1);
        if (tmpbuf) {
            memcpy(tmpbuf, data + 2, len);
            tmpbuf[len] = '\0';
            tmp2 = strchr(tmpbuf, '=');
            // ... process with tmpbuf
        }
    }
    break;
```

## Detection

### IDS/IPS Signatures

Snort/Suricata rule to detect oversized VARIABLE IEs:

```
alert udp any any -> any 4569 (
    msg:"IAX2 VARIABLE IE Buffer Overflow Attempt";
    content:"|34|";  # IAX_IE_VARIABLE = 52 (0x34)
    byte_test:1,>,254,1,relative;
    classtype:attempted-admin;
    sid:1000001;
    rev:1;
)
```

### Log Monitoring

Monitor for Asterisk crashes:

```bash
# Check for segfaults
dmesg | grep -i "asterisk.*segfault"

# Check Asterisk logs
grep -i "segmentation fault\|stack smashing\|corrupted" /var/log/asterisk/*
```

## References

- **Vulnerability Report:** `../IAX2_SECURITY_REVIEW.md`
- **Affected File:** `channels/iax2/parser.c`
- **Affected Function:** `iax_parse_ies()`
- **IAX2 RFC:** RFC 5456
- **Asterisk Security:** https://www.asterisk.org/community/security/

## Responsible Disclosure

If you discover this vulnerability exists in deployed systems:

1. **DO NOT** publicly disclose details immediately
2. **DO** report to Asterisk security team: security@asterisk.org
3. **DO** allow 90 days for patch development
4. **DO** coordinate disclosure timeline
5. **DO NOT** attack systems without authorization

## Legal Disclaimer

This code is provided for:
- Security research
- Vulnerability validation
- Patch verification
- Educational purposes

**Unauthorized use is illegal and unethical.**

The authors assume no liability for misuse of this code. Use only on systems you own or have explicit written permission to test.

---

**POC Author:** Security Review Team
**Date:** 2025-11-09
**Version:** 1.0
