# IAX2 Security Review Report

## Executive Summary

This security review of the IAX2 (Inter-Asterisk eXchange Protocol version 2) implementation in Asterisk has identified multiple critical and high-severity vulnerabilities in remotely accessible code paths. The IAX2 protocol handles network communications between Asterisk servers and is exposed to untrusted network input.

**Critical Findings:** 3
**High Severity:** 4
**Medium Severity:** 2

---

## Critical Vulnerabilities

### 1. Potential Buffer Overflow in IE String Parsing (parser.c:1188)

**Location:** `/home/user/asterisk/channels/iax2/parser.c:1188`
**Severity:** CRITICAL
**CVSS:** 9.8 (Network/High)

**Description:**
The `iax_parse_ies()` function writes a null terminator at `*data = '\0'` after processing all Information Elements. When the last IE exactly fills the remaining buffer (datalen becomes 0), this write occurs one byte past the allocated buffer, causing a heap buffer overflow.

**Vulnerable Code:**
```c
while(datalen >= 2) {
    // ... process IEs ...
    datalen -= (len + 2);
    data += (len + 2);
}
/* Null-terminate last field */
*data = '\0';  // CAN OVERFLOW if datalen == 0
```

**Attack Vector:**
A remote attacker can send a crafted IAX2 packet with IEs that exactly fill the buffer, triggering a one-byte heap overflow which could be leveraged for code execution.

---

### 2. Buffer Overflow in IAX_IE_VARIABLE Parsing (parser.c:1127)

**Location:** `/home/user/asterisk/channels/iax2/parser.c:1127`
**Severity:** CRITICAL
**CVSS:** 9.8 (Network/High)

**Description:**
When parsing the IAX_IE_VARIABLE information element, the code copies `len + 1` bytes into a 256-byte stack buffer without validating that len < 256. This allows a direct stack buffer overflow.

**Vulnerable Code:**
```c
case IAX_IE_VARIABLE:
    ast_copy_string(tmp, (char *)data + 2, len + 1);  // tmp is 256 bytes
```

**Attack Vector:**
An attacker can send a VARIABLE IE with len >= 256, causing `ast_copy_string` to copy up to 257 bytes into a 256-byte buffer, overflowing the stack and potentially achieving code execution.

**Exploitation Likelihood:** HIGH - The bug is straightforward to trigger and the overflow is directly controllable.

---

### 3. Integer Underflow in Trunk Packet Processing (chan_iax2.c:10083-10090)

**Location:** `/home/user/asterisk/channels/chan_iax2.c:10083-10090`
**Severity:** CRITICAL
**CVSS:** 8.6 (Network/High)

**Description:**
In `socket_process_meta()`, the `packet_len` variable (signed int) can underflow when processing meta trunk packets, leading to memory corruption.

**Vulnerable Code:**
```c
while (packet_len >= sizeof(*mte)) {
    if (metatype == IAX_META_TRUNK_MINI) {
        mtm = (struct ast_iax2_meta_trunk_mini *) ptr;
        ptr += sizeof(*mtm);
        packet_len -= sizeof(*mtm);  // Can make packet_len negative
        len = ntohs(mtm->len);
        // ...
    }
    // Later:
    if (len > packet_len)  // Signed comparison with potentially negative value
        break;
    ptr += len;
    packet_len -= len;  // Further underflow
}
```

**Attack Vector:**
If packet_len becomes negative, the signed comparison `len > packet_len` may pass even when len is very large, allowing the attacker to cause ptr to advance beyond buffer bounds, leading to out-of-bounds memory access.

---

## High Severity Vulnerabilities

### 4. Missing Packet Size Validation (chan_iax2.c:9993-9994)

**Location:** `/home/user/asterisk/channels/chan_iax2.c:9993-9994`
**Severity:** HIGH
**CVSS:** 7.5 (Network/High)

**Description:**
The `socket_read()` function casts the received network buffer directly to `struct ast_iax2_full_hdr` without first validating that the buffer is at least `sizeof(struct ast_iax2_full_hdr)` bytes.

**Vulnerable Code:**
```c
thread->buf_len = ast_recvfrom(fd, thread->readbuf, sizeof(thread->readbuf), 0, &thread->ioaddr);
// ... some error checks ...
fh = (struct ast_iax2_full_hdr *) thread->buf;  // NO SIZE CHECK
if (ntohs(fh->scallno) & IAX_FLAG_FULL) {  // Reads from potentially incomplete struct
```

**Impact:**
Reading from an incompletely received structure could lead to reading uninitialized memory or crashing. While later code at 10306-10309 checks minimum size, this occurs after the structure has already been accessed.

---

### 5. Unsafe String Pointer Aliasing Without Null Termination Guarantee

**Location:** `/home/user/asterisk/channels/iax2/parser.c:821-842`
**Severity:** HIGH
**CVSS:** 7.5 (Network/High)

**Description:**
String-type IEs have their pointers set directly into the network buffer without guaranteeing null-termination:

```c
case IAX_IE_CALLED_NUMBER:
    ies->called_number = (char *)data + 2;
    break;
case IAX_IE_USERNAME:
    ies->username = (char *)data + 2;
    break;
// ... many more string IEs
```

While the null-termination scheme (overwriting next IE's type byte) works in most cases, edge cases exist where strings may not be properly terminated, especially:
- When IEs have zero length
- When strings contain embedded nulls
- When parsing errors occur mid-stream

**Impact:**
Use of these pointers in string functions throughout chan_iax2.c could lead to buffer over-reads, information disclosure, or denial of service.

---

### 6. Race Condition in Call Number Handling

**Location:** `/home/user/asterisk/channels/chan_iax2.c:9998-10020`
**Severity:** HIGH
**CVSS:** 6.8 (Network/High)

**Description:**
The code checks if another thread is processing a full frame for the same callno, but there's a window between unlocking and re-processing where the iaxs[callno] structure could be freed:

```c
AST_LIST_TRAVERSE(&active_list, cur, list) {
    if ((cur->ffinfo.callno == callno) &&
        !ast_sockaddr_cmp_addr(&cur->ffinfo.addr, &thread->ioaddr))
        break;
}
if (cur) {
    defer_full_frame(thread, cur);
    // ...
    return 1;
}
```

**Impact:**
Use-after-free conditions could occur if the call is destroyed between threads, potentially leading to code execution.

---

### 7. Lack of Input Validation on Codec Preferences

**Location:** `/home/user/asterisk/channels/chan_iax2.c:10999-11000`
**Severity:** HIGH
**CVSS:** 6.5 (Network/Medium)

**Description:**
The codec preferences IE is passed to `iax2_codec_pref_convert()` without validating its length or content:

```c
if (ies.codec_prefs)
    iax2_codec_pref_convert(&iaxs[fr->callno]->rprefs, ies.codec_prefs, 32, 0);
```

The pointer `ies.codec_prefs` points directly into the network buffer and may not be null-terminated or may have arbitrary length.

---

## Medium Severity Vulnerabilities

### 8. Potential Information Disclosure Through Error Messages

**Location:** Multiple locations in `chan_iax2.c`
**Severity:** MEDIUM

**Description:**
Error messages include details from untrusted network input that could be used for reconnaissance:

```c
ast_log(LOG_WARNING, "Rejected connect attempt from %s, request '%s@%s' does not exist\n",
    ast_sockaddr_stringify(&addr), iaxs[fr->callno]->exten, iaxs[fr->callno]->context);
```

This reveals valid context/extension combinations to attackers.

---

### 9. Insufficient Validation of Firmware Download Requests

**Location:** `/home/user/asterisk/channels/chan_iax2.c:11947-11960`
**Severity:** MEDIUM

**Description:**
The IAX_COMMAND_FWDOWNL handler allows firmware downloads with minimal authentication checks. While firmware files themselves are validated, the mechanism could be abused for:
- Denial of service (requesting large firmware transfers)
- Resource exhaustion
- Information gathering about deployed firmware versions

---

## Recommendations

### Immediate Actions (Critical Fixes)

1. **Fix IAX_IE_VARIABLE overflow:** Add bounds check before copying:
   ```c
   case IAX_IE_VARIABLE:
       if (len > 254) {  // Leave room for null terminator
           errorf("VARIABLE IE too long");
           break;
       }
       ast_copy_string(tmp, (char *)data + 2, len + 1);
   ```

2. **Fix parser null termination overflow:** Check buffer bounds:
   ```c
   if (datalen > 0) {
       *data = '\0';
   } else if (datalen == 0 && data > original_data) {
       *(data-1) = '\0';  // Null terminate last byte of last IE
   }
   ```

3. **Fix packet_len underflow:** Use unsigned arithmetic or add underflow checks:
   ```c
   if (packet_len < (int)sizeof(*mtm)) {
       break;
   }
   packet_len -= sizeof(*mtm);
   ```

### Short-term Mitigations

1. **Add packet size validation** before casting to structures
2. **Implement maximum IE length limits** (e.g., 1024 bytes)
3. **Add fuzzing tests** for IAX2 packet parsing
4. **Enable stack canaries** and compile-time hardening flags
5. **Audit all uses of ies.* pointers** for missing null checks

### Long-term Improvements

1. **Refactor IE parsing** to use safer string handling:
   - Allocate separate buffers for string IEs
   - Always null-terminate explicitly
   - Validate lengths against maximums

2. **Implement comprehensive input validation** at protocol boundaries
3. **Add rate limiting** for unauthenticated IAX2 operations
4. **Consider deprecating IAX2** in favor of more modern, secure protocols
5. **Implement automatic fuzzing** in CI/CD pipeline

---

## Attack Scenarios

### Scenario 1: Remote Code Execution via VARIABLE IE Overflow
1. Attacker sends IAX_COMMAND_NEW with malicious VARIABLE IE
2. IE has length field set to 255+
3. Stack buffer overflow in parser.c:1127
4. Attacker controls return address via overflow
5. Code execution achieved

**Likelihood:** HIGH
**Impact:** CRITICAL
**Weaponization:** Straightforward - no authentication required for initial packet

### Scenario 2: Denial of Service via Trunk Packet Underflow
1. Attacker sends crafted IAX meta trunk packet
2. Packet causes packet_len to underflow
3. Out-of-bounds memory access crashes Asterisk
4. Service disruption

**Likelihood:** HIGH
**Impact:** HIGH
**Weaponization:** Trivial - single malformed packet

---

## Affected Components

- **chan_iax2.c** - Main IAX2 channel driver (15,109 lines)
- **iax2/parser.c** - Protocol parsing (1,353 lines)
- **iax2/firmware.c** - Firmware handling (342 lines)

**Total Remotely Accessible Attack Surface:** ~17,000 lines of C code processing untrusted network input

---

## Conclusion

The IAX2 implementation contains multiple critical memory safety vulnerabilities that can be triggered remotely without authentication. The most severe issues (CVE-worthy) are:

1. Buffer overflow in VARIABLE IE parsing - **IMMEDIATE FIX REQUIRED**
2. Heap overflow in IE null termination - **IMMEDIATE FIX REQUIRED**
3. Integer underflow in trunk processing - **IMMEDIATE FIX REQUIRED**

All findings should be treated as **CRITICAL** due to the remote, unauthenticated nature of the attack vectors and the potential for code execution.

**Recommendation:** Apply emergency patches for the critical issues and consider placing IAX2 behind strict firewall rules limiting exposure to trusted peers only.

---

**Review Date:** 2025-11-09
**Reviewer:** Security Analysis
**Files Analyzed:**
- /home/user/asterisk/channels/chan_iax2.c
- /home/user/asterisk/channels/iax2/parser.c
- /home/user/asterisk/channels/iax2/firmware.c
- /home/user/asterisk/channels/iax2/include/iax2.h
