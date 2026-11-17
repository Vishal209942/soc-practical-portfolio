# SOC Operations Practical Portfolio

Three hands-on security operations exercises performed in a self-built home lab, documented the way a Level 1 SOC analyst works: collect the evidence, read it against a known baseline, decide whether the activity is malicious, and record the verdict with the next action.

**Author:** Vishal Rajput — CEH v11, CompTIA Security+, CompTIA Network+
Greater Noida, India · vr807459@gmail.com · [LinkedIn](https://linkedin.com/in/vishal-6b07a9229)

**Full report:** [`SOC_Operations_Practical_Portfolio.pdf`](SOC_Operations_Practical_Portfolio.pdf) — includes all 12 evidence screenshots, observations, analysis and verdicts.

---

## Lab environment

| Component | Detail |
|---|---|
| Host | Kali Linux virtual machine on VMware Workstation |
| Monitored endpoint | Windows 10 machine (WIN-ATUHMIFM0NT) — Windows Security event log |
| Tools | Windows Event Viewer, Wireshark, Linux process utilities (`ps`, `readlink`), `ping`, `nslookup` |
| Exercises performed | 12 October 2026 |

All exercises were performed on systems I own or administer, in a controlled lab. No client, employer or third-party system was involved, and no credentials or personal data appear in this repository.

---

## Exercise 1 — Identify failed logon attempts (Windows Event ID 4625)

**Objective:** Locate at least three failed logon events in the Windows Security log and establish whether the activity is benign.

**Tools and commands:** Event Viewer → Windows Logs → Security; `Filter Current Log` with Event ID 4625; Event Details → XML View.

**What I did**

1. Opened Event Viewer and navigated to Windows Logs → Security.
2. Entered wrong credentials two to three times on the local account to generate genuine failed logon events.
3. Applied a filter on Event ID 4625 to isolate failed logon entries.
4. Reviewed timestamps, then opened XML View to extract source IP, logon type and process details.
5. Correlated the three events to check whether they formed a pattern.

**Evidence**

| Field | Value |
|---|---|
| Event ID | 4625 — An account failed to log on |
| Events captured | 3 — 12/10/2026 21:31:29 and 21:31:34; 22/09/2026 16:55:37 |
| TimeCreated (UTC) | 2026-10-12T16:01:29.8663837Z (EventRecordID 3861) |
| Target account | Administrator, domain VISHAL |
| Status / Sub-status | 0xc000006d / 0xc000006a — bad password on a valid account |
| Failure reason | %%2313 — unknown user name or bad password |
| Logon type | 7 — unlock attempt |
| Calling process | `C:\Windows\System32\svchost.exe` (Process ID 0x7c4) |
| Source IP / port | 127.0.0.1 / 0 — console logon, not remote |
| Computer | WIN-ATUHMIFM0NT.vishal.local |

**Analysis**

Three failed logons were recorded within a five-second window at 21:31 on 12 October. Sub-status `0xc000006a` is a bad password supplied for a valid account, logon type 7 is an unlock attempt at the console, and the source address is 127.0.0.1 on port 0, confirming the request came from the machine itself rather than across the network. The calling process is `svchost.exe` from the Windows system directory, the legitimate host for the logon service. Nothing in the record points to an external or automated attempt.

**Verdict:** Benign — self-generated on the local lab machine.

In production, the same three events arriving from an external IP, or spread across many accounts, would be triaged as brute force or password spraying: check the source against threat intelligence, look for a successful logon (4624) following the failures, and escalate to L2 if one appears.

---

## Exercise 2 — Analyse network traffic (DNS and ICMP in Wireshark)

**Objective:** Capture live traffic while generating DNS and ICMP activity, then identify and interpret both protocols.

**Tools and commands:** Wireshark live capture on the wireless adapter; display filters `dns` and `icmp`; commands `ping 8.8.8.8`, `ping 127.0.0.1`, `nslookup facebook.com`, `nslookup google.com`.

**What I did**

1. Started a live capture in Wireshark on the active Wi-Fi adapter.
2. Opened a browser and visited www.google.com to generate DNS queries.
3. Ran `ping 127.0.0.1`, `ping 8.8.8.8` and `nslookup` for facebook.com and google.com.
4. Applied the DNS filter, then the ICMP filter, to separate the two protocols.
5. Stopped the capture and recorded source IP, destination IP, protocol and timestamp for each packet.

**Evidence**

| Field | Value |
|---|---|
| DNS query | 192.168.76.131 (lab machine) → 8.8.8.8 (Google DNS), protocol DNS, standard query A www.google.com |
| ICMP echo | 127.0.0.1 → 127.0.0.1, protocol ICMP, echo (ping) request, TTL 64, ID 0x0005, Seq 2/51 |
| Lookups performed | facebook.com and google.com via `nslookup` |
| Capture date | 12 October 2026 |

**Analysis**

The capture shows two distinct patterns. The DNS traffic is a standard A-record query from the lab machine to Google's public resolver at 8.8.8.8, the expected path for name resolution on this network. The ICMP traffic is a loopback ping from 127.0.0.1 to itself, which confirms the local TCP/IP stack is working and never leaves the host. Neither pattern carries the indicators a SOC watches for: no high-volume querying of a single unusual domain, no abnormally long subdomain labels, and no data carried in the ICMP payload — the usual signatures of DNS tunnelling or an ICMP covert channel.

**Verdict:** Benign baseline activity.

On a production network I would baseline which resolvers are normal for each subnet, and alert on internal hosts querying external DNS directly or on bursts of TXT and NULL record requests, which are the classic DNS-exfiltration signals.

---

## Exercise 3 — Investigate a suspicious process (Linux endpoint)

**Objective:** Enumerate running processes on the lab host and validate one process by its name, PID, executable path and parent process.

**Tools and commands:** VMware Workstation (Kali Linux lab VM) and the Linux terminal:

```bash
ps aux | grep wireshark
ps -o pid,ppid,user,comm,args -p 205492
readlink -f /proc/205492/exe
ps -o pid,ppid,user,comm,args -p 205488
```

**What I did**

1. Listed running processes and located the target PID with `ps aux`.
2. Pulled full detail for the PID — owning user, parent PID and command line.
3. Resolved the real executable path to check for masquerading (MITRE ATT&CK T1036).
4. Validated the parent process to confirm the parent-child relationship was expected.
5. Recorded the verdict with the evidence.

**Evidence**

| Field | Value |
|---|---|
| Process name | wireshark |
| PID | 205492 |
| Owner | kali |
| Executable path | `/usr/bin/wireshark` |
| Parent process | `kali-menu` (PID 205488) |
| Technique checked | T1036 — Masquerading |
| Host | Kali Linux VM on VMware Workstation |

**Analysis**

PID 205492 is Wireshark, running as the `kali` user. Its executable resolves to `/usr/bin/wireshark`, the package's real installation path rather than a copy dropped in `/tmp` or a user home directory, which is where masqueraded binaries normally sit. The parent process is `kali-menu`, the desktop launcher, so the process was started from the application menu by the logged-in user. Name, path, owner and parent all agree, and there is no sign of a renamed or reparented binary.

**Verdict:** Benign.

In production I would add Sysmon Event ID 1 (process creation) and a Wazuh agent so this validation runs on telemetry rather than by hand. If a process showed a mismatched path or an unexpected parent — an Office application spawning PowerShell, for example — I would isolate the host, check the file hash against VirusTotal, and escalate to L2 citing T1036 or T1059.

---

## Skills demonstrated

| Skill | Demonstrated in | Why it matters for SOC L1 |
|---|---|---|
| Windows event log analysis | Exercise 1 | Triage decisions turn on fields, not alert titles |
| Network protocol analysis | Exercise 2 | Separating benign baseline from exfiltration attempts |
| Endpoint process validation | Exercise 3 | Catching masquerading and unusual parent-child chains |
| MITRE ATT&CK mapping | Exercises 1–3 | The structured language L2 expects in an escalation |
| Incident documentation | All three | Every SOC ticket needs evidence, analysis and next action |

---

## Repository contents

```
.
├── README.md                                   This file — summary of all three exercises
└── SOC_Operations_Practical_Portfolio.pdf      Full report with evidence screenshots
```

## Planned next

- Detection lab: Splunk Free / Wazuh ingesting Windows Security logs (4624, 4625, 4688) with a brute-force alert and dashboard.
- Phishing analysis set: header review, SPF/DKIM/DMARC validation, URL and attachment triage for five sample emails.
