# SOC Writeups

SOC N1 triage notes from TryHackMe labs (blue team / SIEM). Template: alert → evidence → classification → action/escalation.

Author: Edilson Cabral · targeting junior SOC / blue team roles.

---

## Writeup A — SIEM Alert Triage (Intro to SIEM)

**Date:** 2026-10-28  
**Source:** TryHackMe · Intro to SIEM / SOC Level 1  
**Goal:** Document how an L1 analyst triages SIEM alerts of different severities and verdicts.

### Case 1 — Potential Crypto Miner Activity

- **Severity:** Medium · **Verdict:** True Positive
- **Context:** Host `HR_02` · User `Chris` · Timestamp May 6, 2022 4:55 PM (PKT)
- **Evidence:** Windows event / SIEM fields — severity, process name, host, event time
- **MITRE:** T1496 Resource Hijacking
- **Action:** Classified True Positive; escalated to verify host isolation
- **Did not:** Full malware analysis (L2)

### Case 2 — Unusual VPN Login Location

- **Severity:** Medium · **Verdict:** False Positive
- **Context:** Mar 21, 2025 12:40 · User `M.Clark` · Source IP `45.8.112.7` · Login Japan (expected United States)
- **Evidence:** First-seen VPN location; description indicated possible account compromise
- **MITRE (initial):** T1078 Valid Accounts — discarded after validation
- **Action:** User contact — CFO confirmed vacation in Japan and urgent VPN use; Closed as False Positive
- **Would escalate if:** User unreachable or denied travel → password reset, session/MFA review, L2

### Case 3 — Potential Data Exfiltration

- **Severity:** Critical · **Verdict:** False Positive
- **Context:** Mar 21, 2025 13:30 · Source IP `192.168.45.66` · Network `UK04/MEETINGROOM` · Destination `*.zoom.us`
- **Evidence:** Sent 5.8 GB / Received 5.2 GB in one day (rule: ≥5 GB to a single destination)
- **MITRE (initial):** T1041 Exfiltration Over C2 Channel — discarded
- **Action:** Destination is Zoom; bidirectional volume matches a meeting/recording on a meeting-room network; Closed as False Positive
- **Would escalate if:** Unknown destination or upload-only pattern → isolate, capture flow, L2

### Case 4 — Double-Extension File Creation

- **Severity:** High · **Verdict:** True Positive
- **Context:** Mar 21, 2025 13:58 · Host `LPT-HR-009` · User `S.Conway` · Process `chrome.exe`
- **Evidence:**
  - File: `C:\Users\S.Conway\Downloads\cats2025.mp4.exe`
  - MotW / URL: `https://freecatvideoshd.monster/cats2025.mp4.exe`
  - MD5: `14d8486f3f63875ef93cfd240c5dc10b`
  - VirusTotal: flagged malicious (engines + community)
- **MITRE:** T1036.007 Masquerading: Double File Extension · T1566 Phishing
- **Action:** True Positive; comment with hash, URL, VT; escalate for quarantine, credential reset, execution check
- **SIEM comment (production-style):** True Positive. `cats2025.mp4.exe` downloaded via Chrome on LPT-HR-009 (S.Conway) from freecatvideoshd.monster. Double extension + MotW. MD5 `14d8486f3f63875ef93cfd240c5dc10b` — VirusTotal malicious. Isolate host, remove file, reset credentials; escalate L2 if executed.

### Case 5 — Download from GitHub Repository

- **Severity:** Low · **Verdict:** False Positive
- **Context:** Mar 21, 2025 13:02 · User `G.Chandler` · Host `LPT-IT-063` · Network `VPN/DEVELOPERS`
- **Evidence:** Accessed URL `https://github.com/facebook/react` (official Facebook/React repo)
- **MITRE (rule hypothesis):** T1105 Ingress Tool Transfer — not applicable here
- **Action:** Expected developer traffic; Closed as False Positive
- **Would escalate if:** Unknown gist/raw or suspicious new repo → hash the file, EDR, L2

### Lessons

- Severity ≠ verdict — Critical can be FP (Zoom), Low can still need a quick context check
- MotW + double extension + VT hash closes a TP fast
- Broad rules (any GitHub download) need role/network allowlists to cut noise
- Production comments should include hash, URL, VT outcome, and next action — not only “malicious file”

---

## Roadmap

- [x] Writeup A — SIEM triage (Intro to SIEM)
- [ ] Writeup B — Phishing analysis path
- [ ] Writeup C — Offensive room rewritten from a blue / SIEM-EDR view

All content is from TryHackMe lab scenarios only — no production PII.
