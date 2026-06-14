# SOC Lab Report — Log Monitoring Lab

**Author:** [Andrew Del Toro]  
**Date:** June 2, 2026  
**Scope:** Windows 10 VM (isolated home lab, no production systems)  
**Classification:** Portfolio / Educational

---

## Objective

Deploy a detection capability for three common early-stage attack behaviors on a Windows endpoint using Sysmon and Wazuh SIEM. Document what each detection fires on, where false positives can occur, and how each alert would be tuned in a real environment.

---

## Environment

A two-VM home lab running on VirtualBox:

- **Wazuh Server** — Ubuntu Server 22.04, Wazuh 4.x stack
- **Windows 10 Endpoint** — Wazuh agent, Sysmon (SwiftOnSecurity config)
- **Network** — Host-Only adapter, 192.168.56.x subnet, no external exposure

---

## Detection 1 — Failed Logon Attempts

**Event source:** Windows Security Log  
**Event ID:** 4625  
**Wazuh rule:** 60122

### What fires it
Any failed interactive or network logon attempt on the endpoint. In this lab, triggered by running `net use` with incorrect credentials in a loop.

### Why it matters
Repeated 4625 events from a single source in a short window are a strong indicator of password spraying (low-and-slow across many accounts) or brute force (high-volume against one account). Both are early-stage access techniques — catching them before a successful logon is the goal.

### False positive scenarios
- A user who forgets their password after a recent change and tries several times
- A misconfigured service account attempting to authenticate with an expired credential
- IT helpdesk tools that probe connectivity using test credentials

### Tuning recommendations
- Whitelist known service accounts that generate predictable 4625 noise
- Alert only on interactive logon failures (logon type 2) rather than all types
- Set a threshold — 5+ failures within 60 seconds from the same source — to reduce single-event noise
- Correlate with 4624 (successful logon) shortly after failures to detect successful brute force

---

## Detection 2 — New Local Account Creation

**Event source:** Windows Security Log  
**Event ID:** 4720 (account created), 4732 (added to group)  
**Wazuh rule:** 60110 (version-dependent — validated via Discover view)

### What fires it
Creation of a new local user account on the endpoint. In this lab, triggered using `net user` and `net localgroup` commands.

### Why it matters
Creating a local account — especially adding it to the Administrators group — is a classic persistence technique (MITRE ATT&CK T1136). An attacker who has gained initial access may create a backdoor account to maintain access even if their original foothold is removed.

### False positive scenarios
- IT helpdesk creating a local admin account during a break-fix visit
- Automated provisioning scripts running as part of a software deployment
- A developer setting up a local test account on their own machine

### Tuning recommendations
- Alert on account creation events that occur outside business hours
- Alert specifically when a new account is immediately added to the local Administrators group (4720 + 4732 in quick succession)
- Whitelist known provisioning service accounts as the `subjectUserName`
- Cross-reference with change management records in environments where account creation is formally tracked

### Version note
Wazuh documentation referenced rule IDs 60151 and 60204 for account creation events. These did not fire in this environment. The correct rule ID (60110) was identified by searching raw events in the Discover view and expanding the event to read the `rule.id` field directly. This is a reminder to always validate rule IDs against live data rather than assuming documentation matches your version.

---

## Detection 3 — Suspicious Process Activity

**Event source:** Sysmon Event ID 1 (Process Creation)  
**DQL filter:** `data.win.eventdata.image:*cmd.exe* OR data.win.eventdata.image:*powershell*`  
**Wazuh rules:** 92000+ range (Sysmon process creation)

### What fires it
Any process creation event where the spawned process is `cmd.exe` or `powershell.exe`. In this lab, triggered using `Start-Process` in PowerShell.

### Why it matters
`cmd.exe` and `powershell.exe` spawning from unexpected parent processes — Office applications, browsers, PDF readers — is a hallmark of phishing payload execution (MITRE ATT&CK T1059). Sysmon Event ID 1 captures the full parent-child process chain, which is what makes it valuable for this detection.

### False positive scenarios
- A developer launching a terminal session from their IDE
- A macro-enabled Excel file run legitimately by a finance user
- IT scripts that invoke PowerShell as part of normal maintenance

### Tuning recommendations
- The high-value version of this detection is not "PowerShell ran" but "PowerShell ran from an Office application" — narrow the filter to specific suspicious parent processes
- Baseline normal PowerShell usage in the environment first; alert on deviations from that baseline
- Add `data.win.eventdata.parentImage` as a bucket once the field is indexed as a keyword to enable parent-child table views
- Look for encoded command-line arguments (`-EncodedCommand`) as a higher-confidence signal

### Setup note
Sysmon events did not initially flow to Wazuh. Root cause: the Wazuh agent `ossec.conf` did not include a `localfile` block for the `Microsoft-Windows-Sysmon/Operational` event channel. Sysmon runs as a service and logs to the Windows Event Log, but the Wazuh agent only collects channels explicitly listed in its config. Fix applied:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

After restarting the Wazuh agent service, Sysmon events began indexing within 60 seconds.

---

## Summary of Detections

| Detection | Event Source | Rule / Query | Test Method | Result |
|---|---|---|---|---|
| Failed logons | Windows Security (4625) | Rule 60122 | `net use` loop × 7 | ✅ Detected |
| Account creation | Windows Security (4720) | Rule 60110 | `net user` + `net localgroup` | ✅ Detected |
| Suspicious processes | Sysmon EID 1 | DQL filter | `Start-Process cmd.exe` | ✅ Detected |

---

## What I'd Do Differently

- **Baseline first.** Running detections before establishing a normal activity baseline meant the dashboards showed noise alongside real events. In a real environment, baselining comes before alerting.
- **Correlation rules.** Each detection fires independently. A more mature detection would correlate events — failed logons followed by a new account creation within the same session is a much higher-confidence signal than either alone.
- **Network telemetry.** Endpoint logs alone don't show lateral movement. Adding DNS and firewall logs alongside Sysmon would give a more complete picture.
- **Automated test scripts.** Running test commands manually made it hard to reproduce results consistently. A single PowerShell script that generates all three scenarios in sequence would make the lab more repeatable.

---

## References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1136 — Create Account](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [Wazuh Rules Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules/index.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
