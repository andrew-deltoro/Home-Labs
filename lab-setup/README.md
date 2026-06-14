[README.md](https://github.com/user-attachments/files/28527101/README.md)
# Log Monitoring Lab

**Skill demonstrated:** SIEM setup, Windows event log analysis, Sysmon deployment, detection engineering, alert tuning  
**Tools:** Windows 10 VM · Sysmon · Wazuh SIEM · VirtualBox  
**Status:** Complete  
**Date:** June 2, 2026

---

## Goal

Build a home lab that ingests Windows security events and Sysmon telemetry into a Wazuh SIEM, then surface three key detection scenarios via live dashboards — simulating the kind of visibility a SOC analyst would have on a monitored endpoint.

---

## Lab Environment

| Component | Details |
|---|---|
| Hypervisor | VirtualBox |
| Endpoint VM | Windows 10 |
| SIEM VM | Ubuntu Server 22.04 + Wazuh 4.x |
| Agent | Wazuh Agent (Windows) |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| Network | Host-Only Adapter (192.168.56.x) |

---

## Detections Built

| Dashboard | Event Source | Rule / Query |
|---|---|---|
| Failed logon attempts | Windows Security Log | Wazuh rule 60122 (Event ID 4625) |
| New account creation | Windows Security Log | Wazuh rule 60110 (Event ID 4720) |
| Suspicious process activity | Sysmon Event ID 1 | DQL: `data.win.eventdata.image:*cmd.exe* OR *powershell*` |

---

---

## Key Findings & Lessons Learned

- Rule IDs in Wazuh vary by version — always validate by searching raw events in Discover rather than assuming documented IDs are correct
- Sysmon requires an explicit `localfile` block in `ossec.conf` on the Windows agent; it does not get collected automatically
- `data.win.eventdata` fields are not indexed as keyword fields in this Wazuh version, which prevents their use in Terms aggregation buckets — DQL search is the workaround
- Building detections before baselines exist create a lot of noise — false positive tuning is a critical next step

---

## What I'd Improve Next

- Baseline normal process activity on the endpoint before alerting to reduce false positive volume
- Add a correlation rule: failed logons → new account creation within a short window (potential T1136 + T1110 chain)
- Integrate a threat intel feed (MISP or OpenCTI) to enrich alerts with known IOC context
- Automate test data generation with a single PowerShell script

---

## Repo Structure

```
log-monitoring-lab/
├── README.md
├── docs/
│   └── report.md
├── configs/
│   └── ossec-localfile-sysmon.xml
└── screenshots/
    ├── dashboard1-failed-logons.png
    ├── dashboard2-account-creation.png
    └── dashboard3-suspicious-processes.png
```

---

## References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1136 — Create Account](https://attack.mitre.org/techniques/T1136/)
