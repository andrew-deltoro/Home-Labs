# Cybersecurity Portfolio

Home for hands-on security projects — built to learn, not just to demo.

## About Me

Aspiring SOC Analyst / GRC Analyst actively building hands-on skills in blue-team detection, incident response, and security operations.

Passed CompTIA Security+ (SY0-701) in May 2026. Currently supplementing it with self-directed lab projects built around real-world SOC scenarios — Sysmon, Wazuh, Windows event logging, and custom detection engineering.

Every project here includes documentation covering not just what was built, but why — the alternatives considered, what the alerts actually mean, where false positives show up, and how I'd tune each one in a production environment.

**Targeting:** SOC Analyst · GRC Analyst · Junior Security Analyst
**Learning stack:** Python · Wazuh · Sysmon · Flask · SQLite · Kali Linux · Metasploit
**Location:** Indio, California — open to Orange County, Coachella Valley, and remote

---

## Projects

### [`pysiem/`](./pysiem) — Custom-Built SIEM/EDR
A lightweight SIEM built from scratch in Python (Flask, SQLite) to understand detection-engine internals beyond pre-built tools. Includes a live dashboard, YAML-based rule engine, and a full development log documenting every architecture decision.

### [`wazuh-soc-lab/`](./wazuh-soc-lab) — Attack Simulation & Detection
A 3-VM home lab (Kali Linux, Windows 10, Ubuntu + Wazuh) simulating real-world SOC operations — attack simulation with Metasploit and nmap, endpoint telemetry via Sysmon, and detection dashboards in Wazuh.

---

## License

MIT — use it, fork it, learn from it.
