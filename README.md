# Cybersecurity Portfolio

Home for hands on security projects tht are built to learn not just to demo.

## About Me

Aspiring SOC Analyst and GRC Analyst actively building hands on skills in blue team detection, incident response and security operations.

Passed CompTIA Security+ (SY0-701) in May 2026. Currently supplementing it with self directed lab projects built around real world SOC scenarios that include Sysmon, Wazuh, Windows event logging and custom detection engineering.

Every project here includes documentation covering not just what was built but why. Like what the alerts actually mean, where false positives show up and how I'd tune each one in a production environment.

**Targeting:** SOC Analyst · GRC Analyst · Junior Security Analyst
**Learning stack:** Python · Wazuh · Sysmon · Flask · SQLite · Kali Linux · Metasploit
**Location:** Indio, California. Open to Southern California including Orange County and the Coachella Valley. Remote friendly.

---

## Projects

### [pysiem/](pysiem) — Custom Built SIEM/EDR
A lightweight SIEM built from scratch in Python with Flask and SQLite to understand detection engine internals beyond prebuilt tools. Includes a live dashboard, a YAML based rule engine and a full development log documenting every architecture decision.

### [pysec-academy](https://github.com/andrew-deltoro/pysec-academy) — Full Stack Security Learning Platform
A browser based platform that teaches Python through real security work like hashing, log triage with regex and layered payload decoding. Runs real Python in the browser via WebAssembly. Backed by Supabase auth with per user data locked down by Postgres row level security and API keys kept server side behind a validated serverless proxy.
**Live demo:** https://pysec-academy.netlify.app/

### [wazuh-soc-lab/](wazuh-soc-lab) — Attack Simulation and Detection
A three VM home lab with Kali Linux, Windows 10 and Ubuntu running Wazuh that simulates real world SOC operations. Covers attack simulation with Metasploit and nmap, endpoint telemetry via Sysmon and detection dashboards in Wazuh.

## License

MIT — use it, fork it, learn from it.
