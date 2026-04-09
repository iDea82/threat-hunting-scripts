# Threat Hunting Scripts

A collection of Python-based threat hunting scripts that 
proactively detect adversary behavior in log data — without 
relying on pre-existing alert rules. Each hunt is built around 
a specific hypothesis mapped to MITRE ATT&CK techniques.

---

## The Problem These Scripts Solve

Standard detection rules only catch what they are written to 
catch. Sophisticated attackers study detection thresholds and 
operate just below them. These scripts find that activity 
through statistical analysis and behavioral pattern recognition 
across raw log data.

---

## Hunts

### Hunt 1 — Beaconing Detection
**File:** `hunt_beaconing.py`  
**MITRE ATT&CK:** T1071.001 - Application Layer Protocol: Web  
**Hypothesis:** Malware is calling home to a C2 server at 
regular intervals, blending into normal HTTPS traffic.

**Method:** Statistical analysis of connection timing between 
each internal host and external destination. Legitimate browsing 
produces irregular intervals (high standard deviation). Malware 
beaconing produces regular intervals (low standard deviation). 
A beacon score of 0-100 is calculated using the coefficient of 
variation of inter-connection intervals.

**Result on sample data:**
- Identified `WKSTN-ATIJANI-01` beaconing to `185.220.101.45`
- 260 connections, mean interval 5.0 minutes, std deviation 17.1s
- Beacon score: 95/100

---

### Hunt 2 — Credential Stuffing Detection
**File:** `hunt_credential_stuffing.py`  
**MITRE ATT&CK:** T1110.004 - Credential Stuffing  
**Hypothesis:** An attacker is using distributed credential 
stuffing — many source IPs each attempting 1-2 logins — to 
stay under per-source lockout thresholds.

**Method:** Five-layer analysis — external IP failure volume, 
per-source attempt distribution, time clustering, targeted 
account analysis, and post-attack success detection.

**Result on sample data:**
- Identified 50 unique attacker IPs each attempting ≤3 logins
- 101 total failures across 8 accounts in 9.9 minutes
- Detected successful compromise of `bjones` account

---

### Hunt 3 — Lateral Movement Detection
**File:** `hunt_lateral_movement.py`  
**MITRE ATT&CK:** T1021.002 - SMB/Windows Admin Shares  
**MITRE ATT&CK:** T1047 - Windows Management Instrumentation  
**Hypothesis:** An attacker is moving laterally through the 
network using legitimate admin tools — PsExec and WMI.

**Method:** Four-layer analysis — admin tool usage detection, 
workstation-to-server movement patterns, rapid multi-system 
authentication, and service installation chain analysis.

**Result on sample data:**
- Identified `bjones` using PsExec and WMI to move laterally
- Movement chain: WKSTN-ATIJANI-01 → SRV-FILE-01 → SRV-DC-01
- 4 servers compromised: FILE, APP, DC, SQL

---

## The Full Attack Story

Running all three hunts against the sample data reveals a 
complete intrusion that generated zero alerts:


02:17 — Malware begins beaconing every 5 min (no alert)
03:22 — Credential stuffing attack via 50 IPs (no alert)
03:34 — bjones account compromised via stuffing
03:34 — Lateral movement begins via PsExec/WMI
03:49 — Domain controller and SQL server compromised

---

## Setup

```bash
git clone https://github.com/iDea82/threat-hunting-scripts.git
cd threat-hunting-scripts
python -m venv venv
venv\Scripts\activate
python -m pip install pandas numpy colorama tabulate
python generate_sample_logs.py
python main.py
```

---

## Tech Stack

- **Python 3** — core language
- **pandas** — log data processing and analysis
- **numpy** — statistical calculations
- **colorama** — color-coded terminal output
- **tabulate** — formatted result tables

---

## Author

Adesina Tijani — Security Operations Analyst  
Detection Engineering · Threat Hunting · SOC Automation  
[linkedin.com/in/adesina-tijani-6372693b5](https://linkedin.com/in/adesina-tijani-6372693b5)  
[github.com/iDea82](https://github.com/iDea82)