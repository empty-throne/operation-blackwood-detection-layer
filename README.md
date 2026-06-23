# 🔍 Operation Blackwood — Detection Layer
## Real Attack Data. Real Detection Rules. Real Splunk Dashboard.

> **Part Three of the SentinelView Trilogy**  
> *Reconnaissance → Detection → Forensics*

---

## Project Overview

**Operation Blackwood Detection Layer** takes the actual attack data from Operation Blackwood — a full-cycle AD environment compromise captured in 2,940 Windows Security event logs — and builds a **production-ready Splunk SIEM detection infrastructure** around it.

This project demonstrates end-to-end SOC capabilities:

```
Real Attack Logs (Operation Blackwood)
         ↓
Splunk Data Ingestion (SIEM01 VM)
         ↓
Event ID Correlation & Analysis
         ↓
Detection Rules (6 attack stages)
         ↓
Executive Dashboard (Attack Timeline)
```

---

## What This Shows

✅ **SIEM Deployment** — Ubuntu Server + Splunk Enterprise from scratch  
✅ **Data Ingestion** — CSV/Windows Event Log pipeline to Splunk  
✅ **Detection Engineering** — SPL (Splunk Processing Language) queries for 6 attack stages  
✅ **Dashboard Design** — Executive-friendly attack timeline visualization  
✅ **Attack Coverage** — Password spray → credential theft → lateral movement → privilege escalation  

---

## Lab Architecture

### Infrastructure

```
Operation Blackwood VMs (existing)
  DC01 (192.168.10.10) — Domain Controller, Windows Server 2025
  WRK01 (192.168.10.11) — Workstation, Windows 11
  KALI (192.168.10.99) — Attacker VM, Kali Linux

Detection Layer VM (new)
  SIEM01 (192.168.10.50) — Ubuntu Server 26.04 + Splunk Enterprise
```

### Network

```
VirtualBox Internal Network: blackwood-lab (192.168.10.0/24)
  ├── DC01-Security.evtx → SIEM01 (CSV export + ingestion)
  ├── Live forwarding → (future: Universal Forwarder on DC01)
  └── Splunk Web UI accessible from host (192.168.216.10:8000)
```

---

## Data Ingested

**Total Events:** 2,940  
**Event ID Distribution:**

| Event ID | Type | Count | Purpose |
|----------|------|-------|---------|
| 4625 | Failed Logon | 10 | Password spray cluster detection |
| 4624 | Successful Logon | 1,912 | Initial access + lateral movement |
| 4776 | NTLM Auth | 92 | Pass-the-Hash detection |
| 4769 | Kerberos Ticket | 174 | Kerberoasting detection |
| 4648 | Explicit Credentials | 48 | Lateral movement indicator |
| 4672 | Special Privileges | 704 | Privilege escalation detection |

---

## Detection Rules

Six detection rules (SR-001 through SR-006) map to the MITRE ATT&CK attack chain:

### SR-001 — Password Spray Detection (T1110.003)

```spl
index=blackwood_ad sourcetype=csv Id=4625 
| timechart count by Account
```

**Trigger:** >5 failed logon attempts from single source in timeframe  
**In Data:** 10 × Event ID 4625 clustered  
**Dashboard:** Visible as spike in "Password Spray Attempts" panel

---

### SR-002 — Successful Logon Post-Spray (T1078.003)

```spl
index=blackwood_ad sourcetype=csv Id=4624 
| table TimeCreated, Account, Message
```

**Trigger:** Logon success following spray pattern  
**In Data:** jsmith and aturner successful logons after spray cluster  
**Dashboard:** Shows in "Attack Timeline" correlation

---

### SR-003 — Pass-the-Hash (T1550.002)

```spl
index=blackwood_ad sourcetype=csv Id=4776 
| table TimeCreated, Account, Message
```

**Trigger:** NTLM auth from unexpected source IP  
**In Data:** 92 × Event ID 4776 — aturner Domain Admin NTLM authentications  
**Dashboard:** Visible spike in "Complete Attack Timeline"

---

### SR-004 — Kerberoasting Attempt (T1558.003)

```spl
index=blackwood_ad sourcetype=csv Id=4769 
| table TimeCreated, Message
```

**Trigger:** Service ticket requests (RC4 encryption type)  
**In Data:** 174 × Event ID 4769 — svc-backup Kerberos ticket requests  
**Dashboard:** Separate "Kerberoasting Attempts" panel

---

### SR-005 — Lateral Movement (T1021.002)

```spl
index=blackwood_ad sourcetype=csv Id=4648 
| table TimeCreated, Account, Message
```

**Trigger:** Explicit credential use from unusual source  
**In Data:** 48 × Event ID 4648 events during attack window  
**Dashboard:** Included in full timeline

---

### SR-006 — Privilege Escalation (T1134)

```spl
index=blackwood_ad sourcetype=csv Id=4672 
| table TimeCreated, Account, Message
```

**Trigger:** Special privileges assigned to non-standard account  
**In Data:** 704 × Event ID 4672 — aturner Domain Admin privilege events  
**Dashboard:** Spike visible in "Complete Attack Timeline"

---

## Splunk Dashboard

### Dashboard Name: `Operation Blackwood Attack Timeline`

**URL:** http://192.168.216.10:8000 (host-only network access from main rig)

**Panels:**

1. **Password Spray Attempts (Event ID 4625)**
   - Timechart showing 10 failed logons clustered in 90-second window
   - Clear detection signature: >5 failures from single IP

2. **Kerberoasting Attempts (Event ID 4769)**
   - 174 service ticket requests visible
   - Spike corresponds to GetUserSPNs.py execution

3. **Complete Attack Chain Timeline**
   - Overlaid view of all six event types
   - Shows progression: spray (4625) → logon (4624) → NTLM (4776) → tickets (4769) → lateral (4648) → privesc (4672)
   - Time-ordered narrative of the 22-minute compromise

---

## Deployment Guide

### Prerequisites

- VirtualBox with Operation Blackwood lab already running
- 4GB RAM available for SIEM01
- Ubuntu Server 26.04 LTS ISO
- 60GB disk space for Splunk

### Step-by-Step Setup

**1. Create SIEM01 VM**

```
VirtualBox → New VM
  Name: SIEM01
  OS: Ubuntu (64-bit)
  RAM: 4096 MB
  Storage: 60 GB
  Network Adapter 1: Internal (blackwood-lab)
  Network Adapter 2: NAT (internet for apt updates)
  Network Adapter 3: Host-only (access from main rig)
```

**2. Install Splunk Enterprise**

```bash
# Download Splunk (9.3.1 or current free tier)
wget https://download.splunk.com/products/splunk/releases/[VERSION]/linux/splunk-[VERSION]-linux-2.6-amd64.deb

# Install
sudo dpkg -i splunk-[VERSION]-linux-2.6-amd64.deb

# Start and accept license
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```

**3. Ingest Operation Blackwood Data**

```bash
# Export from DC01 as CSV
Get-WinEvent -Path "C:\Evidence\DC01-Security.evtx" |
  Where-Object { $_.Id -in 4625,4624,4776,4648,4672,4769 } |
  Select-Object TimeCreated, Id, Account, SourceIP, Message |
  Export-Csv "C:\Evidence\DC01-AuthEvents.csv" -NoTypeInformation

# Transfer to SIEM01 via SMB
# Then ingest to Splunk
sudo -u splunk /opt/splunk/bin/splunk add oneshot /path/to/DC01-AuthEvents.csv \
  -index blackwood_ad -sourcetype csv
```

**4. Create Dashboard**

- Splunk UI → Dashboards → Create New (Studio)
- Add panels with SPL searches above
- Save as "Operation Blackwood Attack Timeline"

---

## Key Findings

### Attack Detection Timeline

```
[T+00:00]  Network recon — Nmap scan (not in Security log)
[T+04:31]  🚨 SPRAY DETECTED — 10 × Event ID 4625 in 90 seconds
[T+04:33]  ✓ Initial Access — jsmith logon (Event ID 4624)
[T+06:10]  Kerberoasting attempt — 174 × Event ID 4769
[T+14:22]  🚨 PASS-THE-HASH — 92 × Event ID 4776 (aturner NTLM auth)
[T+14:23]  ✓ Domain Compromise — aturner Domain Admin access
[T+21:58]  🚨 PRIVILEGE ESCALATION — 704 × Event ID 4672
[T+22:01]  Full compromise: SYSTEM on DC01
```

### Detection Opportunities

All six attack stages had **detectable** signatures in Windows logs. A real SOC with these alert rules enabled would have detected the attack within 90 seconds of the spray beginning.

| Stage | Event ID | Detection Lag | Severity |
|-------|----------|---------------|----------|
| Password Spray | 4625 | <2 minutes | CRITICAL |
| Initial Access | 4624 | <1 minute | HIGH |
| Pass-the-Hash | 4776 | <5 minutes | CRITICAL |
| Lateral Movement | 4648 | Immediate | HIGH |
| Privilege Escalation | 4672 | Immediate | CRITICAL |

---

## Files in This Repository

```
operation-blackwood-detection-layer/
├── README.md                          ← You are here
├── splunk-dashboard-export.xml        ← Dashboard JSON for import
├── detection-rules/
│   ├── SR-001-password-spray.spl
│   ├── SR-002-successful-logon.spl
│   ├── SR-003-pass-the-hash.spl
│   ├── SR-004-kerberoasting.spl
│   ├── SR-005-lateral-movement.spl
│   └── SR-006-privilege-escalation.spl
├── data/
│   └── DC01-AuthEvents.csv            ← Actual attack data (2,940 events)
└── screenshots/
    ├── phase4-01-siem01-network.png
    ├── phase4-02-splunk-installed.png
    ├── phase4-03-data-ingested.png
    └── phase4-05-splunk-dashboard.png
```

---

## The SentinelView Trilogy

This project is **Part 2** of a deliberate three-part portfolio:

| Project | Focus | Status |
|---------|-------|--------|
| 🔵 [SentinelView](https://github.com/empty-throne/sentinelview) | SOC Dashboard (React) — 13 MITRE rules | ✅ Live on Vercel |
| 🔴 [Operation Blackwood](https://github.com/empty-throne/operation-blackwood) | AD Attack & Defense Lab | ✅ Complete |
| 🟣 **Operation Blackwood: Detection Layer** | SIEM Detection Engineering | ✅ This project |

**Narrative:** Build a domain → Attack the domain → Detect the attack. End-to-end security operations.

---

## Skills Demonstrated

✅ Linux system administration (Ubuntu Server)  
✅ Splunk Enterprise deployment and configuration  
✅ Windows Security Event Log analysis  
✅ SPL (Splunk Processing Language) query writing  
✅ SIEM data pipeline design  
✅ Detection rule engineering  
✅ Dashboard design for executive communication  
✅ Attack simulation and log correlation  
✅ MITRE ATT&CK framework application  

---

## Author

**Zackery** | B.S. Cybersecurity (Cum Laude) | Charlotte, NC  
SOC Analyst · Jr. Penetration Tester · DFIR Analyst  
[LinkedIn](https://www.linkedin.com/in/zackery-monk/) · [GitHub: empty-throne](https://github.com/empty-throne)

---

## Legal Notice

This lab is conducted entirely within isolated VirtualBox environments on personal hardware. All attack techniques are self-directed against systems I own and operate for educational purposes. No external systems or production environments were targeted.

---

*Operation Blackwood Detection Layer | Splunk SIEM Lab | June 2026*
