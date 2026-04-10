# Splunk SOC Security Monitoring Dashboard

A hands-on Security Operations Center (SOC) project built in Splunk Enterprise, demonstrating log ingestion, SPL-based threat detection, correlation rule configuration, and interactive dashboard development for real-time security event monitoring.

---

## Project Overview

This project simulates a SOC analyst workflow using real-world attack logs. Five datasets covering privilege escalation, credential access, NTLM relay attacks, and RDP activity were ingested into Splunk. Ten SPL detection queries were developed and visualised across a multi-panel SOC dashboard.

---

## Datasets Ingested

| Dataset | Attack Technique | Events |
|---|---|---|
| JuicyPotato | Privilege escalation (token impersonation) | Windows Event Logs |
| Invoke_TokenDuplication / UAC_Bypass | Privilege escalation via token duplication | Windows Event Logs |
| NTLM2SelfRelay | NTLM relay attack | Windows Event Logs |
| DFIR_RDP_Client_TimeZone_RdpCoreTs_104 | RDP client activity (forensic artifact) | RDP Operational Logs |
| CA_hashdump_4663_4656_lsass_access | Credential dumping via LSASS access | Windows Security Logs |

**Total events ingested:** 39 (across all sources, all-time range)

---

## Detection Queries (SPL)

Ten detection queries were developed covering the following threat categories:

- Privilege Escalation (Event ID 4672)
- Failed Login / Brute Force (Event ID 4625)
- Successful Logon (Event ID 4624)
- Anonymous Logon (Event ID 4624 + ANONYMOUS keyword)
- Logoff Events (Event ID 4634)
- Audit Log Cleared (Event IDs 1102, 104)
- Credential Access / LSASS (Event IDs 4656, 4663)
- Process Execution (Event ID 4688)
- Sysmon Activity (Event ID 11)
- Top Computers by Event Count

### Example Query — Threat Type Distribution

```spl
index=windows_logs earliest=-7d latest=now
| eval raw=_raw
| eval ThreatType=case(
    like(raw,"%4672%"), "Privilege Escalation",
    like(raw,"%4625%"), "Failed Login",
    like(raw,"%4624%") AND like(raw,"%ANONYMOUS%"), "Anonymous Logon",
    like(raw,"%4624%"), "Successful Logon",
    like(raw,"%4634%"), "Logoff",
    like(raw,"%1102%") OR like(raw,"%104%"), "Audit Log Cleared",
    like(raw,"%4656%") OR like(raw,"%4663%"), "Credential Access",
    like(raw,"%4688%"), "Process Execution",
    like(raw,"%11%"), "Sysmon Activity",
    true(), "Other"
)
| stats count by ThreatType
| sort - count
```

---

## Dashboard Panels

The SOC Security Monitoring Dashboard includes six panels for real-time security event monitoring:

| Panel | Visualisation | Purpose |
|---|---|---|
| Threat Type Distribution | Bar chart | Overview of event categories across all logs |
| Events Over Time | Line chart | Timeline of security event volume |
| Privilege Escalation Events | Table | Detailed view of 4672 events |
| Credential Dumping Alerts | Table | LSASS access events (4656, 4663) |
| Anonymous Logon Alerts | Table | Anonymous logon detections |
| Top Computers by Event Count | Bar chart | Most active hosts by event volume |

**Dashboard subtitle:** Real-time detection of privilege escalation, credential dumping and unauthorised access

---

## Tools & Technologies

- **Splunk Enterprise** — log ingestion, SPL querying, dashboard development
- **SPL (Search Processing Language)** — detection logic and data transformation
- **Windows Event Logs** — primary data source (Security, System, Sysmon channels)
- **DFIR datasets** — real-world attack simulation logs

---

## Key Skills Demonstrated

- Ingesting and parsing multi-source CSV log data in Splunk
- Writing SPL queries using `eval`, `case`, `stats`, `sort`, and time modifiers
- Classifying Windows Event IDs to map to MITRE ATT&CK-aligned threat categories
- Building multi-panel interactive dashboards in Splunk Classic UI
- Correlating RDP, credential access, and privilege escalation events across datasets

---

## Project Structure

```
splunk-soc-dashboard/
├── README.md
├── queries/
│   ├── threat_type_distribution.spl
│   ├── events_over_time.spl
│   ├── privilege_escalation.spl
│   ├── credential_dumping.spl
│   ├── anonymous_logon.spl
│   └── top_computers.spl
├── screenshots/
│   ├── dashboard_overview.png
│   ├── threat_distribution_chart.png
│   └── events_over_time.png
└── dashboard_xml/
    └── soc_dashboard.xml
```

---
## Author

**Pranjali Saini**  
MSc Forensic Science — National Forensic Sciences University (NFSU), Gandhinagar  
Specialisation: Cyberforensic | SOC Analysis | Digital Forensics
