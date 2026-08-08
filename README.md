# SOC Detection & Incident Response Lab

## Overview

Built a simulated Security Operations Center environment using Microsoft Azure and Microsoft Sentinel to collect Windows security telemetry, investigate suspicious activity, develop detection logic, and document incident response procedures.

## Architecture

Windows Endpoint
↓
Azure Monitor Agent
↓
Log Analytics
↓
Microsoft Sentinel
↓
KQL Detection
↓
Alert
↓
Investigation
↓
Incident Response

## Technologies

* Microsoft Azure
* Microsoft Sentinel
* Log Analytics
* Azure Monitor Agent
* Windows Security Events
* Sysmon
* KQL
* PowerShell
* VirusTotal
* MITRE ATT&CK

## Investigations

### 1. Brute Force / Failed Authentication

Investigated Windows Event ID 4625 events and developed a KQL detection for repeated failed authentication attempts.

### 2. PowerShell Activity

Analyzed Sysmon process creation telemetry to identify PowerShell execution and mapped the activity to MITRE ATT&CK T1059.001.

### 3. File Hash Investigation

Generated a SHA256 hash and performed threat intelligence validation using VirusTotal.

## Skills Demonstrated

* SIEM monitoring
* KQL
* Windows event analysis
* Endpoint telemetry
* Threat detection
* Incident investigation
* MITRE ATT&CK mapping
* Threat intelligence
* Incident response
