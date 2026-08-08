# Incident 002 — PowerShell Process Investigation

## Overview

This investigation focused on identifying PowerShell process creation activity in Microsoft Sentinel.

The goal was to determine whether PowerShell activity was being collected, identify the user and parent process, and document the available information.

**Host:** SOC-Windows01
**Event ID:** 4688
**MITRE ATT&CK:** T1059.001 – PowerShell

## Investigation

I first tested the SecurityEvent table for Windows process creation events:

```kql
SecurityEvent
| where EventID == 4688
| take 20
```

The query returned process creation events, so I used the SecurityEvent table for the investigation.

I then searched specifically for PowerShell processes:

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell.exe"
| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine
| order by TimeGenerated desc
```

## Findings

One of the PowerShell events showed the following:

**Computer:** SOC-Windows01

**User:** SOC-Windows01\aymanmodak

**Process:**

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Parent process:**

```text
C:\Windows\explorer.exe
```

**Time:** 8/8/2026 3:57:49 AM

The event showed that PowerShell was running under my lab user account and that Windows Explorer was the parent process.

The command-line field was not populated in the data collected during the investigation, so I did not make assumptions about what the PowerShell process was doing.

## PowerShell Test

To generate known PowerShell activity, I ran the following command on the Windows VM:

```powershell
Write-Host "SOC Lab PowerShell Test By Ayman Modak"
```

The PowerShell window returned:

```text
SOC Lab PowerShell Test By Ayman Modak
```

I was then able to identify the PowerShell process creation event in Microsoft Sentinel.

The activity was expected because I generated it myself as part of the lab. If the same type of activity appeared on a real workstation without an expected reason, I would investigate it further rather than immediately assuming it was malicious.

## MITRE ATT&CK Mapping

**T1059.001 – PowerShell**

PowerShell is commonly used for administrative tasks, but attackers can also use it to execute commands, download files, perform reconnaissance, or establish persistence.

## Recommended Investigation

If the PowerShell execution appeared suspicious, I would investigate:

* Who started PowerShell
* The parent process
* The command line
* Network connections
* Files created by PowerShell
* Other processes running around the same time
* Whether PowerShell was being used for persistence

If malicious activity was confirmed, I would consider isolating the computer and escalating the incident.

## Conclusion

The investigation confirmed that Windows process creation events were being collected in Microsoft Sentinel and could be used to identify PowerShell activity.

The investigation also showed the importance of having detailed endpoint telemetry. The available Event ID 4688 data included the process, user, parent process, and timestamp, but command-line information was not available for this event.

