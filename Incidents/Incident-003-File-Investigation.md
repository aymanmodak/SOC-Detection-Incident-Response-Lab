# Incident 003 — File Hash Investigation

## Overview

This investigation focused on practicing a basic file-hash threat intelligence workflow.

I created a harmless text file called `SOC-Test.txt` specifically for this lab. The file did not contain personal or sensitive information.

The goal was to calculate the file's SHA256 hash and check the hash against VirusTotal.

## File Investigation

**File:** SOC-Test.txt
**Hash Algorithm:** SHA256
**Threat Intelligence Source:** VirusTotal

## Creating the Hash

I used PowerShell to calculate the SHA256 hash:

```powershell
Get-FileHash .\SOC-Test.txt -Algorithm SHA256
```

This generated a SHA256 hash that could be used as a file indicator for further investigation.

## VirusTotal Investigation

I searched the SHA256 hash on VirusTotal instead of uploading the file.

No existing VirusTotal analysis was found for the SHA256 hash.

Since I created the file myself for the lab, this result was expected.

## Investigation Workflow

The investigation followed this basic threat-intelligence workflow:

```text
File
  ↓
SHA256 Hash
  ↓
VirusTotal
  ↓
Reputation Check
```

A known malicious hash could be searched across an organization's endpoints to determine whether the same file exists elsewhere.

## Findings

The hash did not have an existing VirusTotal analysis.

This did not indicate malicious activity because the file was created specifically for the lab and was not an actual malware sample.

The exercise demonstrated how a file can be converted into a SHA256 indicator and checked against a threat-intelligence service without uploading the file itself.

## Recommended Response

In a real investigation, I would:

* Identify where the file was found.
* Determine which user or process created the file.
* Calculate its SHA256 hash.
* Search the hash using available threat-intelligence sources.
* Check whether the same hash appears on other endpoints.
* Review related process and network activity.
* Isolate the affected endpoint if malicious activity is confirmed.
* Escalate the incident when appropriate.

## Conclusion

This investigation demonstrated a basic threat-intelligence workflow using SHA256 hashing and VirusTotal.

The exercise also showed that a hash can be used as an indicator during an investigation without needing to upload the original file to a threat-intelligence service.

