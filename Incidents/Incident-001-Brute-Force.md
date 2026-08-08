# Incident 001 — Failed Login Attempts

## Overview

This investigation focused on failed Windows authentication attempts collected by Microsoft Sentinel. Windows Security Event ID 4625 is generated when a login attempt fails.

The purpose of the investigation was to confirm that Sentinel was collecting the events and determine what information was available for investigating repeated authentication failures.

**Host:** SOC-Windows01
**Event ID:** 4625
**MITRE ATT&CK:** T1110 – Brute Force

## Investigation

I used the following KQL query to review recent failed authentication events:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress
| order by TimeGenerated desc
| take 20
```

The results showed the event time, computer, account involved, and IP address when that information was available.

I also used a second query to summarize the number of failed attempts by account:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account
| order by FailedAttempts desc
```

I then checked for successful authentication events using Event ID 4624:

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Computer, Account, IpAddress
| order by TimeGenerated desc
| take 20
```

## Findings

The failed login events confirmed that Windows authentication failures were being successfully collected by Microsoft Sentinel.

The activity occurred within my own lab environment and was generated as part of testing rather than representing a real attack.

When investigating this type of activity in a production environment, repeated failures against a single account would warrant additional investigation, especially if a successful login occurred shortly afterward.

## MITRE ATT&CK Mapping

**T1110 – Brute Force**

Repeated authentication failures can be associated with brute-force activity when an attacker attempts to gain access by repeatedly guessing credentials.

## Recommended Response

If this activity occurred on a production system, I would:

* Check with the user to determine whether the login attempts were expected.
* Investigate the source IP address.
* Check for successful authentication after the failed attempts.
* Review MFA activity.
* Reset the password if account compromise was suspected.
* Revoke active sessions if necessary.
* Escalate the incident if the activity appeared malicious.

## Conclusion

The investigation confirmed that Microsoft Sentinel was receiving Windows Event ID 4625 data and that the events could be queried using KQL. Checking both failed and successful authentication events provides additional context when determining whether authentication activity is suspicious.

