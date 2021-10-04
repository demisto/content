Set a value in context under the key you entered.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |

## Used In
---
Sample usage of this script can be found in the following playbooks and scripts.
* Arcsight - Get events related to the Case
* Detonate File - BitDam
* Endace Search Archive Download PCAP v2
* Illinois - Breach Notification
* Illusive - Incident Escalation
* Malware Investigation - Generic - Setup
* QRadar - Get offense correlations v2
* QRadar Indicator Hunting
* SafeBreach - Create Incidents per Insight and Associate Indicators
* Wait Until Datetime

<!--
Used In: list was truncated. Full list commented out for reference:

ATD - Detonate File
Accessdata: Dump memory for malicious process
Active Directory - Get User Manager Details
Allow IP - Okta Zone
Arcsight - Get events related to the Case
Calculate Severity - 3rd-party integrations
Calculate Severity - Critical Assets v2
Calculate Severity - Critical assets
Calculate Severity - Generic v2
Calculate Severity - Indicators DBotScore
Calculate Severity - Standard
Calculate Severity By Email Authenticity
Calculate Severity By Highest DBotScore
California - Breach Notification
Cortex XDR incident handling v2
CrowdStrike Falcon Sandbox - Detonate file
Darkfeed Threat hunting-research
Detonate File - BitDam
Detonate File - CrowdStrike Falcon X
Detonate File - FireEye AX
Detonate File - JoeSecurity
Detonate File - Lastline
Detonate File - Lastline v2
Detonate File - SNDBOX
Detonate File - Symantec Blue Coat Content and Malware Analysis Beta
Detonate File - ThreatGrid
Detonate File - ThreatStream
Detonate File - Trend Micro Deep Discovery Analyzer Beta
Detonate File - VirusTotal
Detonate URL - JoeSecurity
Detonate URL - McAfee ATD
Employee Offboarding - Gather User Information
Employee Status Survey
Endace Search Archive Download PCAP v2
Endpoint Enrichment - Cylance Protect v2
Extract Indicators From File - Generic
Extract Indicators From File - Generic v2
Get Original Email - EWS
Get Original Email - Gmail
IP Whitelist - AWS Security Group
Illinois - Breach Notification
Illusive - Incident Escalation
Impossible Traveler
Logz.io Indicator Hunting
Malware Investigation - Generic - Setup
New York - Breach Notification
PAN-OS Log Forwarding Setup And Configuration
PANW - Hunting and threat detection by indicator type
PCAP File Carving
PII Check - Breach Notification
Phishing Investigation - Generic
Phishing Investigation - Generic v2
Phishing Playbook - Automated
Prisma Cloud Remediation - GCP VPC Network Firewall Misconfiguration
Process Email
Process Email - Core
Process Email - EWS
Process Email - Generic
Process Survey Response
QRadar - Get offense correlations v2
QRadar Indicator Hunting
QRadar Indicator Hunting V2
Residents Notification - Breach Notification
SafeBreach - Compare and Validate Insight Indicators
SafeBreach - Create Incidents per Insight and Associate Indicators
SafeBreach - Process Non-Behavioral Insights Feed
Search Endpoints By Hash - Carbon Black Protection
Search Endpoints By Hash - Carbon Black Response
Splunk Indicator Hunting
TIM - Process Domain Age With Whois
TIM - Process Domain Registrant With Whois
Vulnerability Management - Qualys (Job)
Wait Until Datetime
WildFire - Detonate file
 -->

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to set. Can be a full path such as "Key.ID". If using append=true can also use a DT selector such as "Data\(val.ID == obj.ID\)". |
| value | The value to set to the key. Can be an array (e.g. ["192.168.1.1","192.168.1.2"]) or JSON (e.g. {"key":"value"}). |
| append | If false then the context key will be overwritten. If set to true then the script will append to existing context key. |
| stringify | Whether the argument should be saved as a string. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!Set key="Data(val.ID == obj.ID)" value=`{"ID": "test_id", "Value": "test_val2"}` append="true"```

## Context Example
```json
{
    "Data": {
        "ID": "test_id",
        "Value": "test_val2"
    }
}
```

## Human Readable Output

>Key Data(val.ID == obj.ID) set
