Returns 'yes' if integration brand is available. Otherwise returns 'no'.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | infra, Condition |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
Sample usage of this script can be found in the following playbooks and scripts.

* Calculate Severity Highest DBotScore For Egress Network Traffic - GreyNoise
* Crowdstrike Falcon - Isolate Endpoint
* Crowdstrike Falcon - Unisolate Endpoint
* FireMon Pre Change Assessment
* Get Original Email - Microsoft Graph Mail
* MITRE ATT&CK CoA - T1204 - User Execution
* Microsoft 365 Defender - Emails Indicators Hunt
* Palo Alto Networks BPA - Submit Scan
* Phishing - Machine Learning Analysis
* Prisma Cloud Remediation - AWS EC2 Security Group Misconfiguration

<!--
Used In: list was truncated. Full list commented out for reference:

MITRE ATT&CK CoA - T1027 - Obfuscated Files or Information
Rapid7 InsightIDR - Traffic Indicators Hunting
Get RaDark Detailed Items
CVE-2021-44228 - Log4j RCE
Prepare your CTF
Incremental Export to Cisco ISE - PANW IoT 3rd Party Integration
appNovi-MAC-Address-Lookup
Recorded Future Identity - Identity Found (incident)
Cortex Data Lake - Indicators Hunting
MITRE ATT&CK CoA - T1569.002 - Service Execution
Block Endpoint - Carbon Black Response V2
Microsoft Defender For Endpoint - Unisolate Endpoint
Prisma Cloud Remediation - Azure Storage Blob Misconfiguration
Incremental Export Devices to ServiceNow - PANW IoT 3rd Party Integration
RDP Bitmap Cache - Detect and Hunt
BlockIP
Tidy - Test
Prisma Cloud Remediation - AWS EC2 Instance Misconfiguration v2
MITRE ATT&CK CoA - T1071 - Application Layer Protocol
MITRE ATT&CK CoA - T1003 - OS Credential Dumping
Block Endpoint - Carbon Black Response V2.1
Unisolate Endpoint - Cybereason
PAN-OS - Extract IPs From Traffic Logs To Sinkhole
FireEye HX - File Indicators Hunting
Block Account - Generic v2
Create Jira Issue
MITRE ATT&CK CoA - T1135 - Network Share Discovery
MITRE ATT&CK CoA - T1083 - File and Directory Discovery
Cyren Inbox Security Default
Get User Devices by Email Address - Generic
FireEye ETP - Indicators Hunting
FireEye HX - Isolate Endpoint
MITRE ATT&CK CoA - T1133 - External Remote Services
FireEye HX - Execution Flow Indicators Hunting
Symantec block Email
Bulk Export to SIEM - PANW IoT 3rd Party Integration
Rapid7 InsightIDR - File Indicators Hunting
Endpoint Enrichment By EntityId - XM Cyber
Set up a Shift handover meeting
Prisma Cloud Remediation - Azure SQL Misconfiguration v2
Prisma Cloud Remediation - Azure Network Security Group Misconfiguration
Detect & Manage Phishing Campaigns
Rapid7 InsightIDR - HTTP Requests Indicators Hunting
MITRE ATT&CK CoA - T1518 - Software Discovery
WhisperGate and HermeticWiper & CVE-2021-32648
SandboxDetonateFile
PS Remote Get File Sample From Path
Get Original Email - Gmail v2
Block Email - Generic v2
Cloud Threat Hunting - Persistence
Microsoft 365 Defender - Emails Indicators Hunt
PAN-OS - Enforce Anti-Virus Best Practices Profile
MITRE ATT&CK CoA - T1547.001 - Registry Run Keys Startup Folder
Get Code42 Employee Information
Export Single Vulnerability to ServiceNow - PANW IoT 3rd Party Integration
FireMon Create Policy Planner Ticket
playbook7
Policy Optimizer - Manage Unused Rules
MITRE ATT&CK CoA - T1543.003 - Windows Service
Wildfire Detonate and Analyze File
Endpoint Enrichment - Generic v2.1
Detonate URL - VMRay
CVE-2022-26134 - Confluence RCE
MDE - True Positive Incident Handling
79b5d8a6-2636-480c-8e1c-a3ab2e58ffb5
Quarantine Device in Cisco ISE - PANW IoT 3rd Party Integration
Mimecast - Block Sender Email
Abuse Inbox Management Protection
CVE-2022-30190 - MSDT RCE
PAN-OS - Configure DNS Sinkhole
Calculate Severity Highest DBotScore For Egress Network Traffic - GreyNoise
Druva-Ransomware-Response
Online Brand Protection Detect and Respond
QRadar - Get Offense Logs
Saas Security - Incident Processor
Get Original Email - EWS v2
Get User Devices by Username - Generic
Handle Darktrace Model Breach
MITRE ATT&CK CoA - T1059.001 - PowerShell
Endpoint Enrichment By IP - XM Cyber
PS-Remote Get Registry
CloudConvert - Convert File
Export Single Asset to SIEM - PANW IoT 3rd Party Integration
MITRE ATT&CK CoA - T1204 - User Execution
Get Original Email - Microsoft Graph Mail
Prisma Cloud Remediation - Azure SQL Misconfiguration
Cortex XDR - True Positive Incident Handling
Code42 Add Departing Employee From Ticketing System v2
FireMon Pre Change Assessment
Palo Alto Networks BPA - Submit Scan
Reco Google Drive Automation
Block IP - Generic v3
Cisco FirePower- Append network group object
Prisma Cloud Remediation - Azure AKS Misconfiguration v2
ZTAP Alert
Microsoft Defender For Endpoint - Isolate Endpoint
FireEyeDetonateFile
Prisma Cloud Remediation - Azure SQL Database Misconfiguration
FireEye HX - Traffic Indicators Hunting
Code42 Copy File To Ticketing System v2
Mitre Attack - Extract Technique Information From ID
Bulk Export to Cisco ISE - PANW IoT 3rd Party Integration
Mimecast - Block Sender Domain
CVE-2022-3786 & CVE-2022-3602 - OpenSSL X.509 Buffer Overflows
Prisma Cloud Remediation - Azure AKS Cluster Misconfiguration
Prisma Cloud Remediation - Azure Storage Misconfiguration v2
Un-quarantine Device in Cisco ISE - PANW IoT 3rd Party Integration
Prisma Cloud Remediation - AWS EC2 Security Group Misconfiguration
Calculate Severity Highest DBotScore For Ingress Network Traffic - GreyNoise
File Enrichment - VMRay
Cortex XDR - Unisolate Endpoint
MITRE ATT&CK CoA - T1059 - Command and Scripting Interpreter
MITRE ATT&CK CoA - T1562.001 - Disable or Modify Tools
CrowdStrike Falcon - True Positive Incident Handling
Detonate and Analyze File - JoeSecurity
MITRE ATT&CK CoA - T1566 - Phishing
DLP - Get Approval
MITRE ATT&CK CoA - T1068 - Exploitation for Privilege Escalation
CrowdStrike Falcon Intelligence Sandbox Detonate and Analyze File
CrowdStrike Falcon - Search Endpoints By Hash
PAN-OS - Enforce File Blocking Best Practices Profile
Prisma Cloud Remediation - Azure Network Misconfiguration
Search For Hash In Sandbox - Generic
Phishing - Machine Learning Analysis
Bulk Export Devices to ServiceNow - PANW IoT 3rd Party Integration
Prisma Cloud Remediation - Azure Storage Misconfiguration
Crowdstrike Falcon - Unisolate Endpoint
CVE-2022-26134 - Confluence RCE
Ataya - Securely logging device access to network
SafeNet Trusted Access - Add to Unusual Activity Group
Incremental Export to SIEM - PANW IoT 3rd Party Integration
Containment Plan - Clear User Sessions
Uncover Unknown Malware Using SSDeep
Microsoft 365 Defender - Get Email URL Clicks
CloudConvert-test
DLP - User Message App Check
Autofocus - Hunting And Threat Detection
Endpoint Enrichment By Hostname - XM Cyber
Get the binary file from Carbon Black by its MD5 hash
Detonate and Analyze File - Generic
Prisma Cloud Remediation - AWS EC2 Instance Misconfiguration
MITRE ATT&CK CoA - T1005 - Data from Local System
Trend Micro CAS - Indicators Hunting
Possible External RDP Brute-Force
SOCRadar Incident
Ransomware Exposure - RiskSense
Policy Optimizer - Manage Rules with Unused Applications
Carbon Black Response - Unisolate Endpoint
Export Single Alert to ServiceNow - PANW IoT 3rd Party Integration
FireEye HX - Unisolate Endpoint
TestEditServerConfig
CVE Exposure - RiskSense
Pull Request Creation - Generic
Prisma Cloud Remediation - Azure AKS Misconfiguration
Crowdstrike Falcon - Isolate Endpoint
Rapid7 InsightIDR - Execution Flow Indicators Hunting
Policy Optimizer - Add Applications to Policy Rules
MITRE ATT&CK CoA - T1547 - Boot or Logon Autostart Execution
MITRE ATT&CK CoA - T1057 - Process Discovery
MITRE ATT&CK CoA - T1566.001 - Spear-Phishing Attachment
PS-Remote Get Network Traffic
PS-Remote Get MFT
Indicator Enrichment - Qintel
CVE-2021-44228 - Log4j RCE
Spring Core and Cloud Function SpEL RCEs
Account Enrichment - Generic v2.1
SafeNet Trusted Access - Terminate User SSO Sessions
Cortex XDR - Possible External RDP Brute-Force
MITRE ATT&CK CoA - T1105 - Ingress tool transfer
File Enrichment - RST Threat Feed
Prisma Cloud Remediation - Azure Network Misconfiguration v2
Policy Optimizer - Manage Port Based Rules
MITRE ATT&CK CoA - T1021.001 - Remote Desktop Protocol
MITRE ATT&CK CoA - T1560.001 - Archive via Utility
Block URL - Generic v2
MITRE ATT&CK CoA - T1082 - System Information Discovery
Get host forensics - Generic
Eradication Plan - Reset Password
WhisperGate & CVE-2021-32648
MITRE ATT&CK CoA - T1564.004 - NTFS File Attributes
 -->

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| brandname | Integration's brand name to query. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| brandInstances | List of the instances for the given brands. | Unknown |
