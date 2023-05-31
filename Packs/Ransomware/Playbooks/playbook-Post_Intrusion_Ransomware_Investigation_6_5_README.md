Provides the first step in the investigation of ransomware attacks.
 The playbook requires the ransom note and an example of an encrypted file (<1MB) to try to identify the ransomware and find a recovery tool via the online database.
 You will be guided with further investigation steps throughout the playbook, some of the key features are:

- Encrypted file owner investigation
 - Endpoint forensic investigation
 - Active Directory investigation
 - Timeline of the breach investigation
 - Indicator and account enrichment

Playbook settings and mapping:
 For the full operation of the playbook, the following data should be mapped to the relevant incident fields.
 Username - Usernames (common incident field)
 Hostname - Hostnames (common incident field)





## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Endpoint Enrichment - Generic v2.1
* Active Directory Investigation
* Extract Indicators From File - Generic v2
* Detonate File - Generic
* Isolate Endpoint - Generic
* Account Enrichment - Generic v2.1
* File Enrichment - File reputation
* Block Indicators - Generic v3

### Integrations

* Active Directory Query v2
* Rasterize

### Scripts

* ReadFile

### Commands

* setIndicators
* send-mail
* relatedIncidents
* setIncident
* rasterize-email
* ad-disable-account

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoRemediation | Determines whether to perform auto-isolation and remediation for the infected endpoint and indicators.<br/>Values:<br/>- True<br/>- False. This is the default.  | False | Optional |
| NotificationEmail | The email addresses to notify if there is a possibility of the malware spreading and infecting other endpoints.<br/>Can be a CSV list. |  | Optional |
| EmailBody | The malware notification message content. | During an endpoint investigation in XSOAR, other infected endpoints were found, indicating the malware is spreading in your organization and requires your attention.<br/>To get more information, go to this incident in XSOAR: ${incident.id}. | Optional |
| UserVerification | Possible values: True/False. <br/>Whether to provide user verification for blocking IPs. <br/><br/>False - No prompt will be displayed to the user.<br/>True - The server will ask the user for blocking verification and will display the blocking list. | False | Optional |
| AutoBlockIndicators | Possible values: True/False.  Default: True.<br/>Should the given indicators be automatically blocked, or should the user be given the option to choose?<br/><br/>If set to False - no prompt will appear, and all provided indicators will be blocked automatically.<br/>If set to True - the user will be prompted to select which indicators to block. | True | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Post Intrusion Ransomware Investigation](../doc_files/Post_Intrusion_Ransomware_Investigation.png)
