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

* Account Enrichment - Generic v2.1
* Detonate File - Generic
* Isolate Endpoint - Generic
* Block Indicators - Generic v2
* Active Directory Investigation
* Endpoint Enrichment - Generic v2.1
* Extract Indicators From File - Generic v2
* File Enrichment - File reputation

### Integrations

* Active Directory Query v2
* Rasterize

### Scripts

* ReadFile

### Commands

* setIndicators
* send-mail
* setIncident
* rasterize-email
* relatedIncidents
* ad-disable-account

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoRemediation | Determines whether to perform auto-isolation and remediation for the infected endpoint and indicators.<br/>Values:<br/>- True<br/>- False. This is the default.  | False | Optional |
| NotificationEmail | The email addresses to notify if there is a possibility of the malware spreading and infecting other endpoints.<br/>Can be a CSV list. |  | Optional |
| EmailBody | The malware notification message content. | During an endpoint investigation in XSOAR, other infected endpoints were found, indicating the malware is spreading in your organization and requires your attention.<br/>To get more information, go to this incident in XSOAR: ${incident.id}. | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Post Intrusion Ransomware Investigation](../doc_files/Post_Intrusion_Ransomware_Investigation.png)
