Provides the first step in the investigation of ransomware attacks.
 The playbook requires the ransom note and an example of an encrypted file (<1MB) to try to identify the ransomware and find a recovery tool via the online database.
 You will be guided with further investigation steps throughout the playbook, some of the key features are:

- Encrypted file owner investigation
 - Endpoint forensic investigation
 - Active Directory investigation
 - Timeline of the breach investigation
 - Indicator and account enrichment

Playbook settings and mapping:
 For the operation of the playbook, the following data should be mapped to the relevant incident fields:
 Username - Users (incident field)
 Hostname - Hosts (incident field)





## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Extract Indicators From File - Generic v2
* Endpoint Enrichment - Generic v2.1
* Isolate Endpoint - Generic
* Active Directory Investigation
* file_enrichment_-_file_reputation
* Account Enrichment - Generic v2.1
* Block Indicators - Generic v2
* Detonate File - Generic

### Integrations
* Rasterize
* Active Directory Query v2

### Scripts
This playbook does not use any scripts.

### Commands
* relatedIncidents
* rasterize-email
* setIncident
* setIndicators
* send-mail
* ad-disable-account

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoIsolation | Determines whether to perform auto-isolation for the infected endpoint.<br/>Values:<br/>- True<br/>- False. This is the default.  | False | Optional |
| NotificationEmail | The email addresses to notify if there is a possibility of the malware spreading and infecting other endpoints.<br/>Can be a CSV list. |  | Optional |
| EmailBody | The malware notification message content. | During an endpoint investigation in XSOAR, other infected endpoints were found, indicating the malware is spreading in your organization and requires your attention.<br/>To get more information, go to this incident in XSOAR: ${incident.id}. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Post Intrusion Ransomware Investigation v2](https://raw.githubusercontent.com/demisto/content/ee0c80f7977b1ae2701f5499859a1b70f17cb68b/Packs/Ransomware/doc_files/Post_Intrusion_Ransomware_Investigation.png)