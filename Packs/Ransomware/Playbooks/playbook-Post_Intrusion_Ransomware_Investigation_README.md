Note: This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.

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
Username - Usernames (common incident field)
Hostname - Hostnames (common incident field)



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
* Cryptocurrency

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
![Post Intrusion Ransomware Investigation](https://raw.githubusercontent.com/demisto/content/46d29932562518dcbb7be50ef75d5af45a82beb9/Packs/Ransomware/doc_files/Post_Intrusion_Ransomware_Investigation.png)