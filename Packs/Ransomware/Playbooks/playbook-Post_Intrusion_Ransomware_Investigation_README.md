Post Intrusion Ransomware Investigation Playbook provides a baseline for investigating Ransomware incidents.
In such a complex incident, knowing is half the battle.
This playbook will help you better understand your position and exposure against the threat actor group by collecting the needed information from your environment, performing the required investigation steps, containing the incident, and visualizing the data with its custom Post Intrusion Ransomware Investigation incident layout.
The main features of this semi-automated playbook are:
 - Automated Users and Hosts data enrichment.
 - Automated endpoint isolation and user revocation.
 - Guidance to retrieve the necessary files to identify the ransomware strain and data enrichment.
 - Extract indicators from the ransomware note, including Cryptocurrency addresses and Onion URLs.
 - Guidance to further Recommended investigation steps such as Endpoint Forensics, searching for more infected endpoints, Users investigation.
 -  Active Directory forensics. 
 - Automated block for malicious indicators 

Playbook Settings and Mapping:
For the operation of the playbook, the following data should be mapped to the relevant incident field.
Username - Users (Incident field)
Hostname  -Hosts (Incident field)





## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Isolate Endpoint - Generic
* Detonate File - Generic
* Account Enrichment - Generic v2.1
* file_enrichment_-_file_reputation
* Block Indicators - Generic v2
* Endpoint Enrichment - Generic v2.1
* f8c30530-5ac8-416e-83d0-d7198a5ae50f
* Extract Indicators From File - Generic v2

### Integrations
* Rasterize
* Active Directory Query v2

### Scripts
This playbook does not use any scripts.

### Commands
* rasterize-email
* relatedIncidents
* setIndicators
* setIncident
* send-mail
* ad-disable-account

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoIsolation | This input determines if to perform auto-isolation for the infected endpoint.<br/>Values:<br/>- True<br/>- False  | False | Optional |
| NotificationEmail | The Email address to notify if there is a possibility of the malware spreading and infecting other endpoints.<br/>Can be a CSV list. |  | Optional |
| EmailBody | The notification message content. | During an endpoint investigation in XSOAR, other infected endpoints were found, indicating the malware is spreading in your organization and requires your attention.<br/>To get more information, go to this incident in Demisto: ${incident.id} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Post Intrusion Ransomware Investigation](Insert the link to your image here)