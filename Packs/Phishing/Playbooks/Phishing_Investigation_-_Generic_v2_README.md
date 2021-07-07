Use this playbook to investigate and remediate a potential phishing incident. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Indicators - Generic v2
* File Enrichment - Generic v2
* Search And Delete Emails - Generic
* Email Address Enrichment - Generic v2.1
* Process Microsoft's Anti-Spam Headers
* Calculate Severity - Generic v2
* URL Enrichment - Generic v2
* Domain Enrichment - Generic v2
* IP Enrichment - External - Generic v2
* Process Email - Generic
* Extract Indicators From File - Generic v2
* Detonate File - Generic

### Integrations
This playbook does not use any integrations.

### Scripts
* AssignAnalystToIncident
* DBotPredictPhishingWords
* CheckEmailAuthenticity
* Set

### Commands
* setIncident
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Enable the "Search and Delete" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Search and Delete" sub-playbook will look for other instances of the email and delete them pending analyst approval. | False | Optional |
| BlockIndicators | Enable the "Block Indicators" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Block Indicators" sub-playbook will block all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | True | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | false | Optional |
| CheckMicrosoftHeaders | Check Microsoft's headers fro BCL/PCL/SCL scores and set the "Severity" and "Email Classification" accordingly. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing Investigation - Generic v2](Insert the link to your image here)