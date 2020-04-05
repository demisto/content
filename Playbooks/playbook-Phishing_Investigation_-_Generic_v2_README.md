Investigates and remediates potential phishing incidents. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Detonate File - Generic
* File Enrichment - Generic v2
* Extract Indicators From File - Generic v2
* IP Enrichment - External - Generic v2
* Email Address Enrichment - Generic v2.1
* URL Enrichment - Generic v2
* Search And Delete Emails - Generic
* Domain Enrichment - Generic v2
* Block Indicators - Generic
* Process Email - Generic
* Calculate Severity - Generic v2

### Integrations
* Builtin

### Scripts
* SendEmail
* CheckEmailAuthenticity
* Set
* AssignAnalystToIncident
* DBotPredictPhishingWords

### Commands
* setIncident
* closeInvestigation
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Enable the `Search and Delete` capabilit. Can be either "True" or "False". In the case of a malicious email, the `Search and Delete` sub-playbook will look for other instances of the email and delete them pending analyst approval. | False | Optional |
| BlockIndicators | Enable the `Block Indicators` capability. Can be either "True" or "False". In case of a malicious email, the `Block Indicators` sub-playbook will block all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Phishing_Investigation_Generic_v2.png)
