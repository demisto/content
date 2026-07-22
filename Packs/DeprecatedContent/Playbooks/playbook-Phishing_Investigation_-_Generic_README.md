DEPRECATED. Use "Phishing Investigation - Generic v2" playbook instead. Investigates and remediates potential phishing incidents. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Process Email - Generic
* Email Address Enrichment - Generic
* Search And Delete Emails - Generic
* Detonate File - Generic
* Extract Indicators From File - Generic
* Entity Enrichment - Generic
* Block Indicators - Generic

### Integrations
* Builtin

### Scripts
* AssignAnalystToIncident
* SendEmail
* Set

### Commands
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |  
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Enable the `Search and Delete` capability. Can be, "True" or "False". In the case of a malicious email, the `Search and Delete` sub-playbook will look for other instances of the email and delete them pending analyst approval. | False | Optional |
| BlockIndicators | Enable the `Block Indicators` capability. Can be, "True" or "False". In the case of a malicious email, the `Block Indicators` sub-playbook will block all malicious indicators in the relevant integrations. | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing_Investigation_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Phishing_Investigation_Generic.png)
