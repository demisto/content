Use this playbook to investigate and remediate a potential phishing incident. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Detonate File - Generic
* Process Email - Generic
* Email Address Enrichment - Generic v2.1
* O365 - Security And Compliance - Search And Delete
* Extract Indicators From File - Generic v2
* Entity Enrichment - Phishing v2
* Block Indicators - Generic v2
* Calculate Severity - Generic v2
* Search And Delete Emails - Generic

### Integrations
This playbook does not use any integrations.

### Scripts
* AssignAnalystToIncident
* CheckEmailAuthenticity
* Set
* DBotPredictPhishingWords

### Commands
* send-mail
* closeInvestigation
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Enable the "Search and Delete" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Search and Delete" sub-playbook will look for other instances of the email and delete them pending analyst approval. | False | Optional |
| BlockIndicators | Enable the "Block Indicators" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Block Indicators" sub-playbook will block all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | False | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | False | Optional |
| UseO365ForSearchAndDelete | Whether to use the O365 - Security And Compliance - Search And Delete playbook to search and delete the phishing email from all mailboxes. | False | Optional |
| O365DeleteType | The method by which to delete emails using the O365 - Security And Compliance - Search And Delete playbook. Could be "Soft" \(recoverable\), or "Hard" \(unrecoverable\). Leave empty to decide manually for each email incident. |  | Optional |
| O365DeleteTarget | The exchange location. Determines where to search and delete emails searched using O365 playbooks. Use the value "All" to search all mailboxes. If any another input is specified, the email will be searched and deleted only from the mailbox of the person to whom it was sent. Note - searching all mailboxes may take significantly longer to complete. This input is only applicable if the UseO365ForSearchAndDelete input is set to True. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing Investigation - Generic v2](https://raw.githubusercontent.com/demisto/content/a86b72b40e793b86bc9a795c4a5b155517153fe3/Packs/Phishing/doc_files/Phishing_Investigation_-_Generic_v2_-_6_0.png)