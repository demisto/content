Use this playbook to investigate and remediate a potential phishing incident. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Calculate Severity - Generic v2
* Email Address Enrichment - Generic v2.1
* Process Email - Generic
* Extract Indicators From File - Generic v2
* Detonate File - Generic
* Entity Enrichment - Phishing v2
* Search And Delete Emails - Generic
* Block Indicators - Generic v2
* Detect & Manage Phishing Campaigns

### Integrations
This playbook does not use any integrations.

### Scripts
* DBotPredictPhishingWords
* CheckEmailAuthenticity
* Set
* AssignAnalystToIncident

### Commands
* setIncident
* closeInvestigation
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Enable the "Search and Delete" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Search and Delete" sub-playbook will look for other instances of the email and delete them pending analyst approval. | False | Optional |
| BlockIndicators | Enable the "Block Indicators" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Block Indicators" sub-playbook will block all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | False | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | False | Optional |
| SearchAndDeleteIntegration | Determines which product and playbook will be used to search and delete the phishing email from users' inboxes.<br/>Set this to "O365" to use the O365 - Security And Compliance - Search And Delete playbook.<br/>Set this to "EWS" to use the Search And Delete Emails - EWS playbook. | EWS | Optional |
| O365DeleteType | The method by which to delete emails using the O365 - Security And Compliance - Search And Delete playbook. Could be "Soft" \(recoverable\), or "Hard" \(unrecoverable\). Leave empty to decide manually for each email incident.<br/>This is only applicable if the SearchAndDeleteIntegration input is set to O365. | Soft | Optional |
| O365ExchangeLocation | Used only when searching and deleting emails in O365. The exchange location. Determines from where to search and delete emails searched using O365 playbooks. Use the value "All" to search all mailboxes, use "SingleMailbox" to search and delete the email only from the recipient's inbox, or specify "Manual" to decide manually for every incident. Note - searching all mailboxes may take a significant amount of time. This input is only applicable if the SearchAndDeleteIntegration input is set to O365. | SingleMailbox | Optional |
| O365AllowNotFoundSearchLocations | Used only when searching and deleting emails in O365. Whether to include mailboxes other than regular user mailboxes in the compliance search. Default is "false". | true | Optional |
| O365ExchangeLocationExclusion | Used only when searching and deleting emails in O365. Comma-separated list of mailboxes/distribution groups to exclude when you use the value "All" for the O365ExchangeLocation input. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing_Investigation_Generic_v2](../doc_files/Phishing_Investigation_-_Generic_v2_-_6_0.png)