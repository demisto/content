Use this playbook to investigate and remediate a potential phishing incident produced by either your Email Security Gateway or SIEM product.

One of the playbook's main tasks is retrieving the original email file from your Email Security Gateway or Email Service Provider.

The playbook response tasks take under consideration the initial severity, hunting results and also the existence of similar phishing incidents in XSOAR. 

No action will be taken without an initial approval given by the analyst using the playbook inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Search And Delete Emails - Generic v2
* Phishing Alerts - Check Severity
* Detonate File - Generic
* Threat Hunting - Generic
* Extract Indicators From File - Generic v2
* Process Email - Generic v2
* Email Headers Check - Generic
* Block Indicators - Generic v2
* Entity Enrichment - Phishing v2

### Integrations
This playbook does not use any integrations.

### Scripts
* SearchIncidentsV2

### Commands
* linkIncidents
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Enable the "Search and Delete" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Search and Delete" sub-playbook will look for other instances of the email and delete them pending analyst approval. | True | Optional |
| BlockIndicators | Enable the "Block Indicators" capability \(can be either "True" or "False"\).<br/>In case of a malicious email, the "Block Indicators" sub-playbook will block all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | True | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | False | Optional |
| SearchAndDeleteIntegration | Determines which product and playbook will be used to search and delete the phishing email from users' inboxes.<br/>Set this to "O365" to use the O365 - Security And Compliance - Search And Delete playbook.<br/>Set this to "EWS" to use the Search And Delete Emails - EWS playbook. | EWS | Optional |
| O365DeleteType | The method by which to delete emails using the O365 - Security And Compliance - Search And Delete playbook. Could be "Soft" \(recoverable\), or "Hard" \(unrecoverable\). Leave empty to decide manually for each email incident.<br/>This is only applicable if the SearchAndDeleteIntegration input is set to O365. | Soft | Optional |
| O365DeleteTarget | The exchange location. Determines from where to search and delete emails searched using O365 playbooks. Use the value "All" to search all mailboxes, use "SingleMailbox" to search and delete the email only from the recipient's inbox, or specify "Manual" to decide manually for every incident. Note - searching all mailboxes may take a significant amount of time. This input is only applicable if the SearchAndDeleteIntegration input is set to O365. | SingleMailbox | Optional |
| SOCEmailAddress | The SOC email address to set in case the playbook handles phishing alert. | demistoadmin@demisto.int | Optional |
| closeIfBlocked | Whether to close the investigation in cases where the email has already been blocked. | False | Optional |
| escalationRole | The role to assign the incident to if the incident severity is critical |  | Optional |
| blockedAlertActionValue | List of optional values the email security device returns for blocked\\denied\\etc. emails. | block, deny, denied, delete | Optional |
| SensitiveMailboxesList | The name of a list that contains the organization's sensitive users. | lists.sensitiveMailboxesList | Optional |
| SearchThisWeek | Whether to search for similar emails in a week's time range or all time. | true | Optional |
| CheckMicrosoftHeaders | Check Microsoft's headers for BCL/PCL/SCL scores and set the "Severity" and "Email Classification" accordingly. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing Alerts Investigation](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/PhishingAlerts/doc_files/Phishing_Alerts_Investigation.png)