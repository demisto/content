`Note`: For the Phishing use case, see the [Phishing Investigation - Generic v3 playbook](https://xsoar.pan.dev/docs/reference/playbooks/phishing---generic-v3).

This playbook investigates and remediates potential phishing incidents produced by either an email security gateway or a SIEM product. It retrieves original email files from the email security gateway or email service provider and generates a response based on the initial severity, hunting results, and the existence of similar phishing incidents in XSOAR. 

No action is taken without an initial approval given by the analyst using the playbook inputs.

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
SearchIncidentsV2

### Commands
* linkIncidents
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator | Required |
| SearchAndDelete | Whether to enable the "Search and Delete" capability.<br/>For a malicious email, the Search and Delete sub-playbook looks for other instances of the email and deletes them pending analyst approval. | True | Optional |
| BlockIndicators | Whether to enable the "Block Indicators" capability.<br/>For a malicious email, the Block Indicators sub-playbook blocks all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified using SPF, DKIM, and DMARC. | True | Optional |
| OnCall | Set to True to assign only to analysts on the current shift. Requires Cortex XSOAR v5.5 or later. | False | Optional |
| SearchAndDeleteIntegration | Determines which product and playbook is used to search and delete the phishing email from user inboxes.<ul><li>Set this to "O365" to use the O365 - Security And Compliance - Search And Delete playbook.</li><li>Set this to "EWS" to use the Search And Delete Emails - EWS playbook.</li></ul> | EWS | Optional |
| O365DeleteType | The method to delete emails using the O365 - Security And Compliance - Search And Delete playbook. Can be "Soft" \(recoverable\), or "Hard" \(unrecoverable\). Leave empty to decide manually for each email incident.<br/>This is only applicable if the SearchAndDeleteIntegration input is set to O365. | Soft | Optional |
| O365DeleteTarget | The exchange location. Determines from where to search and delete emails using O365 playbooks. <ul><li>Use "All" to search all mailboxes</li><li>Use "SingleMailbox" to search and delete the email only from the recipient's inbox</li><li>Use "Manual" to decide manually for every incident.</li></ul> Note: Searching all mailboxes may take a significant amount of time. This is only applicable if the SearchAndDeleteIntegration input is set to O365. | SingleMailbox | Optional |
| SOCEmailAddress | The SOC email address to set if the playbook handles phishing alerts. |  | Optional |
| closeIfBlocked | Whether to close the investigation if the email has already been blocked. | False | Optional |
| escalationRole | The role to assign the incident to if the incident severity is critical |  | Optional |
| blockedAlertActionValue | A comma-separated list of optional values the email security device returns for blocked\\denied\\etc. emails. | block, deny, denied, delete | Optional |
| SensitiveMailboxesList | The name of a list that contains the organization's sensitive users. |  | Optional |
| SearchThisWeek | Whether to search for similar emails in a week's time range or for all time. | True | Optional |
| CheckMicrosoftHeaders | Check Microsoft headers for BCL/PCL/SCL scores and set the "Severity" and "Email Classification" accordingly. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing Alerts Investigation](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/PhishingAlerts/doc_files/Phishing_Alerts_Investigation.png)
