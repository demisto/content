This playbook investigates and remediates potential phishing incidents produced by either an email security gateway or a SIEM product. It retrieves original email files from the email security gateway or email service provider and generates a response based on the initial severity, hunting results, and the existence of similar phishing incidents in XSOAR.
No action is taken without an initial approval given by the analyst using the playbook inputs.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Extract Indicators From File - Generic v2
* Entity Enrichment - Phishing v2
* Detonate File - Generic
* Process Email - Generic v2
* Email Headers Check - Generic
* Block Indicators - Generic v2
* Phishing Alerts - Check Severity
* Search And Delete Emails - Generic v2
* Threat Hunting - Generic

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
| SearchAndDelete | Whether to enable the "Search and Delete" capability.<br/>For a malicious email, the Search and Delete sub-playbook looks for other instances of the email and deletes them pending analyst approval. | True | Optional |
| BlockIndicators | Whether to enable the "Block Indicators" capability.<br/>For a malicious email, the Block Indicators sub-playbook blocks all malicious indicators in the relevant integrations. | False | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified using SPF, DKIM, and DMARC. | True | Optional |
| OnCall | Set to True to assign only to analysts on the current shift. Requires Cortex XSOAR v5.5 or later. | False | Optional |
| SearchAndDeleteIntegration | Determines which product and playbook is used to search and delete the phishing email from user inboxes.<br/>Set this to "O365" to use the O365 - Security And Compliance - Search And Delete playbook.<br/>Set this to "EWS" to use the Search And Delete Emails - EWS playbook. | EWS | Optional |
| O365DeleteType | The method to delete emails using the O365 - Security And Compliance - Search And Delete playbook. Can be "Soft" \(recoverable\), or "Hard" \(unrecoverable\). Leave empty to decide manually for each email incident.<br/>This is only applicable if the SearchAndDeleteIntegration input is set to O365. | Soft | Optional |
| O365ExchangeLocationExclusion | The exchange location. Determines from where to search and delete emails searched using O365 playbooks. Use the value 'All' to search all mailboxes, use 'SingleMailbox' to search and delete the email only from the recipient's inbox, or use 'Manual' to decide manually for every incident. Note: Searching all mailboxes may take a significant amount of time. This input is only applicable if the SearchAndDeleteIntegration input is set to O365. | SingleMailbox | Optional |
| SOCEmailAddress | The SOC email address to set if the playbook handles phishing alerts. | demistoadmin@demisto.int | Optional |
| escalationRole | The role to assign the incident to if the incident severity is critical. |  | Optional |
| blockedAlertActionValue | A comma-separated list of optional values the email security device returns for blocked\\denied\\etc. emails. | block, deny, denied, delete | Optional |
| SensitiveMailboxesList | The name of a list that contains the organization's sensitive users. | lists.sensitiveMailboxesList | Optional |
| SearchThisWeek | Whether to search for similar emails in a week's time range or for all time. | true | Optional |
| CheckMicrosoftHeaders | Check Microsoft headers for BCL/PCL/SCL scores and set the "Severity" and "Email Classification" accordingly. | True | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Phishing Alerts Investigation](../doc_files/Phishing_Alerts_Investigation.png)
