This playbook searches and delete emails with similar attributes of a malicious email using EWS or Office 365.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* O365 - Security And Compliance - Search And Delete
* Search And Delete Emails - EWS

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| From | The value of the malicious email's "From" attribute. | incident.emailfrom | Optional |
| Subject | The value of the malicious email's "Subject" attribute. | incident.emailsubject | Optional |
| AttachmentName | The value of the malicious email's "AttachmentName" attribute. | incident.attachmentname | Optional |
| SearchAndDeleteIntegration | The integration in which to run the search and delete action. Can be O365 or EWS. | EWS | Required |
| O365ExchangeLocation | Used only in O365. A comma-separated list of mailboxes/distribution groups to include, or use the value "All" to include all. | incident.emailto | Optional |
| O365KQL | Used only in O365. Text search string or a query that is formatted using the Keyword Query Language \(KQL\). |  | Optional |
| O365Description | Used only in O365. Description of the compliance search. |  | Optional |
| O365AllowNotFoundExchangeLocations<br/> | Used only in O365. Whether to include mailboxes other than regular user mailboxes in the compliance search. | false | Optional |
| O365DeleteType | Used only in O365. The delete type to perform on the search results. Possible values are Hard and Soft or leave empty to select manually. \(Hard = Unrecoverable, Soft=Recoverable\) | inputs.O365DeleteType | Optional |
| O365ExchangeLocationExclusion | Used only when searching and deleting emails in O365. The exchange location. Determines from where to search and delete emails searched using O365 playbooks. Use the value "All" to search all mailboxes, use "SingleMailbox" to search and delete the email only from the recipient's inbox, or specify "Manual" to decide manually for every incident. Note: Searching all mailboxes may take a significant amount of time. | inputs.O365ExchangeLocationExclusion.None | Optional |
| To | The email address to which the email was sent. This is used if the user decides to search for and delete emails only from the inbox of the recipient using O365. | incident.emailto | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Search And Delete Emails - Generic v2](https://raw.githubusercontent.com/demisto/content/a1fd8bd8eaab1058a3b0a6a849552bc62621984e/Packs/CommonPlaybooks/doc_files/Search_And_Delete_Emails_-_Generic_-_v2.png)
