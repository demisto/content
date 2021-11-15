This playbook searches Gmail to identify and delete emails with similar attributes to the malicious email.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Gmail

### Scripts
* GetTime

### Commands
* gmail-search-all-mailboxes
* gmail-delete-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| From | The value of the malicious email's "From" attribute. |  | Optional |
| Subject | The value of the malicious email's "Subject" attribute. |  | Optional |
| AttachmentName | The value of the malicious email's "AttachmentName" attribute. |  | Optional |
| Limit | The maximum number of search results. | 50 | Optional |
| DeleteType | The deletion type \(trash or permanent\).<br/>For permanent choose 'True'. | False | Optional |
| SearchThisWeek | Limit the search to the current week \(true/false\). | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Search And Delete Emails - Gmail](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/Gmail/doc_files/Search_And_Delete_Emails_-_Gmail.png)