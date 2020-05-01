Searches EWS to identify and delete emails with similar attributes of a malicious email.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* EWS v2

### Scripts
* BuildEWSQuery

### Commands
* ews-delete-items
* ews-search-mailboxes

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| From | The value of the malicious email's "From" attribute. | emailfrom | incident | Required |
| Subject | The value of the malicious email's "Subject" attribute. | emailsubject | incident | Optional |
| AttachmentName | The value of the malicious email's `AttachmentName` attribute. | attachmentname | incident | Optional |
| SearchThisWeek | Limit the search to the current week. Can be "true" or "false". | true | - | Required |
| Limit | The maximum number of search results. | 20 | - | Required |
| DeleteType | The deletion type. Can be, "trash", "soft", or "hard". | trash | - | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Search_And_Delete_Emails_EWS](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Search_And_Delete_Emails_EWS.png)
