Use this playbook to retrieve the original email in the thread (as eml file), when the reporting user forwarded the original email not as an attachment.

You must have the necessary permissions in the EWS integration to execute global search: eDiscovery

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* EWS v2

### Scripts
* DeleteContext
* Set

### Commands
* ews-get-items-as-eml
* ews-search-mailbox

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Mailbox | Email address of the reporting user. | incident.emailfrom | Optional |
| InReplyTo | The InReplyTo header in the forwarded email. | incident.phishingreporteremailheaders.headervalue | Optional |
| ThreadTopic | The ThreadTopic header in the forwarded email. | incident.phishingreporteremailheaders.headervalue | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The original email as eml file. | unknown |

## Playbook Image
---
![Get Original Email - EWS v2](../doc_imgs/Get_Original_Email_-_EWS_v2.png)