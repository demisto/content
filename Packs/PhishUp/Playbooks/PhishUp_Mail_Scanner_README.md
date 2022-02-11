Extracts URLs from mail body and checks URLs with PhishUp. Takes action based on PhishUp results.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* PhishUp
* Gmail

### Scripts
* IncreaseIncidentSeverity

### Commands
* gmail-move-mail
* closeInvestigation
* phishup-evaluate-response
* gmail-delete-mail
* url
* extractIndicators
* phishup-get-chosen-action

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| EmailBodyHtml | Email Mail Body for extracting URLs. Default Value is "$\{incident.emailbodyhtml\}" | ${incident.emailbodyhtml} | Required |
| ShouldPhishUpActionWork | If you do not want actions such as deleting mail and moving to spam in PhishUp playbook, you should set the value False. Default value is True | True | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Phishup.Result | Phishup Service Response \(Clean, Phish\) | string |

## Playbook Image
---
![PhishUp Mail Scanner](https://raw.githubusercontent.com/demisto/content/69bf4f8875443f05bad0be5bbbfdcc56bb1fe419/Packs/PhishUp/doc_files/PhishUp_Mail_Scanner.png)