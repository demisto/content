Get an approver response for an exemption request from a user.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

SlackV3

### Scripts

* IsIntegrationAvailable
* MicrosoftTeamsAsk
* SlackAskV2

### Commands

* setIncident
* slack-get-user-details

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Approver | The email address of the approver. |  | Optional |
| SendMailInstance | The name of the instance to be used when executing the "send-mail" command in the playbook. In case it will be empty, all available instances will be used \(default\). |  | Optional |
| ApproverMessageApp | The communication method with the approver.<br/>Can be one of the following:<br/><br/>- Slack<br/>- Microsoft Teams<br/>- Email<br/><br/>If you choose to set "Email", it's also possible to set the relevant email integration instance with the "SendEmailInstance" input. |  | Optional |
| Detections | Detected violation snippets. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DLP - Get Approval](../doc_files/DLP_-_Get_Approval.png)
