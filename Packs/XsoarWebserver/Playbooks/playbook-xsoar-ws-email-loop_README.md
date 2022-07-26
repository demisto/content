This is a subplaybook that runs the email task a configurable number of times and polls the response status by the user

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* xsoar-ws-poll-status
* Set

### Commands
* setIncident
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RecipientAddress | The email address of the recipient |  | Optional |
| FileAttachments | The file id of the attachment to send to the recipient |  | Optional |
| EmailHTML | The HTML email |  | Optional |
| ActionUUID | The action to monitor on XSOARWebserver, You will find it in the output of action-setup |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| UserResponse | The User's response | string |

## Playbook Image
---
![xsoar-ws-email-loop](Insert the link to your image here)