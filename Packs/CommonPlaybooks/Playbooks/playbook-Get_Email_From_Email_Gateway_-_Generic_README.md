This playbook retrieves a specified eml/msg file directly from the email security gateway product.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Email From Email Gateway - Mimecast
* Get Email From Email Gateway - FireEye
* Get Email From Email Gateway - Proofpoint Protection Server

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MessageID | The message ID received by the email security gateway product. |  | Optional |
| UserID | The user ID. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The MSG/EML file entry ID | String |

## Playbook Image
---
![Get Email From Email Gateway - Generic](https://raw.githubusercontent.com/demisto/content/f0c79b8df5ea669b1eed6f75037867f8b0a89eeb/Packs/CommonPlaybooks/doc_files/Get_Email_From_Email_Gateway_-_Generic.png)
