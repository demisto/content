Retrieve a specified eml/msg file directly from the email security gateway product.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get_Email_From_Email_Gateway_-_FireEye
* Get_Email_From_Email_Gateway_-_Agari
* Get_Email_From_Email_Gateway_-_Proofpoint_Protection_Server
* Get_Email_From_Email_Gateway_-_Mimecast

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
| MessageID | The message ID received by the Email Security product. |  | Optional |
| UserID | The Id of user. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The MSG/EML File Entry ID | string |

## Playbook Image
---
![Get Email From Email Gateway - Generic](Insert the link to your image here)