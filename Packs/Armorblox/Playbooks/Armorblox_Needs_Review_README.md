This playbook sends email alerts to admins for Armorblox incidents that need review.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Armorblox

### Scripts
* Print

### Commands
* armorblox-check-remediation-action
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| recipient_mail_address | Receiver's mailing address. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Armorblox.Threat.remediation_actions | Remediation Action for the incident under inspection. | string |

## Playbook Image
---
![Armorblox Needs Review](../doc_files/Armorblox_Needs_Review.png)