This playbook can be used to send email notification if an Incidents severity is Critical or High.  

Can be used as a sub-playbook to perform the same logic across different playbooks/use cases.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* Set

### Commands

* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| emails | The email addresses to send the message to, can be comma separated.  |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EscalationEmailSent | Whether an escalation email was sent, will be Yes or No | string |

## Playbook Image

---

![Case Management - Generic - Send On Call Notification](../doc_files/Case_Management_-_Generic_-_Send_On_Call_Notification.png)
