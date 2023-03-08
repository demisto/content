This sub-playbook can be used to send email notification if an Incidents severity is High or Critical.  By default it will take the current Incident severity as input, and requires a comma separated list of email addresses to send the notification to.

Inputs:

email: The email addresses to send the message to, can be comma separated. 
severity: Defaults to the current incident severity in string format (critical, high, etc)

Outputs:

EscalationEmailSent: (Yes | No) : Whether a notification email was sent. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* XSOAR Engineer Training

### Scripts

* Print
* Set

### Commands

* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| email | The email addresses to send the message to, can be comma separated.  |  | Required |
| severity | The Incident severity in string format  | ${incident.severityStr} | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EscalationEmailSent | Whether an escalation email was sent, will be Yes or No | string |

## Playbook Image

---

![XSOAR Engineer Training - On Call Notification (Sub-Playbook)](../doc_files/XSOAR_Engineer_Training_-_On_Call_Notification_(Sub-Playbook).png)
