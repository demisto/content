This playbook is triggered by a breach notification incident and then proceeds to the breach notification playbook for the relevant state.

DISCLAIMER: Please consult with your legal team before implementing this playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PII Check - Breach Notification
* California - Breach Notification
* Residents Notification - Breach Notification
* Illinois - Breach Notification
* New York - Breach Notification

### Integrations
This playbook does not use any integrations.

### Scripts
* Print

### Commands
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ContactName | In case of a breach, the contact details to send to the Attorney General and the affected residents. |  | Optional |
| ContactEmailAddress | In case of a breach, the contact details to send to the Attorney General and the affected residents. |  | Optional |
| ContactTelNumber | In case of a breach, the contact details to send to the Attorney General and the affected residents. |  | Optional |
| CompanyName | In case of a breach, the company details to display in the breach report. |  | Optional |
| CompanyAddress | In case of a breach, the company details to display in the breach report. |  | Optional |
| CompanyCity | In case of a breach, the company details to display in the breach report. |  | Optional |
| CompanyCountry | In case of a breach, the company details to display in the breach report. |  | Optional |
| AutoNotification | This input determines if the resident notification should be done automatically or manually.
Ture \- Automatically
False \- Manually. | False | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![US-BreachNotification](../doc_files/US_-_Breach_Notification.png)