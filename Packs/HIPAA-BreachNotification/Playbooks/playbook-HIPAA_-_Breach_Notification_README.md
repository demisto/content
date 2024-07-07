USA Health Insurance Portability and Accountability Act of 1996 (HIPAA) covers organizations that use, store, or process Private Health Information (PHI). 
The HIPAA Breach Notification Rule requires companies that deal with health information to disclose cybersecurity breaches; the disclosure will include notification to individuals, to the media, and the Secretary of Health and Human Services.
This playbook is triggered by a HIPAA breach notification incident and follows through with the notification procedures.

DISCLAIMER: Please consult with your legal team before implementing this playbook.

** Source: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* GenerateInvestigationSummaryReport
* SetGridField
* Sleep

### Commands
* setIncident
* extractIndicators
* closeInvestigation
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ContactName | In case of a breach, the contact details to send to the Secretary of HHS and the affected individuals. |  | Optional |
| ContactEmailAddress | In case of a breach, the contact details to send to the Secretary of HHS and the affected individuals. |  | Optional |
| ContactTelNumber | In case of a breach, the contact details to send to the Secretary of HHS and the affected individuals. |  | Optional |
| CompanyName | In case of a breach, the company details to display in the breach report. |  | Optional |
| CompanyAddress | In case of a breach, the company details to display in the breach report. |  | Optional |
| CompanyCity | In case of a breach, the company details to display in the breach report. |  | Optional |
| CompanyCountry | In case of a breach, the company details to display in the breach report. |  | Optional |
| AutoNotification | This input determines if the resident notification should be done automatically or manually.
True \- Automatically
False \- Manually. | False | Optional |
| ResidentNotification_WhatCanTheyDo | An explanation to the individual's notification email of what can they do. | First, change your online login information, passwords, and security questions-and-answers. 
Second, if you used similar login information and passwords for different sites - change the login information, passwords, and security Q&A to them, too.
Third, pay attention if you start receiving notices of password changes to your current accounts or find yourself locked out of your accounts.
Fourth, Consider implementing two-factor-authentication to your account to reduce the risk of unauthorized access in your account. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![HIPAA - Breach Notification](https://raw.githubusercontent.com/demisto/content/master/Packs/HIPAA-BreachNotification/doc_files/HIPAA_-_Breach_Notification.png)