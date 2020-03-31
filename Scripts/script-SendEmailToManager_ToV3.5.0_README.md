Sends an approval email to the manager of the employee with the given email allowing the manager to reply directly in to the incident.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | communication |
| Demisto Version | 0.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* send-mail
* ad-search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email of the employee. This will send an email to the employee's manager. If an email is not provided, the email will be taken from incident the label `Email/from`. |
| manager | The manager attribute in Active Directory. The default is "manager". |
| entitlement | If any value is provided, this will add an entitlement to the subject allowing the manager to reply to the War Room. |
| body | The contents of the email body. This is a template that can include `$empName` and `$managerName` which will be replaced with the actual values. |
| request | The contents of the request from the manager. This will be added below the body. If none is provided, the incident details will be taken. |

## Outputs
---
There are no outputs for this script.
