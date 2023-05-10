Send an approval email to the manager of the employee, allowing the manager to reply directly into the incident

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | communication |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* send-mail
* ad-search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The employee email. We will send an email to his manager. If not provided will be taken from incident label 'Email/from' |
| manager | The manager attribute in Active Directory. Default is 'manager'. |
| allowReply | If true, we will add an entitlement to the subject allowing manager to reply to war room |
| body | The contents of the email body. It's a template that can include $empName and $managerName which will be replaced with actual values. |
| request | The contents of the request from the manager. Will be added below the body. If none is provided, incident details will be taken. |
| replyEntriesTag | Tag to add on email reply entries |
| persistent | Indicates whether to use one-time entitlement or a persistent one |

## Outputs
---
There are no outputs for this script.
