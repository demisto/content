Identify whether the incident includes an email message attached as an eml or msg file and return the answer to playbook. 
Also saves the identified entry ID to context for use for later. 
Commonly used in automated playbooks that handle phishing reports sent to a special phishing mailbox set up by the security team.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | phishing, email, Condition |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Process Email - Core
* Process Email - Core v2
* Process Email - Generic
* Process Email - Generic v2

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entryid | Specific entryid to check if it is an email attachment. If not specified will check all entries of the incident. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| yes | If incident contains an email attachment. | Unknown |
| no | If incident does not contain an email attachment | Unknown |
| reportedemailentryid | The entry IDs of the email attachments found. | String |

