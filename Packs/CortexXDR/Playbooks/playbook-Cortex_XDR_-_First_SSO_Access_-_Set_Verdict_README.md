This playbook determines the alert’s verdict based on the results of multiple checks.
By default, if at least two of the checks' results are true the verdict is set to malicious.
else if only one check's results are true the verdict is set to suspicious.
If none of the conditions is true,  the verdict is set to non-malicious.
It possible to change the threshold value of the inputs to change the sensitivity of the verdict is set.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SetMultipleValues
* SetGridField
* Set

### Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FailedlogonUserThreshold | The 'Failed login' threshold to determine the 'Check for massive failed logon' check result.<br/> |  | Optional |
| FailedlogonFromASNThreshold | The 'Failed login from ASN' threshold to determine the 'Check for massive failed logon from the ASN' check result.<br/> |  | Optional |
| XDRRelatedAlertsThreshold | The 'XDR related alerts' threshold to determine the 'Check for XDR related alerts' check result. |  | Optional |
| MaliciousVerdictThreshold | The 'Malicious verdict' threshold to determine a malicious verdict.<br/>The default value is '2'. | 2 | Optional |
| SuspiciousVerdictThreshold | The 'Suspicious verdict' threshold to determine a suspicious verdict.<br/>The default value is '1'. | 1 | Optional |
| AlertName | Alert Name. |  | Optional |
| NumOfFailedLogonASN | The number of failed logon from the ASN. |  | Optional |
| RelatedCampaign | Campaign related to the indicator. |  | Optional |
| NumOfXDRAlerts | The number of XDR alert for the user. |  | Optional |
| NumOfFailedLogon | The number of failed logins. |  | Optional |
| NumOfOktaSuspiciousUserAgent | The number of Suspicious User Agent from Okta. |  | Optional |
| NumOfOktaSuspiciousActivities | Number of Suspicious Activities for the user from Okta. |  | Optional |
| PermanentCountry | True if the user works from a permanent country from Okta. False if else. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Verdict | The verdict based on the results of multiple checks. | unknown |

## Playbook Image
---
![Cortex XDR - First SSO Access - Set Verdict](../doc_files/Cortex_XDR_-_First_SSO_Access_-_Set_Verdict.png)