The `Cortex XDR - Identity Analytics` playbook is designed to handle Cortex XDR Identity Analytics alerts and executes the following:

Analysis:
- Enriches the IP and the account, providing additional context and information about these indicators.

Verdict:
- Determines the appropriate verdict based on the data collected from the enrichment phase.

Investigation:
- Checks for related XDR alerts to the user by Mitre tactics to identify malicious activity.
- Checks for specific arguments for malicious usage from Okta using the 'Okta User Investigation' sub-playbook.
- Checks for specific arguments for malicious usage from Azure using the 'Azure User Investigation' sub-playbook.

Verdict Handling:
- Handles malicious alerts by initiating appropriate response actions, including blocking malicious IP and revoking or clearing user's sessions.
- Handles non-malicious alerts identified during the investigation.

The playbook is used as a sub-playbook in ‘Cortex XDR Alerts Handling v2’.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cloud Credentials Rotation - Azure
* Cloud IAM Enrichment - Generic
* Account Enrichment - Generic v2.1
* Block IP - Generic v3
* Azure - User Investigation
* Cortex XDR - Get entity alerts by MITRE tactics
* Okta - User Investigation

### Integrations

* XQLQueryingEngine
* XDR_iocs
* CortexXDRIR

### Scripts

* LoadJSON
* SetAndHandleEmpty

### Commands

* setIncident
* okta-clear-user-sessions
* xdr-get-cloud-original-alerts
* ip

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPAddress | IP Address from the XDR Alert. |  | Optional |
| Username | User name. |  | Optional |
| RelatedAlertsThreshold | This is the minimum threshold for XDR related alerts, based on MITRE tactics used to identify malicious activity by the user in the last 1 day.<br/> | 5 | Optional |
| FailedLogonThreshold | This is the minimum threshold for user login failures within the last 1 day.<br/>example: If this input is set to '30', and the 'Okta - User Investigation' or the 'Azure - User Investigation' sub-playbooks have found 31 failed login attempts - It will classify this behavior as malicious activity.<br/>The default value is '30'. | 30 | Optional |
| OktaSuspiciousEventsThreshold | This is the minimum threshold for suspicious Okta activity events by the user in the last 1 day.<br/>example: If this input is set to '5', and the 'Okta - User Investigation' sub-playbooks have found 6 events of suspicious activity by the user - It will classify this behavior as malicious activity.<br/>The default value is '5'. | 5 | Optional |
| AutoRemediation | Whether to execute the remediation flow automatically.<br/>Possible values are: "True" and "False". | False | Optional |
| IAMRemediationType | The response on 'Cloud Credentials Rotation - Azure' sub-playbook provides the following remediation actions using MSGraph Users:<br/> | Revoke | Optional |
| alert_id | Alert ID. |  | Optional |
| AlertName | Alert Name. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR - Identity Analytics](../doc_files/Cortex_XDR_-_Identity_Analytics.png)
