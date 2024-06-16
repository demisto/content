This playbook is designed to handle the following alerts:
A successful SSO sign-in from TOR
A successful SSO sign-in from TOR via a mobile device

The playbook executes the following stages:

Early Containment:
Clear/revoke the user sessions and force re-authentication.

Investigation:
Check the user's risk score.
Check for related XDR alerts using MITRE tactics to identify any malicious activity.

Remediation:
Based on the user's risk score and related alerts, the playbook will disable the account if any malicious parameters are found. By default, account disabling requires analyst approval.

Note: Please configure the 'Okta v2' integration or the 'Azure Active Directory Users' integration to enable the automatic clearing of users' active sessions.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Get entity alerts by MITRE tactics
* Containment Plan - Disable Account
* Containment Plan - Clear User Sessions

### Integrations

* CortexCoreIR

### Scripts

* SetAndHandleEmpty

### Commands

* core-get-cloud-original-alerts
* closeInvestigation
* core-list-risky-users

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ShouldCloseAutomatically | Whether to close the alert automatically or manually, after an analyst's review. | True | Optional |
| RelatedAlertsThreshold | This is the minimum threshold for XSIAM related alerts, based on MITRE tactics used to identify malicious activity by the user in the last 2 hours.<br/>Example: If this input is set to '5' and it detects '6' XSIAM related alerts, it will classify this check as indicating malicious activity.<br/>The default value is '5'. | 5 | Optional |
| UserContainment | Whether to disable the user account using the 'Containment Plan - Disable Account' sub-playbook.<br/>Possible values:True/False. Default:True.<br/> | True | Optional |
| UserVerification | Specify if analyst verification is required to disable user accounts.<br/>Possible values:True/False. Default:True. | True | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![A successful SSO sign-in from TOR](../doc_files/A_successful_SSO_sign-in_from_TOR.png)
