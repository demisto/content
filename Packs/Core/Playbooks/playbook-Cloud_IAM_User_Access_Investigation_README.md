Investigate and respond to Cortex XSIAM alerts where a Cloud IAM user access key is used suspiciously to access the cloud environment.
The following alerts are supported for AWS, Azure, and GCP environments.
Penetration testing tool attempt
Penetration testing tool activity
Suspicious API call from a Tor exit node

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Handle False Positive Alerts
* Cloud IAM Enrichment - Generic
* Cloud Response - Generic
* Enrichment for Verdict

### Integrations

CortexCoreIR

### Scripts

LoadJSON

### Commands

* core-get-cloud-original-alerts
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| autoAccessKeyRemediation | Whether to execute the user remediation flow automatically. | False | Optional |
| autoBlockIndicators | Whether to block the indicators automatically. | False | Optional |
| autoUserRemediation | Whether to execute the user remediation flow automatically. | False | Optional |
| AWS-accessKeyRemediationType | Choose the remediation type for the user's access key.<br/><br/>AWS available types:<br/>Disable - for disabling the user's access key.<br/>Delete - for deleting the user's access key. | Disable | Optional |
| AWS-userRemediationType | Choose the remediation type for the user involved.<br/><br/>AWS available types:<br/>Delete - for deleting the user.<br/>Revoke - for revoking the user's credentials. | Revoke | Optional |
| Azure-userRemediationType | Choose the remediation type for the user involved.<br/><br/>Azure available types:<br/>Disable - for disabling the user.<br/>Delete - for deleting the user. | Disable | Optional |
| GCP-accessKeyRemediationType | Choose the remediation type for the user's access key.<br/><br/>GCP available types:<br/>Disable - For disabling the user's access key.<br/>Delete - For deleting the user's access key. | Disable | Optional |
| GCP-userRemediationType | Choose the remediation type for the user involved.<br/><br/>GCP available types:<br/>Delete - For deleting the user.<br/>Disable - For disabling the user. | Disable | Optional |
| ShouldCloseAutomatically | Whether to close alerts automatically as a false positive. \(True/False\). | False | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cloud IAM User Access Investigation](../doc_files/Cloud_IAM_User_Access_Investigation.png)
