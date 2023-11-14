This playbook performs an investigation on a specific user in GCP environments, using queries and logs from G Suite Auditor, and GCP Logging to locate the following activities performed by the user:
- Failed login attempt
- Suspicious API usage by the user
- Anomalous network traffic by the user
- Unusual and suspicious login attempt
- User's password leaked

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* GetTime
* Set

### Commands

* gcp-logging-log-entries-list
* gsuite-activity-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The username to investigate. |  | Optional |
| GcpProjectName | The GCP project name. This is a mandatory field for GCP queries. |  | Optional |
| GcpTimeSearchFrom | The Search Time for the \`GetTime\` task used by the GCP Logging search query. <br/>This value represents the number of days to include in the search.<br/>Default value: 1.  \(1 Day\) | 1 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GcpAnomalousNetworkTraffic | Determines whether there are events of anomalous network traffic performed by the user in the GCP environment. | unknown |
| GcpSuspiciousApiUsage | Determines whether there are events of suspicious API usage by the user in the GCP environment. | unknown |
| GcpFailLogonCount | The number of failed logins by the user in the GCP environment. | unknown |
| GsuiteFailLogonCount | The number of failed logins by the user in the G Suite environment. | unknown |
| GsuiteUnusualLoginAllowedCount | The number of unusual logins performed by the user and allowed in the G Suite environment. | unknown |
| GsuiteUnusualLoginBlockedCount | The number of unusual logins performed by the user and blocked in the G Suite environment. | unknown |
| GsuiteSuspiciousLoginCount | The number of suspicious logons performed by the user in the G Suite environment. | unknown |
| GsuiteUserPasswordLeaked | Determines whether the user's password was leaked in the G Suite environment. | unknown |

## Playbook Image

---

![GCP - User Investigation](../doc_files/GCP_-_User_Investigation.png)
