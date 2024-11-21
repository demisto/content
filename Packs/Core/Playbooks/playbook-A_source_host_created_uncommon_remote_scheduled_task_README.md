This playbook handles "Uncommon remote scheduled task creation" alerts, which are generated on the source host that created the remote scheduled task.

Playbook Stages:

Analysis:

- The playbook verifies whether the causality process is signed. If the process is not signed, it proceeds with remediation actions; otherwise, it continues investigating the alert.

Investigation:
During the alert investigation, the playbook will perform the following:

- Searches for related XSIAM alerts on the endpoint that use the following MITRE techniques to identify malicious activity: T1202 - Indirect Command Execution, T1021 - Remote Services.
- Searches for related XSIAM agent alerts on the remote endpoint, to determine if the creation of the scheduled task is part of an attack pattern.
- Searches for suspicious command-line parameters indicating a malicious scheduled task.

Remediation:

- Automatically disable the malicious scheduled task on the remote host.
- Terminate the causality process.
- Automatically Close the alert.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Command-Line Analysis

### Integrations

* CortexCoreIR

### Scripts

* Print
* Set
* SearchIncidentsV2

### Commands

* core-get-script-execution-results
* core-terminate-causality
* core-get-endpoints
* core-get-process-analytics-prevalence
* closeInvestigation
* core-get-cloud-original-alerts
* core-run-script-execute-commands

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![A source host created uncommon remote scheduled task](../doc_files/A_source_host_created_uncommon_remote_scheduled_task.png)
