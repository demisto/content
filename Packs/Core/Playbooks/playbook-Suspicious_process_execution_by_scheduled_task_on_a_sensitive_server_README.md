This playbook handles "Suspicious process execution by scheduled task on a sensitive server" alerts.

Playbook Stages:

Investigation:

During the alert investigation, the playbook will perform the following:

- Checks the suspicious process reputation.
- Searches for Cortex XSIAM agent alerts related to any malicious activity on the server.

Remediation:

- Remediation actions will be taken if the suspicious process reputation is malicious, or if a related alert is found. In such cases, the playbook will disable the scheduled task, terminate the malicious process, and close the alert.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CoreIOCs
* CortexCoreIR
* CortexCoreXQLQueryEngine

### Scripts

* SearchIncidentsV2

### Commands

* closeInvestigation
* core-get-script-execution-results
* core-run-script-execute-commands
* core-terminate-causality
* file

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Suspicious process execution by scheduled task on a sensitive server](../doc_files/Suspicious_process_execution_by_scheduled_task_on_a_sensitive_server.png)
