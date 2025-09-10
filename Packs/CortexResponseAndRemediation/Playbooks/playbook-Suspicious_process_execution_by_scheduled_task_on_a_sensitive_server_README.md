This playbook handles "Suspicious process execution by scheduled task on a sensitive server" alerts.

Playbook Stages:

Analysis:

- Checks the suspicious process reputation.

Investigation:

- Searches for related alerts to identify any malicious activity on the server.

Remediation:

If the suspicious process reputation is malicious, or if a related alert is found, the following remediation actions will be taken:

- Disable the scheduled task responsible for executing the process.
- Terminate the malicious process.
- Quarantine the malicious process.
- Automatically Close the alert.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* SearchIncidentsV2
* file-enrichment
* quarantine-file

### Commands

* closeInvestigation
* core-execute-command
* core-get-cloud-original-alerts
* core-terminate-causality

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Suspicious process execution by scheduled task on a sensitive server](../doc_files/Suspicious_process_execution_by_scheduled_task_on_a_sensitive_server.png)
