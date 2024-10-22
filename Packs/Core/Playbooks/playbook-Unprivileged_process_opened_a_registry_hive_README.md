This Playbook is designed to handle the 'Unprivileged process opened a registry hive' alerts and execute the following:
- Check for process signatures and prevalence.
- Searching for additional Cortex XSIAM suspicious alerts in the incident is conducted by searching relevant Mitre techniques.

Remediation:
- Handles malicious alerts by terminating causality processes.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CortexCoreIR

### Scripts

* SearchIncidentsV2

### Commands

* core-get-process-analytics-prevalence
* core-terminate-causality
* core-get-cmd-analytics-prevalence
* closeInvestigation

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Unprivileged process opened a registry hive](../doc_files/Unprivileged_process_opened_a_registry_hive.png)
