This playbook is designed to handle the 'Unprivileged process opened a registry hive' alert. 

The playbook is designed to investigate and respond to an unprivileged process opening a registry hive. It examines the unprivileged process that triggered the alert, the command line, and searches for any additional suspicious Cortex XSIAM alerts using Mitre techniques in order to determine whether a remediation measure is required.

Playbook Stages:

Investigation:

- The playbook is designed to investigate and respond to unprivileged processes opening registry hives. It examines the unprivileged process that triggered the alert, the command line, and searches for additional suspicious Cortex XSIAM alerts within the same incident in order to determine whether a remediation measure is required.

Remediation:

- To prevent malicious activity from continuing, the playbook terminates the causality processes that triggered the alert.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

CortexCoreIR

### Scripts

SearchIncidentsV2

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
