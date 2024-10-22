This Playbook is designed to handle the 'Unprivileged process opened a registry hive' alerts and executes the following:

Investigation:
Check the signature of the Actor & CGO processes. 
Check the prevalence of the Actor & CGO process and Actor & CGO CommandLine
Check for related XDR alerts using MITRE tactics to identify any malicious activity.

Remediation:
Based on the signature status of the Actor & CGO processes, prevalence of the Actor & CGO process and Actor & CGO CommandLine, and related alerts if found, the playbook will terminate the causality process if any malicious parameters are found.

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
* core-get-cmd-analytics-prevalence
* core-terminate-causality
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
