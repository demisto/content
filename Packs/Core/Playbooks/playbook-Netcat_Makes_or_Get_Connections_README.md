This playbook is designed to handle the following alerts:

- Netcat makes or gets connections

The playbook executes the following stages:

Analysis:

- Investigate the IP and Domain  reputation
- Search previous similar alerts

Remediation:

- Handles malicious alerts by terminating the causality process.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CoreIOCs
* CortexCoreIR
* CortexCoreXQLQueryEngine

### Scripts

* SearchAlertsV2

### Commands

* closeInvestigation
* core-get-IP-analytics-prevalence
* core-get-cloud-original-alerts
* core-get-cmd-analytics-prevalence
* core-terminate-causality
* domain
* ip

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Netcat makes or gets connections](../doc_files/Netcat_makes_or_gets_connections.png)
