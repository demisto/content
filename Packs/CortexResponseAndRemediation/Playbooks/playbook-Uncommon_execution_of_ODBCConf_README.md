This playbook handles "Uncommon execution of ODBCConf" alerts.

Playbook Stages:

Analysis:
During the analysis, the playbook will perform the following:

- Checks if the causality process (CGO) is signed and prevalent.
- Checks for the host's risk score.

If the CGO process is not signed and not prevalent, or if either of these conditions is met in addition to having a high-risk score, the playbook proceeds with remediation actions. Otherwise, it will continue to the investigation phase.

Investigation:
During the alert investigation, the playbook will perform the following:

Searches for related Cortex XSIAM alerts and insights on the same causalities chains by specific alert names :  
- Evasion Technique - 3048798454
- An uncommon LOLBIN added to startup-related Registry keys
- Behavioral Threat
- An uncommon file was created in the startup folder
- Unsigned process running from a temporary directory
- Execution From a Restricted Location
- Execution of an uncommon process with a local/domain user SID at an early startup stage by Windows system binary - Explorer CGO

The playbook determines the appropriate verdict. If related alerts are found, it proceeds to remediation actions. In case of related insights are found ,and one of the following is met: the host score is listed as high or the CGO process is not prevalent, it will proceed to remediation actions. Otherwise, it closes the alert with the following message: "No indication of malicious activity was found".


Remediation:  

- Automatically terminate the causality process.
- Automatically Close the alert.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* SearchIncidentsV2

### Commands

* closeInvestigation
* core-get-process-analytics-prevalence
* core-list-risky-hosts
* core-terminate-causality

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Uncommon execution of ODBCConf](../doc_files/Uncommon_execution_of_ODBCConf.png)
