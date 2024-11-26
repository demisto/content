This playbook addresses the following alerts:
 
- Uncommon creation or access operation of sensitive shadow copy by a high-risk process
- Suspicious access to shadow file
 
Playbook Stages:
  
Triage: 
 
- <Action description>
 
Early Containment:
 
- <Action description>
 
Investigation:
 
- <Action description>
 
Containment:
 
- <Action description>
 
Requirements: 
 
For any response action, you need one of the following integrations:
 
- <Pack X>
- <Pack Y>.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CortexCoreIR

### Scripts

* SearchAlertsV2

### Commands

* closeInvestigation
* core-get-process-analytics-prevalence
* core-terminate-causality

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Suspicious access to shadow file](../doc_files/Suspicious_access_to_shadow_file.png)
