This playbook addresses the following alerts:
 
- Uncommon creation or access operation of sensitive shadow copy by a high-risk process
 
Playbook Stages:
  
Triage: 
 
- Check if the causality process image (CGO) is signed or not
 
Investigation:
 
- If CGO is unsigned:
  - Check the CGO process prevalence
  - Check if the process image path is common
- If CGO is signed:
  - Check process image name
  - Check initiating process image name
  - Check if username is SYSTEM
  - Check if host is a server
  - Check for previous similar alert closed as False Positive
 
Containment:
 
- Terminate causality process (CGO) process - when a signed high-risk process or an unsigned process from an uncommon path attempting to create or access sensitive shadow copy data.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CortexCoreIR

### Scripts

* SearchIncidentsV2

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

![Uncommon creation or access operation of sensitive shadow copy by a high-risk process](../doc_files/Uncommon_creation_or_access_operation_of_sensitive_shadow_copy_by_a_high-risk_process.png)
