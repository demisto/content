This playbook handles exposure issue remediation for cloud hosted Virtual Machines by modifying cloud network security settings to block public access to the exposed service port.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Remediate Exposure via EC2 Security Groups

### Integrations

* Cortex Core - Platform

### Scripts

* Set

### Commands

* core-get-asset-details
* setIssueStatus

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex EM - AWS VM Exposure Remediation](../doc_files/Cortex_EM_-_AWS_VM_Exposure_Remediation.png)
