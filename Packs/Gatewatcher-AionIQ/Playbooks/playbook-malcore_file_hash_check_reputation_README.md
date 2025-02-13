This playbook fetch a malcore alert from a GCenter, retrieve the associated suspicious file and checks the SHA256 reputation using VirusTotal integration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* GCenter 103
* VirusTotal

### Scripts

This playbook does not use any scripts.

### Commands

* file
* gcenter103-alerts-list
* gcenter103-raw-alerts-file-get

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![malcore file hash check reputation](../doc_files/malcore_file_hash_check_reputation.png)
