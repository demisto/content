This Playbook is used to verify that all assets found by Expanse are being scanned by a vulnerability management tool by: 
- Searching the IP and / or domain of the identified Expanse asset in the vulnerability management tool

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* This does not use any sub-playbooks

### Integrations
* Tenable.io
* Rapid7 Nexpose

### Scripts
* This playbook does not use any scripts.

### Commands
* tenable-io-get-vulnerabilities-by-asset
* nexpose-search-assets

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image

---
![Expanse VM Enrich](https://raw.githubusercontent.com/demisto/content/master/Packs/ExpanseV2/doc_files/Expanse_VM_Enrich.png)
