This playbook is responsible for detecting the ransomware type and searching for available decryptors.

The playbook uses the ID-Ransomware service, which allows detecting the ransomware using multiple methods.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Rasterize

### Scripts
* ReadFile

### Commands
* rasterize-email
* extractIndicators

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Ransomware Advanced Analysis](https://raw.githubusercontent.com/demisto/content/6b468656734d10b98f9deee7d24897b0acec6292/Packs/Core/doc_files/Ransomware_Advanced_Analysis.png)
