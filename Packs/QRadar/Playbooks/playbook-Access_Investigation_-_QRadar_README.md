This playbook uses the QRadar integration to investigate an access incident by gathering user and IP information.

The playbook then interacts with the user that triggered the incident to confirm whether or not they initiated the access action.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Access Investigation - Generic
* QRadar - Get offense correlations v2

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* setIncident

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Access Investigation - QRadar](https://raw.githubusercontent.com/demisto/content/33e98bf473f174ef010069b34f16aaac0ab55504/Packs/QRadar/doc_files/Access_Investigation_-_QRadar.png)