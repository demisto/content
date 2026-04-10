Example Playbook utilizing the Tufin integration to enrich a network alert and perform containment, if needed.

Requires the following incident details:  Source IP, Destination IP, Destination Ports

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Tufin - Enrich a Single IP Address

### Integrations
* Tufin

### Scripts
This playbook does not use any scripts.

### Commands
* tufin-search-topology-image
* tufin-submit-change-request
* tufin-search-topology

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Tufin - Investigate Network Alert](../doc_files/playbook-Tufin_-_Investigate_Network_Alert.png)
