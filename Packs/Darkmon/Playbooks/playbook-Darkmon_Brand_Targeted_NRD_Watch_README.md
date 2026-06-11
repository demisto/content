Daily sweep of newly-registered domains. Each candidate's root label is compared against the brand list via DarkmonLevenshtein; matches with distance <= 2 (configurable) open a 'Darkmon Typosquatting Threat' incident.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Darkmon - Generic Notify

### Integrations

* Darkmon

### Scripts

* DarkmonCreateIncidents
* DarkmonFilterUnseen
* DarkmonScoreNRDs

### Commands

* dmontip-get-nrd

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Typosquats | NRD entries flagged as typosquats with their best-match brand and distance. | unknown |
