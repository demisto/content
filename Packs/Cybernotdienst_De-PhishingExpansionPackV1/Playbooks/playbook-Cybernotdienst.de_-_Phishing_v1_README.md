This playbook performs an initial email investigation and gives decision options to close an incident as simple Spam or perform a full Phishing investigation, which is utelises the out of the box Phishing Playbook by Palo Alto Networks

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Phishing - Generic v3

### Integrations
* ipinfo_v2

### Scripts
* IncreaseIncidentSeverity
* DBotAverageScore
* ReadPDFFileV2

### Commands
* setIncident
* postmark-spamcheck
* enrichIndicators
* ip
* closeInvestigation
* extractIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| misp_create |  | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cybernotdienst.de - Phishing v1](../doc_files/Cybernotdienst.de_-_Phishing_v1.png)