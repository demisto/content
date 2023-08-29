Template playbook to initiate an Automated Threat Hunt based on the Threat Map in Recorded Future. The Playbook fetches links related to the Threat Actors part of the Threat Map from Recorded Future and launches a hunt in the SIEM for any detections within the environment.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* QRadar Indicator Hunting V2
* Splunk Indicator Hunting

### Integrations

* RecordedFuture
* Recorded Future v2

### Scripts

This playbook does not use any scripts.

### Commands

* recordedfuture-detection-rules
* recordedfuture-threat-links
* recordedfuture-threat-map
* extractIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| threat_actor | The threat actor to enrich &amp; hunt indicators for. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
