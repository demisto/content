Performs indicator extraction and enrichment from the incident content, calculates the severity level, assigns the incident to a particular analyst, notifies SOCRadar platform for the incident response (to mark it as false positive or resolved) and generates investigation summary report just before closing the investigation in the end. This playbook is executed for the SOCRadar Generic incident type.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Entity Enrichment - Generic v3

### Integrations
* SOCRadarIncidents

### Scripts
* IsIntegrationAvailable
* GenerateInvestigationSummaryReport
* AssignAnalystToIncident

### Commands
* socradar-mark-incident-resolved
* socradar-mark-incident-fp
* setIncident
* extractIndicators
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoEnrich | Auto Enrich input to be used for extracting indicators out of the incident content automatically at the beginning of the playbook. \(Options: Yes/No\) | Yes | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---
![SOCRadar Incident](../doc_files/SOCRadar_Incident.png)