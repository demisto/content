This playbook processes files fetched by the Google Dorking integration.
The SOC will track the file owner and classify the exposed data and users in order to contained the leaked data.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GDPR Breach Notification
* HIPAA - Breach Notification
* US - Breach Notification

### Integrations
This playbook does not use any integrations.

### Scripts
* FilterByList
* ExtractUsernames
* ReadFile

### Commands
* closeInvestigation
* extractIndicators
* rasterize
* send-mail
* addToList
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExclusionListName | An XSOAR list to exclude files by hash |  | Optional |
| SeverityMapping |  | 1,2,3,4 | Optional |
| ComplianceMailAddress |  |  | Optional |
| ITMailAddress |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.