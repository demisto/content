Deprecated. Use "Calculate Severity - Generic v2" playbook instead. Calculates and assign the incident severity based on the highest returned severity level from the following severity calculations:

* Indicators DBotScore - Calculates the incident severity level according to the highest indicator DBotScore.
* Critical assets - Determines if a critical assest is associated with the invesigation.
* 3rd-party integrations - Calculates the incident severity level according to the methodology of a 3rd-party integration.

NOTE: the new severity level overwrites the previous severity level even if the previous severity level was more severe.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Calculate Severity - 3rd-party integrations
* Calculate Severity - Critical assets
* Calculate Severity - DBotScore

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| QualysSeverity | Qualys Vulnerability Severity score \(1-5\) | Qualys.Severity | Optional |
| DBotScore | Array of all indicators associated with the incident.  | DBotScore.None | Optional |
| Endpoint | A Endpoint to check against the critical lists. | Endpoint.None | Optional |
| Account | A User account to check against the critical lists. | Account.None | Optional |
| NexposeSeverity | Nexpose Vulnerability Severity score \(Moderate, Severe, Critical\) | Nexpose.Asset.Vulnerability.Severity | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Calculate Severity - Generic](Insert the link to your image here)