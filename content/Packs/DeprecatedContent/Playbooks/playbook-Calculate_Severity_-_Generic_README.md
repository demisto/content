DEPRECATED. Use "Calculate Severity - Generic v2" playbook instead. Calculates and assigns the incident severity based on the highest returned severity level from the following severity calculations:

* Indicators DBotScore - Calculates the incident severity level according to the highest indicator DBotScore.
* Critical assets - Determines if a critical assest is associated with the invesigation.
* 3rd-party integrations - Calculates the incident severity level according to the methodology of a 3rd-party integration.

NOTE: the new severity level overwrites the previous severity level even if the previous severity level was more severe.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Calculate Severity - DBotScore
* Calculate Severity - 3rd-party integrations
* Calculate Severity - Critical assets

## Integrations
* Builtin

## Scripts
This playbook does not use any scripts.

## Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| QualysSeverity | The qualys vulnerability severity score (1-5). | Severity | Qualys | Optional |
| DBotScore | The array of all indicators associated with the incident.  | None | DBotScore | Optional |
| Endpoint | The endpoint to check against the critical lists. | None | Endpoint | Optional |
| Account | The user account to check against the critical lists. | None | Account | Optional |
| NexposeSeverity | The Nexpose vulnerability severity score. Can be, "Moderate", "Severe", or "Critical". | Asset.Vulnerability.Severity | Nexpose | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Calculate_Severity_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Calculate_Severity_Generic.png)
