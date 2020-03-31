Calculates incident severity by indicators reputation and user/endpoint membership in critical groups.

Note - current severity will be overwritten and new severity may be lower than the current one.

Playbook inputs:
* CriticalUsers - The comma separated array with usernames of critical users.
* CriticalEndpoints - The comma separated array with hostnames of critical endpoints.
* CriticalGroups - The comma separated array with DN of critical active directory groups.
* QualysSeverity - The Qualys severity score (1-5) to calculate severity from.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* Builtin

## Scripts
* StringContains
* Exists

## Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| CriticalUsers | The critical users' usernames. | - | - | Optional |
| CriticalEndpoints | The critical endpoints' hostnames. | - | - | Optional |
| CriticalGroups | The critical active directory groups DN. | - | - | Optional |
| QualysSeverity | The qualys vulnerability severity score (1-5). | Severity | Qualys | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->
