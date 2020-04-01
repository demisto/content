Calculates incident severity by indicators reputation and user/endpoint membership in critical groups.

Note - current severity will be overwritten and new severity may be lower than the current one.

Playbook inputs:
* CriticalUsers - Comma separated array with usernames of critical users.
* CriticalEndpoints - Comma separated array with hostnames of critical endpoints.
* CriticalGroups - Comma separated array with DN of critical Active Directory groups.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* Builtin

## Scripts
* Print
* StringContains
* Exists

## Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| CriticalUsers | The critical users' usernames. | Optional |
| CriticalEndpoints | The critical endpoints' hostnames. | Optional |
| CriticalGroups | The critical active directory groups DN. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->
