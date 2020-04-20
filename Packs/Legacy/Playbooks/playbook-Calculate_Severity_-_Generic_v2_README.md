Calculates and assigns the incident severity based on the highest returned severity level from the following calculations:

- DBotScores of indicators
- Critical assets
- Email authenticity
- Current incident severity

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Calculate Severity - Critical Assets v2
* Calculate Severity - DBotScore v2
* Calculate Severity - Email Authenticity

## Integrations
* Builtin

## Scripts
* Set

## Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| DBotScore | The array of all indicators associated with the incident.  | None | DBotScore | Optional |
| CriticalUsers | The CSV of usernames of critical users. | admin,administrator | - | Optional |
| CriticalEndpoints | The CSV of hostnames of critical endpoints. | admin | - | Optional |
| CriticalGroups | The CSV of DN names of critical AD groups. | admins,administrators | - | Optional |
| Account | The user accounts to check against the critical lists. | None | Account | Optional |
| Endpoint | The endpoints to check against the CriticalEndpoints list. | None | Endpoint | Optional |
| EmailAuthenticityCheck | Indicates the email authenticity resulting from the `EmailAuthenticityCheck` script. Possible values are, "Pass", "Fail", "Suspicious", and "Undetermined'. | AuthenticityCheck | Email | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CriticalAssets | All critical assets involved in the incident. | unknown |
| CriticalAssets.CriticalEndpoints | The critical endpoints involved in the incident. | unknown |
| CriticalAssets.CriticalEndpointGroups | The critical endpoint-groups involved in the incident. | unknown |
| CriticalAssets.CriticalUsers | The critical users involved in the incident. | unknown |
| CriticalAssets.CriticalUserGroups | The critical user-groups involved in the incident. | unknown |

## Playbook Image
---
![Calculate_Severity_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Calculate_Severity_Generic_v2.png)
