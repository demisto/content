Calculates and sets the incident severity based on the combination of the current incident severity, and the severity returned from the `Evaluate Severity - Set By Highest DBotScore` playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Evaluate Severity - Set By Highest DBotScore

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
| DBotScore | The list of DBotScores of indicators. | None | DBotScore | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![Calculate_Severity_Standard](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Calculate_Severity_Standard.png)
