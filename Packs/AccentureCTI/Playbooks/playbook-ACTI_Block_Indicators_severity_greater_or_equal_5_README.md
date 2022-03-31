Block Indicators with severity 5 or more

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Domain - Generic
* Block IP - Generic v2
* Block URL - Generic

### Integrations
* ACTI Indicator Query

### Scripts
This playbook does not use any scripts.

### Commands
* url
* domain
* ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | Considers IP\(s\) which have severity 5 or more | ${DBotScore.Indicator} | Optional |
| URL | Considers URL\(s\) which have severity 5 or more | ${DBotScore.Indicator} | Optional |
| Domain | Considers Domain\(s\) which have severity 5 or more | ${DBotScore.Indicator} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![ACTI Block Indicators | severity >= 5](Insert the link to your image here)