XDR Retro Hunt is an automated threat hunting playbook created for Palo Alto Network Cortex XDR, it will fetch indicators from the Threat Intelligence Library / Threat Intelligence module for a given time and verdict (default malicious / yesterday) and execute XQL queries for every found indicator, at the end it will report the number of events found.

v1:
- Hunt for IP addresses, File Hashes and Domain names
- default limit for indicators : 10 (changeable via input)
- default verdict malicious (changeable via input)
- default time "yesterday" (changeable via input)
- Print amount of events found for each type of hunt

(!!!) Higher limits can impact the performance of XSOAR and XDR


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* XDR Retro Hunt - Query

### Integrations
This playbook does not use any integrations.

### Scripts
* GetIndicatorsByQuery
* Print

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| limit |  | 100 | Optional |
| verdict |  | malicious | Optional |
| time |  | {yesterday} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![XDR Retro Hunt](Insert the link to your image here)