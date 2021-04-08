

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* updateIndicatorNMAP

### Commands
* nmap-scan

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| hosts | The hosts to scan. Accepts comman separated list |  | Required |
| ports | The ports to scan. Accept NMAP compatible port definitions. Examples:<br/>22<br/>1-65535<br/> U:53,111,137,T:21-25,80,139,8080,S:9<br/> |  | Required |
| enumerate_service | Whether to enumerate the service attached to the port \(true or false\) | true | Optional |
| detect_OS | Whether or not to attempt OS detection \(true or false\) | true | Optional |
| isIPv6 | Whether or not this is an IPv6 scan \(true or false\) | false | Optional |
| update_indicator | Whether or not to update the indicator with the relevant information \(true or false\) | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NMAP Enrichment](Insert the link to your image here)