Launches a C2sec scan by domain name and waits for the scan to finish by polling its status in pre-defined intervals.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* GenericPolling

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
* irisk-rescan-domain
* irisk-get-scan-results
* irisk-get-domain-issues
* irisk-get-scan-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DomainName | The domain name. | - | Required |
| interval | How often the polling command should run (in minutes). | 1 | Optional |
| timeout | The amount of time to wait before a timeout occurs (in minutes). | 600 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![C2SEC_Domain_Scan](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/C2SEC_Domain_Scan.png)
