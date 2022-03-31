Blocks malicious URLs using all integrations that are enabled.

Supported integrations for this playbook:
* Palo Alto Networks Minemeld
* Palo Alto Networks PAN-OS
* Zscaler

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* PAN-OS - Block URL - Custom URL Category
* Add Indicator to Miner - Minemeld
* PAN-OS - Block IP and URL - External Dynamic List

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
* zscaler-blacklist-url

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| URLBlacklistMiner | The name of the URL block list Miner in Minemeld. | Optional |
| URL | The array of malicious URLs to block. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block_URL_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_URL_Generic.png)
