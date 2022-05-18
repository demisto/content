Blocks IP addresses using Custom Block Rules in Palo Alto Networks Panorama or Firewall.
The playbook receives malicious IP addresses as inputs, creates a custom bi-directional rule to block them, and commits the configuration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-create-address
* pan-os-custom-block-rule

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| LogForwarding | The Panorama log forwarding object name. | - | - | Optional |
| IP | The IP address to block. | Address | IP | Optional |
| AutoCommit | Whether to commit the configuration automatically. "Yes", will commit automatically. "No" will commit manually. | No | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_Block_IP_Custom_Block_Rule](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_Block_IP_Custom_Block_Rule.png)
