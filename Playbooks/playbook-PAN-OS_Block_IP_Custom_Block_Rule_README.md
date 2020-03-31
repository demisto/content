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
* panorama-create-address
* panorama-custom-block-rule

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

![PAN-OS_Block_IP_Custom_Block_Rule](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/PAN-OS_Block_IP_Custom_Block_Rule.png)
