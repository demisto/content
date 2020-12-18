This playbook blocks a Destination IP and Service (tcp or udp port) by creating a rule for a specific Device Group on PAN-OS.
Supported Cortex XSOAR versions: 6.0.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration

### Integrations
* Panorama

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-create-rule
* panorama-create-service
* panorama-list-services
* panorama-create-address

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| LogForwarding | Panorama log forwarding object name. |  | Optional |
| IP | IP address to block. |  | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically.<br/>Yes - Commit automatically.<br/>No - Commit manually. | No | Optional |
| DeviceGroup | Target Device Group. |  | Optional |
| Port | Destination port to block. |  | Optional |
| Protocol | Protocol |  | Optional |
| ServiceNamePrefix | Prefix of the Service name to be created. | xsoar-service- | Optional |
| RuleNamePrefix | Prefix of the Rule name to be created. | xsoar-rule- | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS - Block Destination Service](Insert the link to your image here)