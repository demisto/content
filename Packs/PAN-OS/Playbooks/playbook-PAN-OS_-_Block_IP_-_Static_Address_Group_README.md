Blocks IP addresses using Static Address Groups in Palo Alto Networks Panorama or Firewall.
The playbook receives malicious IP addresses and an address group name as inputs, verifies that the addresses are not already a part of the address group, adds them and commits the configuration.

**Note**: The playbook does not block the address group communication using a policy block rule. This step will be taken once outside of the playbook.

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
* pan-os-edit-address-group
* pan-os-get-address-group

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IP | The IP address to block. | Address | IP | Optional |
| LogForwarding | The Panorama log forwarding object name. | - | - | Optional |
| AddressGroupName | The static address group name. | Demisto Remediation - Static Address Group | - | Optional |
| AutoCommit | Whether to commit the configuration automatically. "Yes" will commit automatically. "No" will commit manually. | No | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_Block_IP_Static_Address_Group](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_Block_IP_Static_Address_Group.png)
