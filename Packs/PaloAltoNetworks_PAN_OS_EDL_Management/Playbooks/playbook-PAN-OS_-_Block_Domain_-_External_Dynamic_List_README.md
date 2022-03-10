Blocks domains using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the `PAN-OS EDL Setup v3` sub-playbook
(otherwise the list will be configured), and adds the input Domains to the relevant lists.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS EDL Setup v3

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-refresh-edl
* panorama
* pan-os-edl-update

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Domain | The domain to block. | Name | Domain | Optional |
| DomainListName | The domain list from the instance context with which to override the remote file. | Demisto Remediation - Domain EDL | - | Optional |
| LogForwarding | The log forwarding object name. | - | - | Optional |
| EDLServerIP | The EDL server IP address. | - | - | Optional |
| AutoCommit | Whether to commit the configuration automatically. "Yes" will commit automatically. "No" will commit manually. | No | - | Optional |
| pre-post-rulebase | The pre-rulebase or post-rulebase, according to the rule structure. | pre-rulebase | - | Optional |
| rule-position | The position of the rule in the ruleset. Can be, "Top", "Bottom", "Before", or "After". | - | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_Block_Domain_External_Dynamic_List](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_Block_Domain_External_Dynamic_List.png)
