DEPRECATED. Use "PAN-OS - Block IP and URL - External Dynamic List v2" playbook instead. Blocks IP addresses and URLs using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the `PAN-OS EDL Setup` sub-playbook (otherwise the list will be configured), and adds the input IP addresses and URLs to the relevant lists.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS EDL Setup

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
| IPListName | The IP address list from the instance context with which to override the remote file. | XSOAR Remediation - IP EDL | - | Optional |
| IP | The IP address to block. | Address | IP | Optional |
| URL | The URL to block. | Data | URL | Optional |
| URLListName | The URL list from the instance context with which to override the remote file. | XSOAR Remediation - URL EDL | - | Optional |
| LogForwarding | The log forwarding object name. | - | - | Optional |
| EDLServerIP | The EDL server IP address. | - | - | Optional |
| AutoCommit | Whether to commit the configuration automatically. "Yes" will commit automatically. "No" will Commit manually. | No | - | Optional |
| url-pre-post-rulebase | Either pre-rulebase or post-rulebase, according to the rule structure. | pre-rulebase | - | Optional |
| ip-pre-post-rulebase | Either pre-rulebase or post-rulebase, according to the rule structure. | pre-rulebase | - | Optional |
| url-rule-position | The position of the rule in the ruleset. Can be, "Top", "Bottom", "Before", or "After". | - | - | Optional |
| ip-rule-position | The position of the rule in the ruleset. Can be, "Top", "Bottom", "Before", or "After". | - | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_Block_IP_and_URL_External_Dynamic_List](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_Block_IP_and_URL_External_Dynamic_List.png)
