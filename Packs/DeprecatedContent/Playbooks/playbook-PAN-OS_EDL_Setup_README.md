DEPRECATED. Use "PAN-OS EDL Setup v3" playbook instead. Configures an external dynamic list in PAN-OS.
In the event that the file exists on the web server, it will sync it to Cortex XSOAR. Then it will create an EDL object and a matching rule.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS-Commit-Configuration
* PAN-OS - Create Or Edit Rule

### Integrations
This playbook does not use any integrations.

### Scripts
* AreValuesEqual

### Commands
* panorama-create-edl
* pan-os-edl-update-from-external-file
* pan-os-edl-update
* pan-os-edl-get-external-file-metadata

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| list-name | The name of the list that will store the IOCs. The name of the file on the web server. This file name is the same as the name of the list with the extension ".txt" added. | Required |
| ioc-type | The type of the IOCs that the list will store. Can be "ip", "url", or "domain". | Required |
| action-type | The action that will be defined in the rule. Can be, "allow", "deny", or "drop". | Required |
| auto-commit | Whether to commit the configuration automatically. | Optional |
| log-forwarding-object-name | The server address to which to forward logs. | Optional |
| web-server-ip | The IP address of the web server on which the files are stored. The web server IP address is configured in the integration instance. | Required |
| pre-post-rulebase | Either pre-rulebase or post-rulebase,  according to the rule structure. | Required |
| rule-position | The position of the rule in the ruleset. Can be, "Top", "Bottom", "Before" or "After". The default position is "Top". | Optional |
| relative-rule-name | If the rule-position that is chosen is before or after, specify the rule name to which it is related. |Optional |
| inbound-or-outbound-rule | Determines if the rule is inbound or outbound. | Optional |
| rule-name | The name of the rule to update, or the name of the rule that will be created. | Optional |
| device-group | The device group to work on. Exists only in panorama! | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_EDL_Setup](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_EDL_Setup.png)
