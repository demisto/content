Utilizes the Dynamic Address Group (DAG) capability of PAN-OS.
DAG enables analysts to create a rule one time, where the group is the source/destination, and adds IP addresses dynamically without the need to commit the configuration every time.

The playbook checks if the given tag already exists. If the tag exists, then the IP address is added to the tag.

If the tag does not exist, a new address group is created with the given tag and a matching rule, and the configuration is committed. 


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration
* PAN-OS - Create Or Edit Rule

### Integrations
This playbook does not use any integrations.

### Scripts
* AreValuesEqual

### Commands
* panorama-list-address-groups
* panorama-create-address-group
* panorama-register-ip-tag

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| tag_name | The name of the tag to add to PAN-OS. | - | Required |
| ip_list | The list of the IP addresses to block. | 7.7.7.6 | Required |
| address_group_name | The name of the group that will be created if the tag does not exist. | - | Required |
| rule_name | The name of the rule to update, or the name of the rule that will be created. | - |Optional |
| auto_commit | Whether the rule will be committed automatically. | - | Optional |
| log-forwarding-object-name | The server address to which to forward logs. |-  |Optional |
| rule-position | The position of the rule in the ruleset. Can be, "Top", "Bottom", "Before", or "After". The default position is "Top". | - | Optional |
| relative-rule-name | If the rule-position that is chosen is before or after, specify the rule name to which it is related. |-  | Optional |
| inbound-or-outbound-rule | Determines if the rule is inbound or outbound. | - |Optional |
| action-type | The action that will be defined in the rule. Can be, "allow", "deny", or "drop". |-  | Optional |
| pre-post-rulebase | Whether the rule is a pre-rulebase or post-rulebase rule, according to the rule structure. Exists only in panorama. | - |Required |
| device-group | The device group for which to return results. For panorama only. | - |Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_DAG_Configuration](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_DAG_Configuration.png)
