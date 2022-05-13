This playbook blocks IP addresses using Custom Block Rules in Check Point Firewall.
The playbook receives malicious IP addresses as inputs, creates a custom bi-directional rule to block them, and publishes the configuration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Checkpoint - Publish&Install configuration

### Integrations
* CheckPointFirewallV2

### Scripts
* Print
* CompareLists

### Commands
* checkpoint-access-rule-add
* checkpoint-logout
* checkpoint-login-and-get-session-id
* checkpoint-access-rule-list
* checkpoint-group-update
* checkpoint-show-objects
* checkpoint-host-add
* checkpoint-group-add

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | An array of malicious IPs to block \(Can be also provided as a context path. e.g. $\{IP\} \).<br/>Example:     1.1.1.1,2.2.2.2 |  | Required |
| install_policy | Whether the playbook should continue install policy process for Check Point Firewall. | False | Required |
| policy_package | The name of the policy package to be installed. | Standard | Required |
| block_IP_error_handling | If one of the actions for the Block IP playbook fails due to issues on the Check Point Firewall, this input determines whether the playbook continues or stops for manual review. If the playbook continues, the session ID logs out and all Check Point changes are discarded.<br/>Values are "Continue" or "Stop".<br/>The default value is "Stop". | Stop | Optional |
| checkpoint_error_handling | If one of the actions for publish/install policy fails due to issues on the Check Point side, this input determines whether the playbook continues or stops for manual review. If the playbook continues, the session ID logs out and all Check Point changes are discarded.<br/>Values are "Continue" or "Stop".<br/>The default value is "Stop". | Stop | Required |
| rule_layer | Determines which Check Point Firewall rule layer is used.<br/>By default, the  "Network" layer is used, but this can be changed. | Network | Required |
| rule_position | Determines which Check Point Firewall rule position is used.<br/>By default, the "top" position is used, but this can be changed. | top | Required |
| rule_name | Creates a new blocking rule using this Check Point Firewall group.  <br/>Use this option if you have not assigned the appended group to a rule in your firewall policy. | XSOAR - ${incident.id} | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Checkpoint - Block IP - Custom Block Rule](../doc_files/Checkpoint_-_Block_IP_-_Custom_Block_Rule.png)
