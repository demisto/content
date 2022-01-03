This playbook will use an object group in order to block IPs.
The playbook receives malicious IP addresses as inputs, checks if the object group exists (and if not will create one), and will append the related IPs in that object.
Please remember to assign the appended group to a rule in your FW policy. If not, you can use the `rule_name` and the playbook will create for this one.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Checkpoint - Publish&Install configuration

### Integrations
* CheckPointFirewallV2

### Scripts
* isError
* Print
* SetAndHandleEmpty
* CompareLists

### Commands
* checkpoint-access-rule-add
* checkpoint-host-add
* checkpoint-group-add
* checkpoint-login-and-get-session-id
* checkpoint-show-objects
* checkpoint-group-get
* checkpoint-logout
* checkpoint-group-update

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | An array of malicious IPs to block \(Can be also provided as a context path. e.g. $\{IP\} \).<br/>Example:     1.1.1.1,2.2.2.2 |  | Required |
| install_policy | Input True / False for playbook to continue install policy process for checkpoint Firewall. | False | Required |
| policy_package | The name of the policy package to be installed. | Standard | Required |
| block_IP_error_handling | In case one of the actions for block IP playbook fails due to issues on the Checkpoint side, This input will determine whether the playbook will continue or stop for manual review. Also, in case of Continue the session id will logout and all changes will discard.<br/>Values can be "Continue" or "Stop".<br/>The default value will be "Stop". | Stop | Optional |
| checkpoint_error_handling | In case one of the actions for publish/install policy fails due to issues on the Checkpoint side, This input will determine whether the playbook will continue or stop for manual review. Also, in case of Continue the session id will logout and all changes will discard.<br/>Values can be "Continue" or "Stop".<br/>The default value will be "Stop". | Stop | Required |
| group_name | Provide the group name to be appended with the provided IPs. <br/>The group will be created in case it did not exist before. |  | Required |
| rule_name | This input determines whether the Checkpoint firewall rule name is used. With this name - a new blocking rule, with mentioned the group,  will be created  |  | Optional |
| rule_layer | This input determines whether the Checkpoint firewall rule layer is used.<br/>By default, we use the "Network" layer, but can be changed. | Network | Optional |
| rule_position | This input determines whether the Checkpoint firewall rule position is used.<br/>By default, we are using the "top" position but can be changed. | top | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Checkpoint - Block IP - Append Group](../doc_files/Checkpoint_-_Block_IP_-_Append_Group.png)