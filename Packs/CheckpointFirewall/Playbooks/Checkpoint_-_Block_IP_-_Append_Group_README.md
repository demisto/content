This playbook will use an object group in order to block IPs.
The playbook receives malicious IP addresses as inputs, checks if the object group exists (and if not will create one), and will append the related IPs in that object.
Please remember to assign the appended group to a rule in your FW policy.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Checkpoint - Publish&Install configuration

### Integrations
* CheckPointFirewallV2

### Scripts
* Print
* isError
* CompareLists

### Commands
* checkpoint-group-add
* checkpoint-group-update
* checkpoint-host-add
* checkpoint-show-objects
* checkpoint-login-and-get-session-id
* checkpoint-group-get
* checkpoint-logout

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | Array of malicious IPs to block. |  | Required |
| install_policy | Input True / False for playbook to continue install policy process for checkpoint Firewall. | False | Required |
| policy_package | The name of the policy package to be installed. | Standard | Required |
| block_IP_error_handling | In case one of the actions for block IP playbook fails due to issues on the Checkpoint side, This input will determine whether the playbook will continue or stop for manual review. Also, in case of Continue the session id will logout and all changes will discard.<br/>Values can be "Continue" or "Stop".<br/>The default value will be "Stop". | Stop | Optional |
| checkpoint_error_handling | In case one of the actions for publish/install policy fails due to issues on the Checkpoint side, This input will determine whether the playbook will continue or stop for manual review. Also, in case of Continue the session id will logout and all changes will discard.<br/>Values can be "Continue" or "Stop".<br/>The default value will be "Stop". | Stop | Required |
| group_name | Provide the group name to be appended with the provided IPs. <br/>The group will be created in case it did not exist before. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Checkpoint - Block IP - Append Group](../doc_files/Checkpoint_-_Block_IP_-_Append_Group.png)