Publish the Checkpoint Firewall configuration and install policy over all the gateways that are available.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* CheckPointFirewallV2
* CheckPointFirewall_v2

### Scripts
* PrintErrorEntry

### Commands
* checkpoint-packages-list
* checkpoint-show-task
* checkpoint-gateways-list
* checkpoint-publish
* checkpoint-logout
* checkpoint-install-policy

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| sid | SID - Session unique identifier as it returned by the login request required for publish /install changes. Change configuration  will be seen by all users only after publish is called and finish with the specific SID. |  | Required |
| install_policy | Input True / False for playbook to continue install policy process for checkpoint Firewall. | False | Required |
| policy_package | The name of the policy package to be installed. | Standard | Required |
| action_manual_handling | Input True / False. When one of the actions publish/install policy stops due to problem or error, the Playbook will stop in favor of further manual handling. | True | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Checkpoint - Publish&Install configuration](../doc_files/Checkpoint_-_Publish&Install_configuration.png)