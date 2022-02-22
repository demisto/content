Publish the Checkpoint Firewall configuration and install policy over all the gateways that are available.
Please note that only CheckPoint admin users can run this playbook.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* CheckPoint_FW

### Scripts
* PrintErrorEntry

### Commands
* checkpoint-gateways-list
* checkpoint-packages-list
* checkpoint-install-policy
* checkpoint-show-task
* checkpoint-logout
* checkpoint-publish

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| sid | SID \- Session unique identifier as it returned by the login request required for publish changes. done by this SID will be seen by all users only after publish is called and finish. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.
