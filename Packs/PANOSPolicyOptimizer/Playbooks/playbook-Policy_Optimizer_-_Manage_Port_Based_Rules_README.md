This playbook migrates port-based rules to application-based allow rules to reduce the attack surface and safely enable applications on your network.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Policy Optimizer - Add Applications to Policy Rules
* PAN-OS Commit Configuration

### Integrations
PANOSPolicyOptimizer

### Scripts
IsIntegrationAvailable

### Commands
* send-notification
* closeInvestigation
* pan-os-po-no-apps
* panorama-delete-rule
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| slack_user | Slack user to notify about port based rules. |  | Optional |
| email_address | User email address to notify about port based rules. |  | Optional |
| auto_commit | Specifies whether you want to auto-commit the configuration for the PAN-OS policy changes automatically \(Yes/No\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Policy Optimizer - Manage Port Based Rules](https://github.com/demisto/content/raw/82df056cff9dc4ce8b0753b341a4434593fa4608/Packs/PANOSPolicyOptimizer/doc_files/Policy_Optimizer_-_Manage_Port_Based_Rules.png?raw=true)
