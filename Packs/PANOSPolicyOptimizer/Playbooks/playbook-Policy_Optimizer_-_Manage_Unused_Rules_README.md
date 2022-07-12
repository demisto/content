This playbook helps identify and remove unused rules that do not pass traffic in your environment.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
PAN-OS Commit Configuration

### Integrations
PAN-OS Policy Optimizer

### Scripts
IsIntegrationAvailable

### Commands
* pan-os-po-get-rules
* panorama-delete-rule
* send-notification
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| slack_user | Slack user to notify about unused rules. |  | Optional |
| email_address | User email address user to notify about unused rules. |  | Optional |
| auto_commit | Specifies whether you want to auto-commit the configuration for the PAN-OS policy changes automatically \(Yes/No\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Policy Optimizer - Manage Unused Rules](https://github.com/demisto/content/raw/82df056cff9dc4ce8b0753b341a4434593fa4608/Packs/PANOSPolicyOptimizer/doc_files/Policy_Optimizer_-_Manage_Unused_Rules.png?raw=true)
