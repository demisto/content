This playbook is triggered by the PAN-OS Policy Optimizer incident type, and can go through any of the following sub-playbooks:
- Policy Optimizer - Manage Unused Rules
- Policy Optimizer - Manage Rules with Unused Applications
- Policy Optimizer - Manage Port Based Rules

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Policy Optimizer - Manage Rules with Unused Applications
* Policy Optimizer - Manage Port Based Rules
* Policy Optimizer - Manage Unused Rules

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| slack_user | Slack user to notify about unused rules. |  | Optional |
| email_address | Email address user to notify about unused rules. |  | Optional |
| auto_commit | Specify whether you want to auto-commit the configuration for the PAN-OS policy changes automatically \(Yes/No\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Policy Optimizer - Generic](https://github.com/demisto/content/blob/82df056cff9dc4ce8b0753b341a4434593fa4608/Packs/PANOSPolicyOptimizer/doc_files/Policy_Optimizer_-_Generic.png?raw=true)