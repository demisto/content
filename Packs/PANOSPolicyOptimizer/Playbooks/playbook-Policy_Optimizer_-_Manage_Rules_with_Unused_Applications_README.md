If you have application-based Security policy rules that allow a large number of applications, you can remove unused applications (applications never seen on the rules) from those rules to tighten them so that they only allow applications actually seen in the rule’s traffic. Identifying and removing unused applications from Security policy rules is a best practice that strengthens your security posture by reducing the attack surface.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Policy Optimizer - Add Applications to Policy Rules
* PAN-OS Commit Configuration

### Integrations
* PANOSPolicyOptimizer

### Scripts
* IsIntegrationAvailable

### Commands
* closeInvestigation
* send-notification
* panorama-delete-rule
* pan-os-po-unused-apps
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| slack_user | Slack user to notify about port based rules. |  | Optional |
| email_address | Email address user to notify about port based rules. |  | Optional |
| auto_commit | Specify whether you want to auto-commit the configuration for the PAN-OS policy changes automatically \(Yes/No\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Policy Optimizer - Manage Rules with Unused Applications](https://github.com/demisto/content/blob/82df056cff9dc4ce8b0753b341a4434593fa4608/Packs/PANOSPolicyOptimizer/doc_files/Policy_Optimizer_-_Manage_Rules_with_Unused_Applications.png?raw=true)