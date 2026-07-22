This playbook helps identify and remove unused applications from security policy rules. If you have application-based security policy rules that allow a large number of applications, you can remove unused applications (applications never seen on the rules) from those rules to allow only applications actually seen in the rule’s traffic. This strengthens your security posture by reducing the attack surface.


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
| email_address | User email address to notify about port based rules. |  | Optional |
| auto_commit | Specifies whether you want to auto-commit the configuration for the PAN-OS policy changes automatically \(Yes/No\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Policy Optimizer - Manage Rules with Unused Applications](https://github.com/demisto/content/raw/82df056cff9dc4ce8b0753b341a4434593fa4608/Packs/PANOSPolicyOptimizer/doc_files/Policy_Optimizer_-_Manage_Rules_with_Unused_Applications.png?raw=true)
