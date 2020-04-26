Sync a list of IP addresses to an AWS Security Group.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin
* AWS - EC2

### Scripts
* Set
* CompareLists

### Commands
* aws-ec2-revoke-security-group-ingress-rule
* closeInvestigation
* removeIndicatorField
* setIndicator
* aws-ec2-describe-security-groups
* aws-ec2-authorize-security-group-ingress-rule

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
|  |  |  |  | Optional |
| IP | IP addresses to set in the whitelist |  |  | Required |
| SecurityGroupName | Name of the AWS Security Group to update |  |  | Required |
| IndicatorTagName | Name of the Indicator Tag to apply to any IPs whitelisted by this playbook. | AWS_IP_Whitelist |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->