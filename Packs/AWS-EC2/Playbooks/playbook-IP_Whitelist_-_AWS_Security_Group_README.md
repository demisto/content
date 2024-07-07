Sync a list of IP addresses to an AWS Security Group.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* AWS - EC2
* AWS-EC2

### Scripts
* Set
* CompareLists

### Commands
* removeIndicatorField
* aws-ec2-describe-security-groups
* aws-ec2-revoke-security-group-ingress-rule
* setIndicator
* aws-ec2-authorize-security-group-ingress-rule

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| IP | IP addresses to set in the allow list |  | Required |
| SecurityGroupName | Name of the AWS Security Group to update |  | Required |
| IndicatorTagName | Name of the Indicator Tag to apply to any IPs allowed by this playbook. | AWS_IP_Whitelist | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![IP Whitelist - AWS Security Group](https://raw.githubusercontent.com/demisto/content/859f073f59aabaef8e36ec39eed63778cd2b9856/Packs/AWS-EC2/doc_files/IP_Whitelist_-_AWS_Security_Group.png)