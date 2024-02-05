Given the IP address this playbook enriches EC2 and IAM information.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* AWS - EC2

### Scripts

* AWSAccountHierarchy
* Set

### Commands

* aws-ec2-describe-ipam-resource-discoveries
* aws-ec2-describe-security-groups
* aws-ec2-get-ipam-discovered-public-addresses
* aws-ec2-describe-regions
* aws-ec2-describe-instances

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| AwsIP | AWS IP in alert | alert.remoteip | Required |
| AWSAssumeRoleName | If assuming roles for AWS, this is the name of the role to assume \(should be the same for all organizations\). |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWS.EC2.Instances | AWS EC2 information. | unknown |
| AWS.EC2.SecurityGroups | AWS Security group information. | unknown |
| AWSHierarchy | AWS account hierarchy information. | unknown |

## Playbook Image

---

![AWS - Enrichment](../doc_files/AWS_-_Enrichment.png)
