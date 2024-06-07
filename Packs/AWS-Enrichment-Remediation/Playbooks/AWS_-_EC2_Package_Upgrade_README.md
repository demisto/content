This playbook upgrades supported package on an AWS EC2 instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* AWS - System Manager

### Scripts

* AWSEC2PackageUpgrade
* Set

### Commands

* aws-ssm-command-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ASM Rule ID | ASM rule ID | ${alert.asmattacksurfaceruleid} | Required |
| Instance ID | Instance ID of the EC2 |  | Required |
| Region | AWS Region of the EC2 instance. |  | Required |
| Assume Role | AWS Role to be assumed. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| remediatedFlag | Boolean value if Package is upgraded or not. | unknown |

## Playbook Image

---

![AWS - EC2 Package Upgrade](../doc_files/AWS_-_EC2_Package_Upgrade.png)
