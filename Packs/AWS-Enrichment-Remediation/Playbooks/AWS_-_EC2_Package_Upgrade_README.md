This playbook upgrades supported package on an AWS EC2 instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* AWS - System Manager

### Scripts

* Set
* AWSEC2PackageUpgrade

### Commands

* aws-ssm-command-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ASM Rule ID | ASM rule ID | InsecureOpenSSH | Required |
| Instance ID | Instance ID of the EC2 | i-0e3097bd313c4b430 | Required |
| Version | Version of the Package | openssh-9.7p1 | Required |
| Region | AWS Region of the EC2 instance. | us-east-1 | Optional |
| Assume Role | AWS Role to be assumed. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| packageUpgradeFlag | Boolean value if Package is upgraded or not. | unknown |

## Playbook Image

---

![AWS - EC2 Package Upgrade](../doc_files/AWS_-_EC2_Package_Upgrade.png)
