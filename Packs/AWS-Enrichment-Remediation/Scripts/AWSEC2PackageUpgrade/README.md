This is an AWS script that upgrades a package on the AWS EC2 instance.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Dependencies

---
This script uses the following commands and scripts.

* aws-ssm-command-run
* AWS - System Manager
* aws-ssm-inventory-entry-list

## Used In

---
This script is used in the following playbooks and scripts.

AWS - EC2 Package Upgrade

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| instance_id | ID of the AWS Ec2 instance. |
| asm_rule_id | ASM alert rule ID. |
| region | Region of the EC2 instance. |
| assume_role | Name of an AWS role to assume \(should be the same for all organizations\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| awsec2packageupgrade | The command ID of the command initiated by AWS SSM command. | Unknown |
