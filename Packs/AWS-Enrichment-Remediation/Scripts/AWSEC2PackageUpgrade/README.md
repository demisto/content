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
* aws-ssm-inventory-entry-list
* AWS - System Manager

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| instance_id | ID of the AWS Ec2 instance. |
| asm_rule_id | ASM alert rule ID. |
| version | Version of the package to be installed. |
| region | Region of the EC2 instance. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWSCommandID | This is the command Id of the command initiated by AWS SSM command | Unknown |
