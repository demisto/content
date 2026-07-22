This is an AWS script that upgrades a package on the AWS EC2 instance using AWS Systems manager.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| instance_id | ID of the AWS Ec2 instance. |
| asm_rule_id | ASM alert rule ID. |
| region | Region of the EC2 instance. |
| assume_role | Name of an AWS role to assume \(should be the same for all organizations\). |
| account_id | AWS account ID. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| awspackageupgrade | The command ID of the command initiated by the AWS SSM command. | Unknown |
