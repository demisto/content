Gets a command with its arguments, validates the command and the arguments, and then parses it to use in the Cortex XSOAR context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | troubleshoot |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Integration Troubleshooting

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| instance_name | Instance on which to check the command. |
| command_line | Command line to process. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CommandArgs.instance_name | The instance name. | String |
| CommandArgs.command | The command. | String |
| CommandArgs.Arguments | The arguments in the command. | String |
| CommandArgs.Arguments.using | The instance name. All other arguments are dynamically provided. | String |
