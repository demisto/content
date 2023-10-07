Collects all results from previous tasks. (Available from Cortex XSOAR 5.0.0.)

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
| succeeded_changed_params | Parameters that were changed and caused the integration to run successfully. |
| file_names | All file entry IDs in the incident. |
| configuration | The raw configuration output. |
| errors | The errors when testing the instance. |
| execute_command_errors | Errors from the ExecuteCommand automation. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TroubleshootAggregateResults.configuration_file_name | The name of the file the configuration was saved to. | String |
| TroubleshootAggregateResults.summary_file_name | The name of the file the summary was saved to. | String |
