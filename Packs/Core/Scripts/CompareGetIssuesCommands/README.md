# CompareGetIssuesCommands

Compares the outputs of **core-get-issues** and **core-get-issues-private** for the same set of filter arguments.

The script executes both commands with the provided arguments, then compares the **Raw JSON** and **Entry Context** outputs side-by-side to verify consistency between the public and private versions of the command. Results are displayed as a comparison table in the War Room.

## Use Case

This script is intended for **demo and validation purposes** — to confirm that `core-get-issues` and `core-get-issues-private` return identical data for any given set of filter arguments.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | Python 3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.2.0+ |

## Inputs

All arguments mirror those of `core-get-issues` / `core-get-issues-private`. All arguments are optional — if none are provided, both commands are called with default parameters.

| **Argument Name** | **Description** |
| --- | --- |
| issue_id | The unique ID of the issue. Accepts a comma-separated list. |
| severity | The severity of the issue (low, medium, high, critical). Accepts a comma-separated list. |
| custom_filter | A custom JSON filter object. When used, other filter arguments are ignored. |
| Identity_type | Account type (e.g., USER, SERVICE). Accepts a comma-separated list. |
| agent_id | A unique identifier per agent. Accepts a comma-separated list. |
| action_external_hostname | The hostname to connect to. Accepts a comma-separated list. |
| rule_id | A string identifying the user rule. Accepts a comma-separated list. |
| rule_name | The name of the user rule. Accepts a comma-separated list. |
| issue_name | The issue name. Accepts a comma-separated list. |
| issue_source | The issue source (e.g., XDR Agent, Prisma Cloud). Accepts a comma-separated list. |
| user_name | The name assigned to the user_id during agent runtime. Accepts a comma-separated list. |
| actor_process_image_name | The file name of the binary file. Accepts a comma-separated list. |
| causality_actor_process_image_command_line | SHA256 Causality Graph Object command line. Accepts a comma-separated list. |
| actor_process_image_command_line | Command line used by the process image. Accepts a comma-separated list. |
| action_process_image_command_line | The command line of the process created. Accepts a comma-separated list. |
| actor_process_image_sha256 | SHA256 hash of the binary file (actor). Accepts a comma-separated list. |
| causality_actor_process_image_sha256 | SHA256 hash of the binary file (causality actor). Accepts a comma-separated list. |
| action_process_image_sha256 | SHA256 of the binary file (action process). Accepts a comma-separated list. |
| action_file_image_sha256 | SHA256 of the file related to the event. Accepts a comma-separated list. |
| action_registry_name | The name of the registry. Accepts a comma-separated list. |
| action_registry_key_data | The key data of the registry. Accepts a comma-separated list. |
| host_ip | The host IP address. Accepts a comma-separated list. |
| action_local_ip | The local IP address for the connection. Accepts a comma-separated list. |
| action_remote_ip | Remote IP address for the connection. Accepts a comma-separated list. |
| issue_action_status | Issue action status (e.g., detected, prevented). |
| action_local_port | The local port for the connection. Accepts a comma-separated list. |
| action_remote_port | The remote port for the connection. Accepts a comma-separated list. |
| dst_action_external_hostname | The destination hostname. Accepts a comma-separated list. |
| sort_field | The field by which to sort the results. Default: source_insert_ts. |
| sort_order | The order in which to sort the results (ASC or DESC). |
| page | The page number for pagination. Default: 0. |
| page_size | The number of issues to return per page. Default: 50. |
| start_time | Start time filter. Supports epoch timestamp or ISO format (YYYY-MM-DDThh:mm:ss). |
| end_time | End time filter. Supports epoch timestamp or ISO format (YYYY-MM-DDThh:mm:ss). |
| starred | Whether the issue is starred (true or false). |
| mitre_technique_id_and_name | The MITRE attack technique. Accepts a comma-separated list. |
| issue_category | The category of the issue. Accepts a comma-separated list. |
| issue_domain | The domain of the issue (Health, Hunting, IT, Posture, Security). Accepts a comma-separated list. |
| issue_description | The description of the issue. Accepts a comma-separated list. |
| os_actor_process_image_sha256 | The SHA256 hash of the OS actor process image. Accepts a comma-separated list. |
| action_file_macro_sha256 | The SHA256 hash of the action file macro. Accepts a comma-separated list. |
| status | The status progress (New, In Progress, Resolved). Accepts a comma-separated list. |
| not_status | Exclude issues with this status. Accepts a comma-separated list. |
| asset_ids | The asset IDs related to the issue. Accepts a comma-separated list. |
| assignee | The assignee of the issue. Use "unassigned" or "assigned" as special values. |
| output_keys | A comma-separated list of output keys to include in the context. |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CompareGetIssues.args_tested | The list of argument names passed to both commands. | List |
| CompareGetIssues.raw_json_status | Whether the Raw JSON outputs matched (✅ Match / ❌ Mismatch). | String |
| CompareGetIssues.entry_context_status | Whether the Entry Context outputs matched (✅ Match / ❌ Mismatch). | String |
| CompareGetIssues.overall | Overall comparison result — FULL MATCH or MISMATCH DETECTED. | String |

## War Room Output

The script renders a `tableToMarkdown` table in the War Room with the following columns:

| Column | Description |
| --- | --- |
| **Argument** | The argument name passed to both commands |
| **Value Used** | The value provided for that argument |
| **Raw JSON** | ✅ Match or ❌ Mismatch for the raw API response |
| **Entry Context** | ✅ Match or ❌ Mismatch for the XSOAR context output |

A summary line at the bottom shows the **Overall Result**.

## Example Usage

```
!CompareGetIssuesCommands severity=high status=New page_size=10
```

```
!CompareGetIssuesCommands issue_id=abc-123,def-456
```

```
!CompareGetIssuesCommands
```
*(Runs both commands with default parameters)*
