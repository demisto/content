Searches Cortex Issues.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Cortex Core - Platform
* core-get-issues

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| issue_id | The unique ID of the issue. |
| severity | The severity of the issue. |
| Identity_type | Account type. |
| issue_name | The issue name. |
| issue_source | The issue source. |
| actor_process_image_sha256 | Initiator SHA256 actor process image. |
| causality_actor_process_image_sha256 | CGO SHA256 hash of causality actor process image. |
| action_process_image_sha256 | Target process SHA256 of action process image. |
| sort_field | The field by which to sort the results. |
| sort_order | The order in which to sort the results. |
| offset | The first page from which we bring the issues. |
| limit | The last page from which we bring the issues. |
| additional_output_fields | Additional output fields. |
| start_time | Supports epoch timestamp and simplified extended ISO format \(YYYY-MM-DDThh:mm:ss\). |
| end_time | Supports epoch timestamp and simplified extended ISO format \(YYYY-MM-DDThh:mm:ss\). If start time is provided without end_time it will be from start_time until now. |
| issue_category | The category of the issue. |
| issue_domain | The domain of the issue. |
| issue_description | The description of the issue. |
| os_actor_process_image_sha256 | OS Parent SHA256 hash of the OS actor process image. |
| action_file_macro_sha256 | File Macro SHA256 hash of the action file macro. |
| status | The progress status. |
| not_status | Not progress status. |
| asset_ids | The assets ids related to the issue. |
| assignee | The assignee of the issue. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.Issue.internal_id | The internal ID of the issue. | String |
| Core.Issue.alert_source | The source of the alert. | String |
| Core.Issue.status.progress | The progress status of the issue. | String |
| Core.Issue.assigned_to_pretty | The pretty name of the user assigned to the issue. | String |
| Core.Issue.assigned_to | The user assigned to the issue. | String |
| Core.Issue.assetid | The asset ID related to the issue. | String |
| Core.Issue.action_file_macro_sha256 | File Macro SHA256 hash of the action file macro. | String |
| Core.Issue.os_actor_process_image_sha256 | OS Parent SHA256 hash of the OS actor process image. | String |
| Core.Issue.alert_domain | The domain of the alert. | String |
| Core.Issue.action_process_image_sha256 | Action process image SHA256 hash. | String |
| Core.Issue.causality_actor_process_image_sha256 | Causality actor process image SHA256 hash. | String |
| Core.Issue.actor_process_image_sha256 | Actor process image SHA256 hash. | String |
| Core.Issue.source_insert_ts | The detection timestamp. | Number |
| Core.Issue.alert_name | The name of the issue. | String |
| Core.Issue.severity | The severity of the issue. | String |
| Core.Issue.alert_category | The category of the issue. | String |
| Core.Issue.alert_name | The issue name. | String |
| Core.Issue.alert_description | The issue description. | String |
| Core.Issue.Identity_type | The identity type of the account. | String |
