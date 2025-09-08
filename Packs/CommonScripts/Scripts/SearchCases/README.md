Retrieves cases based on the provided filters.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.6.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Cortex Core - Platform
* core-get-case-extra-data
* core-get-cases

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| case_id_list | A comma seperated list of case IDs. |
| start_time | The start time for filtering according to case creation time. Supports free text relative and absolute times. For example: 7 days ago, 2023-06-15T10:30:00Z, 13/8/2025. |
| end_time | The end time for filtering according to case creation time. Supports free text relative and absolute times. For example: 7 days ago, 2023-06-15T10:30:00Z, 13/8/2025. |
| sort_by_creation_time | Sorts returned cases by the date/time that the case was created \("asc" - ascending, "desc" - descending\). |
| status | Filters only cases in the specified status. The options are: new, under_investigation, resolved_known_issue, resolved_false_positive, resolved_true_positive resolved_security_testing, resolved_other, resolved_auto. |
| starred | Whether the case is starred \(Boolean value: true or false\). |
| page | Page number \(for pagination\). The default is 0 \(the first page\). |
| page_size | Maximum number of cases to return per page. The default and maximum is 100. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.Case.case_id | Unique ID assigned to each returned case. | String |
| Core.Case.case_name | Name of the case. | String |
| Core.Case.creation_time | Timestamp when the case was created. | Number |
| Core.Case.modification_time | Timestamp when the case was last modified. | Number |
| Core.Case.detection_time | Timestamp when the first issue was detected in the case. May be null. | Date |
| Core.Case.status | Current status of the case. | String |
| Core.Case.severity | Severity level of the case. | String |
| Core.Case.description | Description of the case. | String |
| Core.Case.assigned_user_mail | Email address of the assigned user. May be null. | String |
| Core.Case.assigned_user_pretty_name | Full name of the assigned user. May be null. | String |
| Core.Case.issue_count | Total number of issues in the case. | Number |
| Core.Case.low_severity_issue_count | Number of issues with low severity. | Number |
| Core.Case.med_severity_issue_count | Number of issues with medium severity. | Number |
| Core.Case.high_severity_issue_count | Number of issues with high severity. | Number |
| Core.Case.critical_severity_issue_count | Number of issues with critical severity. | Number |
| Core.Case.user_count | Number of users involved in the case. | Number |
| Core.Case.host_count | Number of hosts involved in the case. | Number |
| Core.Case.notes | Notes related to the case. May be null. | String |
| Core.Case.resolve_comment | Comments added when resolving the case. May be null. | String |
| Core.Case.resolved_timestamp | Timestamp when the case was resolved. | Number |
| Core.Case.manual_severity | Severity manually assigned by the user. May be null. | Number |
| Core.Case.manual_description | Description manually provided by the user. | String |
| Core.Case.xdr_url | URL to view the case in Cortex XDR. | String |
| Core.Case.starred | Indicates whether the case is starred. | Boolean |
| Core.Case.starred_manually | True if the case was starred manually; false if starred by rules. | Boolean |
| Core.Case.hosts | List of hosts involved in the case. | Array |
| Core.Case.users | List of users involved in the case. | Array |
| Core.Case.case_sources | Sources of the case. | Array |
| Core.Case.rule_based_score | Score based on rules. | Number |
| Core.Case.manual_score | Manually assigned score. May be null. | Number |
| Core.Case.wildfire_hits | Number of WildFire hits. | Number |
| Core.Case.issues_grouping_status | Status of issue grouping. | String |
| Core.Case.mitre_tactics_ids_and_names | List of MITRE ATT&amp;CK tactic IDs and names associated with the case. | Array |
| Core.Case.mitre_techniques_ids_and_names | List of MITRE ATT&amp;CK technique IDs and names associated with the case. | Array |
| Core.Case.issue_categories | Categories of issues associated with the case. | Array |
| Core.Case.original_tags | Original tags assigned to the case. | Array |
| Core.Case.tags | Current tags assigned to the case. | Array |
| Core.Case.case_domain | Domain associated with the case. | String |
| Core.Case.custom_fields | Custom fields for the case with standardized lowercase, whitespace-free names. | Unknown |
