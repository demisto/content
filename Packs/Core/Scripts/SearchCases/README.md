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
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only cases that were created on or before the specified date/time will be retrieved. |
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only cases that were created on or after the specified date/time will be retrieved. |
| lte_modification_time | Filters returned cases that were created on or before the specified date/time, in the format 2019-12-31T23:59:00. |
| gte_modification_time | Filters returned cases that were modified on or after the specified date/time, in the format 2019-12-31T23:59:00. |
| case_id_list | An array or CSV string of case IDs. |
| since_creation_time | Filters returned cases that were created on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. |
| since_modification_time | Filters returned cases that were modified on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. |
| sort_by_modification_time | Sorts returned cases by the date/time that the case was last modified \("asc" - ascending, "desc" - descending\). |
| sort_by_creation_time | Sorts returned cases by the date/time that the case was created \("asc" - ascending, "desc" - descending\). |
| page | Page number \(for pagination\). The default is 0 \(the first page\). |
| limit | Maximum number of cases to return per page. The default and maximum is 100. |
| status | Filters only cases in the specified status. The options are: new, under_investigation, resolved_known_issue, resolved_false_positive, resolved_true_positive resolved_security_testing, resolved_other, resolved_auto. |
| starred | Whether the case is starred \(Boolean value: true or false\). |
| issues_limit | Maximum number of issues to return per case. The default and maximum is 1000. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.Case.case_id | Unique ID assigned to each returned case. | String |
| Core.Case.manual_severity | Case severity assigned by the user. This does not affect the calculated severity. Can be "low", "medium", "high". | String |
| Core.Case.manual_description | Case description provided by the user. | String |
| Core.Case.assigned_user_mail | Email address of the assigned user. | String |
| Core.Case.high_severity_issue_count | Number of issues with the severity HIGH. | String |
| Core.Case.host_count | Number of hosts involved in the case. | number |
| Core.Case.xdr_url | A link to the case view on Cortex XDR. | String |
| Core.Case.assigned_user_pretty_name | Full name of the user assigned to the case. | String |
| Core.Case.issue_count | Total number of issues in the case. | number |
| Core.Case.med_severity_issue_count | Number of issues with the severity MEDIUM. | number |
| Core.Case.user_count | Number of users involved in the case. | number |
| Core.Case.severity | Calculated severity of the case. Valid values are:<br/>"low","medium","high". | String |
| Core.Case.low_severity_issue_count | Number of issues with the severity LOW. | String |
| Core.Case.status | Current status of the case. Valid values are: "new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing" or "resolved_other".<br/> | String |
| Core.Case.description | Dynamic calculated description of the case. | String |
| Core.Case.resolve_comment | Comments entered by the user when the case was resolved. | String |
| Core.Case.notes | Comments entered by the user regarding the case. | String |
| Core.Case.creation_time | Date and time the case was created on Cortex XDR. | date |
| Core.Case.detection_time | Date and time that the first issue occurred in the case. | date |
| Core.Case.modification_time | Date and time that the case was last modified. | date |
| Core.Case.issue_ids | List of unique issue identifiers associated with the case. | date |
| Core.Case.network_artifacts | Network-related artifacts associated with the case. | date |
| Core.Case.file_artifacts | File-related artifacts associated with the case. | date |
