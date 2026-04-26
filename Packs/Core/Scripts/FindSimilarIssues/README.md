Searches for issues similar to a given issue based on fields' similarity.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| issue_id | The issue ID to use as reference for similarity matching. |
| text_similarity_fields | A comma-separated list of free-text fields compared using semantic similarity \(NLP\). Suitable for longer descriptive fields where partial matches are meaningful. For example: name, description, remediation. |
| discrete_match_fields | A comma-separated list of fields representing discrete identifiers. Each field contributes 1 if values are equal, or 0 if not. The average of all selected fields affects the overall similarity score. For example: status, type, assignee, severity, starred, category, domain, source. |
| json_similarity_fields | A comma-separated list of fields containing structured data. Each is compared by flattening nested structures and calculating the overlap of key-value pairs. |
| fields_to_display | A comma-separated list of additional issue fields to display that will not be taken into account when computing similarity. |
| filter_equal_fields | A comma-separated list of issue fields that must exactly match the current issue's field values before proceeding to the similarity scoring phase. Acts as a strict pre-filter. |
| from_date | The start date by which to filter issues. Date format is the same as in the issues query page, for example, "3 days ago", "2019-01-01T00:00:00 \+0200". |
| to_date | The end date by which to filter issues. Date format is the same as in the issues query page, for example, "3 days ago", "2019-01-01T00:00:00 \+0200". |
| limit | The maximum number of issues to query. |
| aggregate_issues_different_date | Whether to aggregate duplicate issues within different dates. |
| min_similarity | Minimum overall similarity score \(0-1\) required for an issue to be considered similar. Higher thresholds return fewer, more precise matches. |
| max_issues_to_display | The maximum number of issues to display. |
| show_current_issue | Whether to display the current issue. |
| custom_filter | A custom filter to retrieve issues for similarity calculation. For example: \`\{"OR":\["SEARCH_FIELD":"actor_process_command_line","SEARCH_TYPE":"EQ","SEARCH_VALUE":"path_to_file"\}\]\}\`. |
| show_issue_fields_similarity | Whether to display the similarity score for each of the issue fields. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SimilarIssues.execution_summary | The summary of the execution. | string |
| SimilarIssues.is_similar_issue_found | Indicates whether similar issues have been found. | boolean |
| SimilarIssues.similar_issue.issue_id | The ID of the similar issue. | string |
| SimilarIssues.similar_issue.issue_description | The description of the similar issue. | string |
| SimilarIssues.similar_issue.issue_name | The name of the similar issue. | string |
| SimilarIssues.similar_issue.similarity_score | The similarity of the similar issue, represented as a number between 0-1. | number |
