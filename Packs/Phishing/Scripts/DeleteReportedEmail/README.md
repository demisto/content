Use this script to delete a reported phishing email from the mailbox it was reported to

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.1.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| delete_type | The type of deletion - soft allows restoring, hard doesnt. Not relevant for O365 and Search &amp;amp; Compliance. |
| delete_from_brand | The brand of which you wish to delete this email from. the default value is the incident using brand. |
| search_name | argument used for the generic polling flow within the security and compliance search. |
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. |
| interval_in_seconds | Interval in seconds between each poll. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DeleteReportedEmail.result | Whether the deletion operation was successful, skipped, or failed | String |
| DeleteReportedEmail.deletion_failure_reason | The reason of failure if the deletion operation failed or skipped | String |
| DeleteReportedEmail.delete_type | Whether the deletion operation was hard or soft | String |
| DeleteReportedEmail.using_brand | The email service that was used to delete the email | String |
| DeleteReportedEmail.email_subject | The subject of the deleted email | String |
| DeleteReportedEmail.message_id | The message id of the deleted email | String |
