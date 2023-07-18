A script for deleting reported phishing emails from the mailbox in which they were reported.

## Note
The script was specifically developed for use by the `Delete Reported Email` layout on the `Phishing - Generic v3` playbook, and should not be used elsewhere.

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
| delete_type | The type of deletion - soft allows restoring, hard doesn't. Not relevant for O365 and Search &amp;amp; Compliance. |
| delete_from_brand | The brand for which to delete this email from. The default value is the incident using the brand. |
| search_name | Argument used for the generic polling flow within the security and compliance search. |
| polling | Use the Cortex XSOAR built-in polling to retrieve the result when it's ready. |
| interval_in_seconds | Interval in seconds between each poll. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DeleteReportedEmail.result | Whether the deletion operation was successful, skipped, or failed | String |
| DeleteReportedEmail.deletion_failure_reason | The reason of failure if the deletion operation failed or skipped | String |
| DeleteReportedEmail.delete_type | Whether the deletion operation was hard or soft. | String |
| DeleteReportedEmail.using_brand | The email service that was used to delete the email. | String |
| DeleteReportedEmail.email_subject | The subject of the deleted email. | String |
| DeleteReportedEmail.message_id | The message ID of the deleted email. | String |

## Troubleshooting
---
* If the `Reported Email Origin` field is missing or has a value of `None`, the script will not be able to locate the email and fail.  
  This can happen if the email forwarded to the listener mailbox was not forwarded as an attachment (with an `EML` file) as it should.
* If either the `Reported Email Message ID` or `Reported Email To` fields are missing, the cause is likely to be one of the following:
  * An `EML` file was not attached to the email.
  * The playbook is being used as a sub-playbook, causing the `EML` file to exist only in the parent playbook.
  * The `Process Email - Generic v2` sub-playbook failed, or the `ParseEmailFilesV2` step within it specifically failed.