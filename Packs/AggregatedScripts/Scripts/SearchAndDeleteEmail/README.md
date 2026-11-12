Searches for emails and optionally deletes them, using one or more of the supported mail integrations: Gmail, Microsoft Graph Mail, Microsoft Graph Security and EWS on-prem (EWS v2). The results of all vendors are normalized into the unified EmailData context path.

Supported scopes: Gmail, Microsoft Graph Security and EWS v2 support searching all mailboxes. Microsoft Graph Mail supports only specific mailboxes.
Delete types: Gmail, Microsoft Graph Security and EWS v2 support both soft and hard delete. Microsoft Graph Mail supports soft delete only (the emails are moved to Deleted Items).
Microsoft Graph Security and EWS v2 honor only the date part of the time frame, so the effective search window can be up to 24 hours wider than requested.
The command may take a long time when searching thousands of mailboxes. It uses the built-in polling: long waits (the Microsoft Graph Security eDiscovery operations and the deletion verification) are polled, while the search and delete commands of each run are executed synchronously within that run. The timeout argument is the overall time budget (in seconds) of the whole run.
When verify_deletion is true (relevant only for "Search & Delete"), the script verifies that the emails were really deleted instead of trusting that the delete command did not fail (the verification is polled for up to 120 seconds). Verification is not supported for Microsoft Graph Security.
Microsoft Graph Security runs in a dedicated eDiscovery case that is created for the run, and returns a single aggregate record (counts only) instead of per-email details. "Search & Delete" estimates the matching emails, starts the purge in the background (fire and forget) and deletes the search and the case. "Search Only" creates the case and the search and returns a warning with the ediscovery_case_id and ediscovery_search_id to re-run the command with; that second run reads the results and deletes the search and the case. "Search & Delete" with mailbox_scope "Specific" is refused for Microsoft Graph Security, because its search would also match the copies of the email in other mailboxes.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | email, Utility |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* gmail-search
* gmail-search-all-mailboxes
* gmail-get-mail
* gmail-get-attachments
* gmail-delete-mail
* msgraph-mail-list-emails
* msgraph-mail-get-email
* msgraph-mail-get-attachment
* msgraph-mail-delete-email
* msg-create-ediscovery-case
* msg-create-ediscovery-search
* msg-run-estimate-statistics
* msg-get-last-estimate-statistics-operation
* msg-purge-ediscovery-data
* msg-delete-ediscovery-search
* msg-delete-ediscovery-case
* msg-list-ediscovery-cases
* ews-search-mailboxes
* ews-get-items
* ews-get-attachment
* ews-delete-items

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| internet_message_id | One or more Internet Message IDs of the emails to search for or delete. When specified, it is preferred over subject and sender_address. |
| object_id | The vendor specific ID of the email (for example, the ItemID in EWS). When specified, a single target_mailbox and a single brand must also be specified, and mailbox_scope must be "Specific". Not supported for Microsoft Graph Security. |
| operation | The operation to perform. "Search Only" searches for the emails without deleting them. "Search &amp; Delete" also deletes the emails that were found. |
| delete_type | The delete type to use when the operation is "Search &amp; Delete": "soft" (the email is moved to the deleted items / trash and can be recovered) or "hard" (the email is permanently deleted). Microsoft Graph Mail supports soft delete only. Default is soft. |
| time_frame | How far back to search, for example "7 days" or "3 hours". Supported units: minutes, hours, days, weeks and months. Microsoft Graph Security and EWS v2 honor only the date part. Default is 1 hour. |
| subject | One or more email subjects to search for. Ignored when internet_message_id is specified. |
| sender_address | The sender address to search for. Can be used together with subject. Ignored when internet_message_id is specified. |
| retrieve_files | Whether to retrieve the attachments of the emails before they are deleted. The files are added to the Attachments key of EmailData and returned as file entries. Not supported by Microsoft Graph Security. Default is false. |
| target_mailbox | The mailbox(es) to search in. Required when mailbox_scope is "Specific". Ignored when mailbox_scope is "All". |
| mailbox_scope | Whether to search specific mailboxes or all mailboxes. Microsoft Graph Mail does not support "All". Default is Specific. |
| brands | The brands to run the operation on. If empty, all enabled instances of the supported brands are used. |
| verify_deletion | Whether to verify the deletion by searching again after the emails were deleted and checking that they no longer exist. Relevant only when the operation is "Search &amp; Delete". Emails whose deletion cannot be verified are reported as failed. Not supported for Microsoft Graph Security, for which a warning is returned. Default is false. |
| verbose | Whether to include the list of executed commands in the human readable output and the instance name in the AdditionalFields of every email. Default is false. |
| ediscovery_case_id | The ID of a Microsoft Graph Security eDiscovery case that was created by a previous *Search Only* run of this script (returned in its warning and in `AdditionalFields.EDiscoveryCaseID`). Must be specified together with ediscovery_search_id, only with the "Search Only" operation and only with the Microsoft Graph Security brand. When specified, the script reads the results of the existing search and then deletes the search and the case. |
| ediscovery_search_id | The ID of the Microsoft Graph Security eDiscovery search that was created by a previous *Search Only* run of this script (returned in its warning and in `AdditionalFields.EDiscoverySearchID`). Must be specified together with ediscovery_case_id. |
| timeout | The overall time budget of the whole run (all polling runs together), in seconds (a positive integer). It is not a per-operation timeout. When it is exhausted, vendors that were not started yet are reported as failed and the results collected so far are returned (the Microsoft Graph Security search and case are always cleaned up, which may take up to an additional 600 seconds grace period). Default is 1800. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | The unified results of the search and delete operation. Contains one record per email found, or one record per brand instance that found no emails, failed, or returns aggregate counts only \(Microsoft Graph Security\). | Unknown |
| EmailData.Brand | The brand that was used. | String |
| EmailData.Mailbox | The mailbox addresses in which the email was found. For records without an email, the target mailboxes or "All". | Unknown |
| EmailData.Subject | The email subject. | String |
| EmailData.From | The email sender. | String |
| EmailData.To | The email recipients. | Unknown |
| EmailData.CC | The email CC recipients. | Unknown |
| EmailData.BCC | The email BCC recipients. | Unknown |
| EmailData.HTML | The HTML body of the email. | String |
| EmailData.Timestamp | The timestamp of the email. | String |
| EmailData.Attachments | A dictionary of the attachment names and their SHA256 hashes. The hashes are populated only when retrieve_files is true. | Unknown |
| EmailData.Success | Whether the operation succeeded for this email \(or for this brand instance, when the record has no email\). | Boolean |
| EmailData.Reason | The reason for the failure, if any. | String |
| EmailData.Operation | The operation that was performed \("Search Only" or "Search &amp; Delete"\). | String |
| EmailData.AdditionalFields | Additional vendor specific fields. | Unknown |
| EmailData.AdditionalFields.ObjectID | The vendor specific ID of the email \(for example, the message ID in Microsoft Graph Mail or the item ID in EWS\). | String |
| EmailData.AdditionalFields.InternetMessageID | The Internet Message ID of the email, when the vendor returns it. | String |
| EmailData.AdditionalFields.Verified | Whether the deletion of the email was verified. Returned only when verify_deletion is true and the verification could be determined. Never returned for Microsoft Graph Security \(its purge is fire and forget\). | Boolean |
| EmailData.AdditionalFields.Instance | The name of the integration instance. Returned for records without an email and for every email when verbose is true. | String |
| EmailData.AdditionalFields.HTMLBodyTruncated | True when the HTML body of the email was truncated to keep the polling state small. | Boolean |
| EmailData.AdditionalFields.Aggregate | True for the single aggregate record of a brand that returns counts only \(Microsoft Graph Security\), which has no per-email details. | Boolean |
| EmailData.AdditionalFields.SearchPending | True when a Microsoft Graph Security *Search Only* search was initiated and its results are not available yet. Re-run the script with ediscovery_case_id and ediscovery_search_id to get them. | Boolean |
| EmailData.AdditionalFields.EDiscoveryCaseID | The ID of the Microsoft Graph Security eDiscovery case that was kept for a later run. Returned only when SearchPending is true. | String |
| EmailData.AdditionalFields.EDiscoverySearchID | The ID of the Microsoft Graph Security eDiscovery search that was kept for a later run. Returned only when SearchPending is true. | String |
| EmailData.AdditionalFields.Note | A note about the run of the brand instance, for example when the vendor capped the number of returned emails. Returned only in records without an email and in aggregate records. | String |
| TotalFound | The total number of emails that were found across all brands. | Number |
| TotalDeleted | The total number of emails that were deleted across all brands. | Number |
| TotalFailed | The total number of emails that failed to be deleted across all brands. | Number |
| File.Name | The name of the retrieved attachment. Returned only when retrieve_files is true. | String |
| File.SHA256 | The SHA256 of the retrieved attachment. Returned only when retrieve_files is true. | String |

## Additional Information

---

### Vendor support

| **Vendor** | **Specific mailboxes** | **All mailboxes** | **Delete types** | **Retrieve files** |
| --- | --- | --- | --- | --- |
| Gmail | Yes | Yes | Soft, Hard | Yes |
| Microsoft Graph Mail | Yes | No | Soft only (moved to *Deleted Items*) | Yes |
| Microsoft Graph Security | Search only (scoped by the KQL query) | Yes | Soft, Hard (*All* scope only) | No |
| EWS v2 | Yes | Yes | Soft, Hard | Yes |

### Notes and limits

* **Safety**: at least one of `internet_message_id`, `object_id`, `subject` or `sender_address` is required, so a delete operation can never match every email in the time frame.
* **Message ID is preferred**: when `internet_message_id` is specified, `subject` and `sender_address` are ignored.
* **object_id**: requires exactly one `target_mailbox` and one brand, with `mailbox_scope` set to *Specific*. It is not supported for Microsoft Graph Security.
* **Microsoft Graph Security**: the script creates a dedicated eDiscovery case named `XSOAR Search And Delete Email <UTC timestamp>-<short id>` with a search in it. For *Search & Delete* it estimates the number of matching emails, starts the purge in the background (fire and forget: the purge is not polled, the deleted count is the estimate count and the deletion is not verified) and deletes the search and the case. *Search Only* runs in two steps, because the estimate may take a long time: the first run only creates the case and the search, keeps them and returns a warning with their IDs; re-running the script with `ediscovery_case_id` and `ediscovery_search_id` polls the estimate, reports the count and deletes the search and the case. On failure or timeout the search and the case are always deleted (except after the first step of *Search Only*). For the *Specific* scope the mailboxes are matched using `recipients:` in the KQL query over all tenant mailboxes, so every copy of the email (for example the sender's *Sent Items*) matches too. Therefore *Search & Delete* with the *Specific* scope is refused for Microsoft Graph Security (an error is reported for the brand and nothing is purged), while *Search Only* is allowed. To delete from specific mailboxes, use another brand. The API returns only totals, so a single aggregate record (`AdditionalFields.Aggregate=true`) is returned for the brand, and attachments cannot be retrieved.
* **Microsoft Graph Mail** cannot search all mailboxes and cannot hard delete.
* **Gmail all mailboxes**: in a domain with more than 500 accounts, Gmail splits the all-mailboxes search into background sub-searches whose results are not available to this script. This is reported as an error for the brand. Use specific mailboxes or another brand.
* **Pagination**: result pages are followed, and when a vendor caps the number of returned emails the search is repeated after the deletion until no emails are left (up to 10 rounds). A soft deleted Microsoft Graph Mail / EWS email is moved to *Deleted Items* under a new ID, so emails whose mailbox and Internet Message ID were already processed in an earlier round are skipped (they are not counted or deleted again).
* **EWS email details**: only the first 50 emails that EWS returns are fetched in full (HTML body and attachments). The other emails are reported with the fields returned by the search.
* **State size**: the polling state is kept below roughly 500 KB. When it grows beyond it, the largest HTML bodies are truncated and marked with `AdditionalFields.HTMLBodyTruncated=true`.

### Polling and timeout

The script never sleeps. Long waits (the Microsoft Graph Security eDiscovery operations and the deletion verification) are polled: every run advances the operation by one step and then either returns the final results or schedules the next run 20 seconds later. The search and delete commands of a run are executed synchronously within that run. The state is passed between the runs in the hidden `state` argument. A short progress message is added to the War Room only when a vendor moves to a new stage.

`timeout` is the overall time budget of the whole run, in seconds (default 1800), measured across all the polling runs. When it is exhausted, vendors that were not started yet are reported as failed, the results collected so far are returned, and the Microsoft Graph Security cleanup still runs (the scheduled command gets the remaining budget plus a 600 seconds grace period).

If the platform cancels the scheduled task before the cleanup ran, an eDiscovery case whose name starts with `XSOAR Search And Delete Email` may be left in Microsoft Graph Security and should be deleted manually.

### Deletion verification

When `verify_deletion` is `true` and the operation is *Search & Delete*:

* **Gmail, Microsoft Graph Mail and EWS v2**: the same search is repeated after the deletion (once per polling run, for up to 120 seconds) and none of the deleted emails may be returned. Emails that are still found are reported with `Success=false` and `AdditionalFields.Verified=false` and are counted in `TotalFailed` instead of `TotalDeleted`. Verified emails have `AdditionalFields.Verified=true`. When searching by `object_id`, a Gmail email with the `TRASH` label counts as deleted, and a "not found" response of Microsoft Graph Mail or EWS v2 counts as verified.
* **Microsoft Graph Security**: verification is not supported. A warning entry is returned and the purge is started without verification (fire and forget).

### Output

The script returns a single War Room entry with the `EmailData` context, `TotalFound`, `TotalDeleted` and `TotalFailed`. The human readable output is a table titled `Search & Delete Email - <operation>` with the columns `Brand`, `Mailbox`, `ID`, `Subject`, `From`, `To`, `Timestamp`, `Operation`, `Success` and `Reason`, a line with the totals of every Microsoft Graph Security instance (which has no per-email rows), and a summary line (`Total found | Total deleted | Total failed`). When nothing was found, the table is replaced with "No emails were found.". When `verbose` is true, the list of executed commands is appended. When the operation failed for all the integrations, the entry is returned as an error entry with the reasons.

### Examples

Search and soft delete an email by its Internet Message ID in specific mailboxes, verify the deletion and limit the run to 30 minutes:

```text
!SearchAndDeleteEmail operation="Search & Delete" delete_type=soft verify_deletion=true timeout=1800 internet_message_id="<abc@example.com>" target_mailbox="user1@example.com,user2@example.com" time_frame="7 days"
```

Only search all mailboxes for a sender and subject, and retrieve the attachments:

```text
!SearchAndDeleteEmail operation="Search Only" sender_address="bad@evil.com" subject="Invoice" mailbox_scope=All retrieve_files=true brands="Gmail,EWS v2"
```

Search all mailboxes with Microsoft Graph Security, then read the results with the IDs that the warning of the first run returned:

```text
!SearchAndDeleteEmail operation="Search Only" subject="Invoice" mailbox_scope=All brands="Microsoft Graph Security"
!SearchAndDeleteEmail operation="Search Only" brands="Microsoft Graph Security" ediscovery_case_id=<case_id> ediscovery_search_id=<search_id>
```
