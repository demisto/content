Searches for emails and optionally deletes them, using one or more of the supported mail integrations: Gmail, Microsoft Graph Mail, Microsoft Graph Security and EWS on-prem (EWS v2). The results of all vendors are normalized into the unified EmailData context path.

Supported scopes: Gmail, Microsoft Graph Security and EWS v2 support searching all mailboxes. Microsoft Graph Mail supports only specific mailboxes.
Delete types: Gmail, Microsoft Graph Security and EWS v2 support both soft and hard delete. Microsoft Graph Mail supports soft delete only (the emails are moved to Deleted Items).
Microsoft Graph Security and EWS v2 honor only the date part of the time frame, so the effective search window can be up to 24 hours wider than requested.
The command may take a long time when searching thousands of mailboxes. It uses the built-in polling: every run advances the operation by one step and releases the worker until the next run, so it never blocks. The timeout argument is the overall time budget (in seconds) of the whole run.
When verify_deletion is true (relevant only for "Search & Delete"), the script verifies that the emails were really deleted instead of trusting that the delete command did not fail (the verification is polled for up to 120 seconds). Verification is not supported for Microsoft Graph Security.
Microsoft Graph Security runs in a dedicated eDiscovery case that is created for the run and is always deleted at the end, together with its search, and returns a single aggregate record (counts only) instead of per-email details.

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
* msg-list-case-operation
* msg-delete-ediscovery-search
* msg-delete-ediscovery-case
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
| EmailData.AdditionalFields.Verified | Whether the deletion of the email was verified. Returned only when verify_deletion is true and the verification could be determined. | Boolean |
| EmailData.AdditionalFields.Instance | The name of the integration instance. Returned for records without an email and for every email when verbose is true. | String |
| EmailData.AdditionalFields.HTMLBodyTruncated | True when the HTML body of the email was truncated to keep the polling state small. Returned only when verbose is true. | Boolean |
| EmailData.AdditionalFields.Aggregate | True for the single aggregate record of a brand that returns counts only \(Microsoft Graph Security\), which has no per-email details. | Boolean |
| EmailData.AdditionalFields.DeletionVerified | Whether the deletion was verified. Returned only in the aggregate record of Microsoft Graph Security. | Boolean |
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
| Microsoft Graph Security | Yes (scoped by the KQL query) | Yes | Soft, Hard | No |
| EWS v2 | Yes | Yes | Soft, Hard | Yes |

### Notes and limits

* **Safety**: at least one of `internet_message_id`, `object_id`, `subject` or `sender_address` is required, so a delete operation can never match every email in the time frame.
* **Message ID is preferred**: when `internet_message_id` is specified, `subject` and `sender_address` are ignored.
* **object_id**: requires exactly one `target_mailbox` and one brand, with `mailbox_scope` set to *Specific*. It is not supported for Microsoft Graph Security.
* **Microsoft Graph Security**: for every run the script creates a dedicated eDiscovery case named `XSOAR Search And Delete Email <UTC timestamp>-<short id>` with a search in it, estimates the number of matching emails and, for *Search & Delete*, purges them (and re-estimates until nothing matches or 10 rounds were done). The search and the case are always deleted at the end of the run, also for *Search Only* and also on failure or timeout. For the *Specific* scope the mailboxes are matched using `recipients:` in the KQL query, so copies of the email in other mailboxes may match too. The API returns only totals, so a single aggregate record (`AdditionalFields.Aggregate=true`) is returned for the brand, and attachments cannot be retrieved.
* **Microsoft Graph Mail** cannot search all mailboxes and cannot hard delete.
* **Pagination**: result pages are followed, and when a vendor caps the number of returned emails the search is repeated after the deletion until no emails are left (up to 10 rounds).
* **State size**: the polling state is kept below roughly 500 KB. When it grows beyond it, the largest HTML bodies are truncated and marked with `AdditionalFields.HTMLBodyTruncated=true`.

### Polling and timeout

The script never sleeps or blocks. Every run advances the operation by one step and then either returns the final results or schedules the next run 20 seconds later. The state is passed between the runs in the hidden `state` argument. A short progress message is added to the War Room only when a vendor moves to a new stage.

`timeout` is the overall time budget of the whole run, in seconds (default 1800), measured across all the polling runs. When it is exhausted, vendors that were not started yet are reported as failed, the results collected so far are returned, and the Microsoft Graph Security cleanup still runs (the scheduled command gets the remaining budget plus a 600 seconds grace period).

If the platform cancels the scheduled task before the cleanup ran, an eDiscovery case whose name starts with `XSOAR Search And Delete Email` may be left in Microsoft Graph Security and should be deleted manually.

### Deletion verification

When `verify_deletion` is `true` and the operation is *Search & Delete*:

* **Gmail, Microsoft Graph Mail and EWS v2**: the same search is repeated after the deletion (once per polling run, for up to 120 seconds) and none of the deleted emails may be returned. Emails that are still found are reported with `Success=false` and `AdditionalFields.Verified=false` and are counted in `TotalFailed` instead of `TotalDeleted`. Verified emails have `AdditionalFields.Verified=true`.
* **Microsoft Graph Security**: verification is not supported. A warning entry is returned and the deletion is performed without verification, except that the estimate that is calculated after the last purge is used to report remaining items as failed (`AdditionalFields.DeletionVerified`).

### Output

The script returns a single War Room entry with the `EmailData` context, `TotalFound`, `TotalDeleted` and `TotalFailed`. The human readable output is a table titled `Search & Delete Email - <operation>` with the columns `Brand`, `Mailbox`, `ID`, `Subject`, `From`, `To`, `Timestamp`, `Operation`, `Success` and `Reason`, followed by a summary line (`Total found | Total deleted | Total failed`). When `verbose` is true, the list of executed commands is appended. When the operation failed for all the integrations, the entry is returned as an error entry with the reasons.

### Examples

Search and soft delete an email by its Internet Message ID in specific mailboxes, verify the deletion and limit the run to 30 minutes:

```text
!SearchAndDeleteEmail operation="Search & Delete" delete_type=soft verify_deletion=true timeout=1800 internet_message_id="<abc@example.com>" target_mailbox="user1@example.com,user2@example.com" time_frame="7 days"
```

Only search all mailboxes for a sender and subject, and retrieve the attachments:

```text
!SearchAndDeleteEmail operation="Search Only" sender_address="bad@evil.com" subject="Invoice" mailbox_scope=All retrieve_files=true brands="Gmail,EWS v2"
```
