Searches for emails and optionally deletes them, using one or more of the supported mail integrations. The results of all vendors are normalized into the unified `EmailData` context path.

This script replaces the *Search And Delete Emails - Generic v2* and *Get Original Email - Generic v2* playbooks.

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

* Gmail: `gmail-search`, `gmail-search-all-mailboxes`, `gmail-get-mail`, `gmail-get-attachments`, `gmail-delete-mail`
* Microsoft Graph Mail: `msgraph-mail-list-emails`, `msgraph-mail-get-email`, `msgraph-mail-get-attachment`, `msgraph-mail-delete-email`
* Microsoft Graph Security: `msg-create-ediscovery-case`, `msg-create-ediscovery-search`, `msg-run-estimate-statistics`, `msg-get-last-estimate-statistics-operation`, `msg-purge-ediscovery-data`, `msg-list-case-operation`, `msg-delete-ediscovery-search`, `msg-delete-ediscovery-case`
* EWS on-prem (EWS v2): `ews-search-mailboxes`, `ews-get-items`, `ews-get-attachment`, `ews-delete-items`

## Vendor Support

---

| **Vendor** | **Specific mailboxes** | **All mailboxes** | **Delete types** | **Retrieve files** |
| --- | --- | --- | --- | --- |
| Gmail | Yes | Yes | Soft, Hard | Yes |
| Microsoft Graph Mail | Yes | No | Soft only (moved to *Deleted Items*) | Yes |
| Microsoft Graph Security | Yes (scoped by the KQL query) | Yes | Soft, Hard | No |
| EWS on-prem | Yes | Yes | Soft, Hard | Yes |

### Vendor notes and limits

* **Time frame**: Gmail and Microsoft Graph Mail honor the exact time. Microsoft Graph Security and EWS honor only the *date* part, so the effective window can be up to 24 hours wider than requested.
* **Microsoft Graph Security**: for every run the script creates a **dedicated eDiscovery case** named `XSOAR Search And Delete Email <UTC timestamp>-<short id>` (the shared *XSOAR Auto Phishing* case of the playbooks is no longer used or touched) with a search in it, and moves through the stages *estimating* (`msg-run-estimate-statistics`, polled until it finishes), *purging* (`msg-purge-ediscovery-data`, polled until it finishes, followed by a new estimate, until nothing matches or 10 rounds were done) and *cleanup*. For *Search Only* the estimate is polled to completion, its count is reported and no purge is done. The **cleanup always runs last**, whatever happened before (success, *Search Only*, an error, a failed purge, a timeout): it deletes the search and then the case. A cleanup that failed is retried on the next polling run up to 3 times. For *Specific* scope, the mailboxes are matched using `recipients:` in the KQL query, so copies of the email in other mailboxes may match too. The API returns only totals, therefore the script returns a single **aggregate record** for this brand (see *Output*); per-email details and attachments are not available.
* **Microsoft Graph Mail** cannot search all mailboxes and cannot hard delete.
* **Message ID is preferred**: when `internet_message_id` is specified, `subject` and `sender_address` are ignored.
* **Large searches**: searching thousands of mailboxes is resource heavy. Long running operations are polled (see *Polling*) until the overall `timeout` budget (default 1800 seconds) is exhausted. Result pages are followed, and when a vendor caps the number of returned emails the search is repeated after the deletion until no emails are left.
* **Safety**: at least one of `internet_message_id`, `object_id`, `subject` or `sender_address` is required, so a delete operation can never match every email in the time frame.

### Polling

The script never sleeps or blocks. It uses the built-in polling of the platform: every run advances the operation by one step and then either returns the final results or schedules the next run **20 seconds** later and releases the worker. The state of the operation is passed between the runs in the hidden `state` argument (a JSON string), together with the original arguments. A short one-line progress message (for example *Microsoft Graph Security: estimate running*) is added to the War Room only when a vendor moves to a new stage, never on idle polls.

Per-email vendors (Gmail, Microsoft Graph Mail, EWS) do the whole search, file retrieval and deletion in the first run. Microsoft Graph Security advances one stage per run (`create`, `estimate_start`, `estimate_wait`, `purge_start`, `purge_wait`, `cleanup`). The final results are returned when every vendor is done.

**State size limit**: the state is kept below roughly 500 KB. When a run handles many emails with big bodies, the largest `HTMLBody` values are truncated to a short prefix in the state, and the final output marks them with `AdditionalFields.HTMLBodyTruncated=true`.

### Timeout

`timeout` is the **overall time budget of the whole run**, in seconds (a positive integer, default `1800`). It is not a per-operation timeout: every vendor command and every polling run draws from the same budget, which is measured across the polling runs with an absolute deadline that is stored in the state when the script starts.

* When the budget is exhausted, no further vendor command is started. A vendor that has not been started yet is reported as a failed row with the reason *Timed out before this vendor was run: the N seconds timeout was reached.*
* Results that were collected before the timeout (for example emails that were already found and deleted in a previous search round) are still reported, together with the error.
* The Microsoft Graph Security cleanup (deleting the search and the case) always runs, even when the budget is exhausted, so nothing is leaked. It may therefore finish after the `timeout`: the scheduled command of the platform gets a timeout of the remaining budget **plus a grace period of 600 seconds**, so that the script's own deadline (which triggers the cleanup) is always reached first.
* **Orphaned case**: if the platform cancels the scheduled task externally (for example an analyst closes the investigation or stops the task) before the cleanup ran, a Microsoft Graph Security eDiscovery case (and search) may be left behind. Look for cases whose name starts with `XSOAR Search And Delete Email` and delete them manually.
* The wait for the deletion verification is limited to 2 minutes and to the overall deadline; a timeout while verifying is reported as *not verified*.
* The script timeout of the platform (3 hours, set in the script YAML) applies to every single run, which is now short.

### Deletion verification

When `verify_deletion` is `true`, the script verifies that the deletion really happened, instead of trusting that the vendor delete command did not return an error. The flag is relevant only when `operation` is *Search & Delete*; it is ignored (no extra calls) for *Search Only*. When it is `false` (default), the behavior is unchanged.

* **Gmail, Microsoft Graph Mail and EWS on-prem**: after the delete, the same search is executed again and none of the deleted emails may be returned (matched by mailbox and email ID; Graph Mail and EWS assign a new ID to an item that was moved to *Deleted Items*, and Gmail's search excludes the trash). Because search indexes can lag, the vendor moves to the `verify` stage: the search is repeated once per polling run (every 20 seconds, without blocking the worker) for up to 2 minutes until the emails are gone. Emails that are still found are reported with `Success=false`, `AdditionalFields.DeletionVerified=false` and counted in `TotalFailed` instead of `TotalDeleted`. Verified emails have `AdditionalFields.DeletionVerified=true`. If the verification search itself fails, the emails stay reported as deleted, `DeletionVerified` is not set and the error is added to the vendor `Reason`.
* **Microsoft Graph Security**: the estimate that is calculated after the last purge is used as the verification (no additional API calls). When no items are left, the aggregate record has `AdditionalFields.DeletionVerified=true`. Otherwise, the remaining items are counted in `TotalFailed` and `AdditionalFields.DeletionVerified=false`.
* When `object_id` is used, the verification re-runs the get-by-ID command, which may fail for an email that no longer exists. In this case the error is reported as described above.

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| internet_message_id | One or more Internet Message IDs of the emails to search for or delete. When specified, it is preferred over subject and sender_address. |
| object_id | The vendor specific ID of the email (for example, the ItemID in EWS). When specified, target_mailbox (a single mailbox) and a single brand must also be specified. |
| operation | The operation to perform. "Search Only" searches for the emails and cleans up any search item that was created. "Search &amp; Delete" also deletes the emails that were found. |
| delete_type | The delete type to use when the operation is "Search &amp; Delete": "soft" (the email is moved to the deleted items / trash and can be recovered) or "hard" (the email is permanently deleted). Microsoft Graph Mail supports soft delete only. Default is soft. |
| time_frame | How far back to search, for example "7 days" or "3 hours". Supported units are minutes, hours, days, weeks and months. Default is 1 hour. |
| subject | One or more email subjects to search for. Ignored when internet_message_id is specified. |
| sender_address | The sender address to search for. Can be used together with subject. |
| retrieve_files | Whether to retrieve the attachments of the emails before they are deleted. Default is false. |
| target_mailbox | The mailbox(es) to search in. Required when mailbox_scope is "Specific". |
| mailbox_scope | Whether to search specific mailboxes or all mailboxes. Default is Specific. |
| brands | The brands to run the operation on. If empty, all enabled instances of the supported brands are used. |
| verify_deletion | Whether to verify the deletion by searching again after the emails were deleted and checking that they no longer exist. Relevant only when the operation is "Search &amp; Delete". Emails whose deletion cannot be verified are reported as failed. Default is false. |
| verbose | Whether to include the list of executed commands in the human readable output. Default is false. |
| timeout | The overall time budget of the whole run (all polling runs together), in seconds (a positive integer). It is not a per-operation timeout. When it is exhausted, vendors that were not started yet are reported as failed and the results collected so far are returned (the Microsoft Graph Security search and case are always cleaned up, which may take up to an additional 600 seconds grace period). Default is 1800. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | The unified results of the search and delete operation. | Unknown |
| EmailData.ID | The vendor specific ID of the email (for example the message ID in Microsoft Graph Mail or the item ID in EWS). | String |
| EmailData.Mailbox | The mailbox addresses in which the email was found. | Unknown |
| EmailData.Subject | The email subject. | String |
| EmailData.From | The email sender. | String |
| EmailData.To | The email recipients. | Unknown |
| EmailData.CC | The email CC recipients. | Unknown |
| EmailData.BCC | The email BCC recipients. | Unknown |
| EmailData.HTMLBody | The HTML body of the email. | String |
| EmailData.Timestamp | The timestamp of the email. | String |
| EmailData.Attachments | A dictionary of the attachment names and their hashes. | Unknown |
| EmailData.Success | Whether the operation succeeded for this email (or for this vendor, when no email was found). | Boolean |
| EmailData.Reason | The reason for the failure, if any. | String |
| EmailData.Operation | The operation that was performed. | String |
| EmailData.Brand | The brand that was used. | String |
| EmailData.AdditionalFields | Additional vendor specific fields, such as the Internet Message ID and the instance name. | Unknown |
| EmailData.AdditionalFields.DeletionVerified | Whether the deletion was verified. Returned only when verify_deletion is true and the verification could be determined. | Boolean |
| EmailData.AdditionalFields.Aggregate | True for the single aggregate record of a brand that returns counts only (Microsoft Graph Security), which has no per-email details. | Boolean |
| EmailData.AdditionalFields.HTMLBodyTruncated | True when the HTML body of the email was truncated to keep the polling state small. | Boolean |
| EmailData.TotalFound | The total number of emails that were found by the brand. | Number |
| EmailData.TotalDeleted | The total number of emails that were deleted by the brand. | Number |
| EmailData.TotalFailed | The total number of emails that failed to be deleted by the brand. | Number |
| File.Name | The name of the retrieved attachment. Returned only when retrieve_files is true. | String |
| File.SHA256 | The SHA256 of the retrieved attachment. Returned only when retrieve_files is true. | String |

## Output

---

The script returns two War Room entries (after the file entries, when `retrieve_files` is true):

1. **`Search & Delete Email results`** - holds the `EmailData` context and a single table with one row per email, plus one row per vendor instance that found no email or had errors. The columns are always `Brand`, `Mailbox`, `ID`, `Subject`, `From`, `Timestamp`, `Operation`, `Success`. The column `Total Found` is added right after them only when at least one aggregate row exists (see below). The columns `Reason`, `Deletion Verified` (only when `verify_deletion` was requested) and `Note` are appended, in this order, only when at least one row has a value. The first 50 rows are displayed unless `verbose` is true, in which case all rows and the list of executed commands are displayed.

   **Microsoft Graph Security returns only a count**, so it is reported as one *aggregate* record per instance (always, also when nothing was found): in the context an `EmailData` entry with `Brand`, `Operation`, `Mailbox` (the target mailboxes, or `["All"]`), `Success`, `Reason`, `TotalFound`, `TotalDeleted`, `TotalFailed` and `AdditionalFields` (`Aggregate=true`, `Instance`, and `DeletionVerified` / `Note` when applicable), with empty `ID`, `Subject`, `From`, `To`, `CC`, `BCC`, `HTMLBody`, `Timestamp` and `Attachments`; in the table one row with `Brand`, `Mailbox`, `Operation`, `Success` and `Total Found` filled (a successful search without hits shows `Total Found = 0`) and the note *Microsoft Graph Security returns aggregate counts only (no per-email details).*
2. **`Summary`** - a table (no context) with the columns `TotalDeleted`, `TotalFailed` and `TotalFound`, which are the sums over all vendors.

Example (*Search Only*, one Microsoft Graph Mail email):

```text
### Search & Delete Email results
|Brand|Mailbox|ID|Subject|From|Timestamp|Operation|Success|
|---|---|---|---|---|---|---|---|
| MicrosoftGraphMail | avishai@demistodev.onmicrosoft.com | AAMkAGY3...AAl1lYHQAAA= | Undeliverable: Message from Cortex XSOAR Security Operations Server | MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@demistodev.onmicrosoft.com | 2026-10-21T11:58:19Z | Search Only | true |

### Summary
|TotalDeleted|TotalFailed|TotalFound|
|---|---|---|
| 0 | 0 | 1 |
```

Example (*Search Only*, Microsoft Graph Security, 3 matching emails):

```text
### Search & Delete Email results
|Brand|Mailbox|ID|Subject|From|Timestamp|Operation|Success|Total Found|Note|
|---|---|---|---|---|---|---|---|---|---|
| Microsoft Graph | user1@example.com | | | | | Search Only | true | 3 | Microsoft Graph Security returns aggregate counts only (no per-email details). |

### Summary
|TotalDeleted|TotalFailed|TotalFound|
|---|---|---|
| 0 | 0 | 3 |
```

## Error handling

---
Every vendor instance is executed independently. A failure of one vendor does not stop the others, and the errors are aggregated into the results table (`Success=false` and `Reason`) and into `EmailData.Reason`. When all vendors fail, the script does not fail: it returns the results table with a failed row for each vendor, the `Summary` and one `EmailData` entry per vendor with `Success=false`.

## Examples

---

Search and soft delete an email by its Internet Message ID in specific mailboxes, verify the deletion and limit the run to 30 minutes:

```text
!SearchAndDeleteEmail operation="Search & Delete" delete_type=soft verify_deletion=true timeout=1800 internet_message_id="<abc@example.com>" target_mailbox="user1@example.com,user2@example.com" time_frame="7 days"
```

Only search all mailboxes for a sender and subject, and retrieve the attachments:

```text
!SearchAndDeleteEmail operation="Search Only" sender_address="bad@evil.com" subject="Invoice" mailbox_scope=All retrieve_files=true brands="Gmail,EWS v2"
```
