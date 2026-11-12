Searches for emails and optionally deletes them, using one or more of the supported mail integrations: Gmail, Microsoft Graph Mail and EWS on-prem (EWS v2). The results of all vendors are normalized into the unified EmailData context path.

Supported scopes: Gmail and EWS v2 support searching all mailboxes. Microsoft Graph Mail supports only specific mailboxes.
Delete types: Gmail and EWS v2 support both soft and hard delete. Microsoft Graph Mail supports soft delete only (the emails are moved to Deleted Items).
EWS v2 honors only the date part of the time frame, so the effective search window can be up to 24 hours wider than requested.
The search, the retrieval of the files and the deletion are executed synchronously in a single run. The timeout argument is the overall time budget (in seconds) of the run, checked before each integration instance is run.
Vendor notes (for example, when the vendor capped the number of returned emails) are shown in a Notes section of the human readable output.

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
* ews-search-mailboxes
* ews-get-items
* ews-get-attachment
* ews-delete-items

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| internet_message_id | One or more Internet Message IDs of the emails to search for or delete. When specified, it is preferred over subject and sender_address. A message ID that contains whitespace, quotes, backslashes, parentheses or inner angle brackets is rejected. |
| object_id | The vendor specific ID of the email (for example, the ItemID in EWS). When specified, a single target_mailbox and a single brand must also be specified, and mailbox_scope must be "Specific". |
| operation | The operation to perform. "Search Only" searches for the emails without deleting them. "Search &amp; Delete" also deletes the emails that were found. |
| delete_type | The delete type to use when the operation is "Search &amp; Delete": "soft" (the email is moved to the deleted items / trash and can be recovered) or "hard" (the email is permanently deleted). Microsoft Graph Mail supports soft delete only. Default is soft. |
| time_frame | How far back to search, for example "7 days" or "3 hours". Supported units: minutes, hours, days, weeks and months. EWS v2 honors only the date part. Default is 1 hour. |
| subject | One or more email subjects to search for. Ignored when internet_message_id is specified. |
| sender_address | The sender address to search for. Can be used together with subject. Ignored when internet_message_id is specified. An address that contains whitespace, quotes, backslashes or parentheses is rejected. |
| retrieve_files | Whether to retrieve the attachments of the emails before they are deleted. The files are added to the Attachments key of EmailData and returned as file entries. Default is false. |
| target_mailbox | The mailbox(es) to search in. Required when mailbox_scope is "Specific". Ignored when mailbox_scope is "All". |
| mailbox_scope | Whether to search specific mailboxes or all mailboxes. Microsoft Graph Mail does not support "All" (an error is returned for it, use Gmail or EWS on-prem instead). Default is Specific. |
| brands | The brands to run the operation on. If empty, all enabled instances of the supported brands are used. The run fails if no enabled instance of the requested brands is found. |
| verbose | Whether to include the list of executed commands in the human readable output and the instance name in the AdditionalFields of every email. Default is false. |
| timeout | The overall time budget of the run, in seconds (a positive integer, at most 1800, since the whole search and delete runs synchronously within the script timeout). It is not a per-operation timeout. It is checked before each integration instance is run and before each email is processed. When it is exhausted, the integration instances that were not run yet are reported as failed, the remaining emails are not processed (a note is added) and the results collected so far are returned. Default is 1800. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | The unified results of the search and delete operation. Contains one record per email found, and one record per brand instance that found no emails or had errors. | Unknown |
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
| EmailData.AdditionalFields.Instance | The name of the integration instance. Returned for records without an email and for every email when verbose is true. | String |
| EmailData.AdditionalFields.NotFound | True when the email requested by object_id was not found \(the vendor returned a "not found" error for the lookup\). Returned only in the record of the brand instance \(a record without an email\). The vendor error is reported in Reason, but the brand instance is not counted as a hard failure, so the entry is not returned as an error entry. | Boolean |
| EmailData.AdditionalFields.Note | Notes about the run of the brand instance, for example when the vendor capped the number of returned emails or when Microsoft Graph Mail could not hard delete. Multiple notes are appended to each other. Returned only in the record of the brand instance \(a record without an email, added when the instance found no emails or had errors\). The notes of all brand instances are always shown in the Notes section of the human readable output. | String |
| TotalFound | The total number of emails that were found across all brands. | Number |
| TotalDeleted | The total number of emails that were deleted across all brands. | Number |
| TotalFailed | The total number of emails that failed to be deleted across all brands. | Number |
| File.Name | The name of the retrieved attachment. Returned only when retrieve_files is true. | String |
| File.SHA256 | The SHA256 of the retrieved attachment. Returned only when retrieve_files is true. | String |

## Additional Information

---

### Vendor support

| **Vendor** | **Specific mailboxes** | **All mailboxes** | **Delete types** |
| --- | --- | --- | --- |
| Gmail | Yes | Yes | Soft, Hard |
| Microsoft Graph Mail | Yes | No | Soft only (moved to *Deleted Items*) |
| EWS v2 | Yes | Yes | Soft, Hard |

### Notes and limits

* **Safety**: at least one of `internet_message_id`, `object_id`, `subject` or `sender_address` is required, so a delete operation can never match every email in the time frame.
* **Message ID is preferred**: when `internet_message_id` is specified, `subject` and `sender_address` are ignored.
* **Untrusted values**: the search values may come from attacker controlled email headers. A message ID with whitespace, quotes, backslashes, parentheses or inner angle brackets and a sender address with whitespace, quotes, backslashes or parentheses are rejected. In Gmail and EWS v2 subject queries, `"` and `\` are replaced with a space (the subject is a phrase search). In Microsoft Graph Mail the values are escaped and URL-encoded in the `$filter`.
* **object_id**: requires exactly one `target_mailbox` and one brand, with `mailbox_scope` set to *Specific*. When the email does not exist, `AdditionalFields.NotFound=true` is returned for the brand.
* **Enabled instances**: when no enabled instance of the requested brands is found, the run fails with "No enabled instance was found for the requested brands.".
* **Microsoft Graph Mail** cannot search all mailboxes (an error is reported for the brand, suggesting Gmail or EWS on-prem) and cannot hard delete (the emails are moved to *Deleted Items* and a note is added).
* **Gmail all mailboxes**: in a domain with more than 500 accounts, Gmail splits the all-mailboxes search into background sub-searches whose results are not available to this script. This is reported as an error for the brand. Use specific mailboxes or another brand.
* **Pagination**: result pages are followed, and when a vendor caps the number of returned emails the search is repeated after the deletion until no emails are left (up to 10 rounds). A soft deleted Microsoft Graph Mail / EWS email is moved to *Deleted Items* under a new ID, so emails whose mailbox and Internet Message ID were already processed in an earlier round are skipped (they are not counted or deleted again).
* **EWS email details**: only the first 50 emails that EWS returns are fetched in full (HTML body and attachments). The other emails are reported with the fields returned by the search.
* **Vendor notes**: notes of a brand instance (for example, capped results, no hard delete or an exhausted timeout budget) are appended to each other in `AdditionalFields.Note` and are shown in a *Notes* section of the human readable output.

### Timeout

The script runs once and synchronously: the integration instances are run one after the other, each running the search, the retrieval of the files and the deletion. `timeout` is the overall time budget of the run, in seconds (default and maximum 1800, since the run must finish within the 35 minutes script timeout). It is checked before each integration instance is run and before each email is processed. When it is exhausted, the integration instances that were not run yet are reported as failed, the remaining emails are not processed (in *Search & Delete* they are reported with `Success=false` and counted in `TotalFailed`, and a note is added) and the results collected so far are returned.

### Output

The script returns a single War Room entry with the `EmailData` context, `TotalFound`, `TotalDeleted` and `TotalFailed`. The human readable output is a table titled `Search & Delete Email - <operation>` with the columns `Brand`, `Mailbox`, `ID`, `Subject`, `From`, `To`, `Timestamp`, `Operation`, `Success` and `Reason`, and a summary line (`Total found | Total deleted | Total failed`). When nothing was found, the table is replaced with "No emails were found.". The vendor notes are appended in a *Notes* section. When `verbose` is true, the list of executed commands is appended. When the operation failed for all the integrations, the entry is returned as an error entry with the reasons.

### Examples

Search and soft delete an email by its Internet Message ID in specific mailboxes and limit the run to 30 minutes:

```text
!SearchAndDeleteEmail operation="Search & Delete" delete_type=soft timeout=1800 internet_message_id="<abc@example.com>" target_mailbox="user1@example.com,user2@example.com" time_frame="7 days"
```

Only search all mailboxes for a sender and subject, and retrieve the attachments:

```text
!SearchAndDeleteEmail operation="Search Only" sender_address="bad@evil.com" subject="Invoice" mailbox_scope=All retrieve_files=true brands="Gmail,EWS v2"
```
