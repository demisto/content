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
* Microsoft Graph Security: `msg-list-ediscovery-cases`, `msg-create-ediscovery-case`, `msg-create-ediscovery-search`, `msg-run-estimate-statistics`, `msg-get-last-estimate-statistics-operation`, `msg-purge-ediscovery-data`, `msg-list-case-operation`, `msg-delete-ediscovery-search`
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
* **Microsoft Graph Security**: the script reuses (or creates) the *XSOAR Auto Phishing* eDiscovery case, creates a search, runs estimate statistics, purges the matching emails and **always deletes the search at the end** (also for *Search Only* and also when a step fails). For *Specific* scope, the mailboxes are matched using `recipients:` in the KQL query, so copies of the email in other mailboxes may match too. The API returns only totals, therefore per-email details and attachments are not available.
* **Microsoft Graph Mail** cannot search all mailboxes and cannot hard delete.
* **Message ID is preferred**: when `internet_message_id` is specified, `subject` and `sender_address` are ignored.
* **Large searches**: searching thousands of mailboxes is resource heavy. Long running operations are polled (default timeout of 1 hour per operation, script timeout of 3 hours). Result pages are followed, and when a vendor caps the number of returned emails the search is repeated after the deletion until no emails are left.
* **Safety**: at least one of `internet_message_id`, `object_id`, `subject` or `sender_address` is required, so a delete operation can never match every email in the time frame.

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| internet_message_id | One or more Internet Message IDs of the emails to search for or delete. When specified, it is preferred over subject and sender_address. |
| object_id | The vendor specific ID of the email (for example, the ItemID in EWS). When specified, target_mailbox (a single mailbox) and a single brand must also be specified. |
| operation | The operation to perform. "Search Only" searches for the emails and cleans up any search item that was created. "Search &amp; Delete" also deletes the emails that were found. |
| delete_type | The delete type to use when the operation is "Search &amp; Delete", where supported by the vendor. Default is Soft Delete. |
| time_frame | How far back to search, for example "7 days" or "3 hours". Supported units are minutes, hours, days, weeks and months. Default is 1 hour. |
| subject | One or more email subjects to search for. Ignored when internet_message_id is specified. |
| sender_address | The sender address to search for. Can be used together with subject. |
| retrieve_files | Whether to retrieve the attachments of the emails before they are deleted. Default is false. |
| target_mailbox | The mailbox(es) to search in. Required when mailbox_scope is "Specific". |
| mailbox_scope | Whether to search specific mailboxes or all mailboxes. Default is Specific. |
| brands | The brands to run the operation on. If empty, all enabled instances of the supported brands are used. |
| verbose | Whether to include the list of executed commands in the human readable output. Default is false. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | The unified results of the search and delete operation. | Unknown |
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
| EmailData.AdditionalFields | Additional vendor specific fields, such as the object ID and the instance name. | Unknown |
| EmailData.TotalFound | The total number of emails that were found by the brand. | Number |
| EmailData.TotalDeleted | The total number of emails that were deleted by the brand. | Number |
| EmailData.TotalFailed | The total number of emails that failed to be deleted by the brand. | Number |
| File.Name | The name of the retrieved attachment. Returned only when retrieve_files is true. | String |
| File.SHA256 | The SHA256 of the retrieved attachment. Returned only when retrieve_files is true. | String |

## Error handling

---
Every vendor instance is executed independently. A failure of one vendor does not stop the others, and the errors are aggregated into the human readable output and into `EmailData.Reason`. When all vendors fail, the script does not fail: it returns a human readable table with the failure of each vendor and one `EmailData` entry per vendor with `Success=false`.

## Examples

---

Search and soft delete an email by its Internet Message ID in specific mailboxes:

```text
!SearchAndDeleteEmail operation="Search & Delete" internet_message_id="<abc@example.com>" target_mailbox="user1@example.com,user2@example.com" time_frame="7 days"
```

Only search all mailboxes for a sender and subject, and retrieve the attachments:

```text
!SearchAndDeleteEmail operation="Search Only" sender_address="bad@evil.com" subject="Invoice" mailbox_scope=All retrieve_files=true brands="Gmail,EWS v2"
```
