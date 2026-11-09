Searches for emails (and optionally deletes them) across multiple email integrations - Gmail, Microsoft Graph Mail, Microsoft Graph Security and EWS v2 (on-premise). This script replaces the "Search And Delete Emails - Generic v2" and "Get Original Email - Generic v2" playbooks.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts. Only the commands of the enabled integrations are used.

* Gmail: gmail-search-all-mailboxes, gmail-search, gmail-get-mail, gmail-delete-mail, gmail-get-attachments, gmail-list-users
* Microsoft Graph Mail (MicrosoftGraphMail): msgraph-mail-list-emails, msgraph-mail-get-email, msgraph-mail-delete-email, msgraph-mail-get-attachment. When all the mailboxes are searched, msgraph-user-list (Microsoft Graph User) is used to list the mailboxes.
* Microsoft Graph Security (Microsoft Graph): msg-list-ediscovery-cases, msg-create-ediscovery-case, msg-create-ediscovery-search, msg-run-estimate-statistics, msg-get-last-estimate-statistics-operation, msg-purge-ediscovery-data, msg-delete-ediscovery-search
* EWS v2: ews-search-mailbox, ews-search-mailboxes, ews-get-items, ews-delete-items, ews-get-attachment, ews-get-searchable-mailboxes

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| internet_message_id | A comma-separated list of one or more Internet Message IDs (the "Message-ID" email header) of the emails to search for. When specified, it is preferred over the subject and sender address. |
| object_id | The vendor-specific ID of the email (for example, the ItemID in EWS or the message ID in Gmail and Microsoft Graph Mail). When specified, the "target_mailbox" and "brands" arguments must also be specified (a single mailbox and a single brand). Not supported for Microsoft Graph Security. |
| operation | The operation to perform. "Search Only" only searches for the emails, "Search & Delete" also deletes the emails that were found. |
| delete_type | The type of deletion, relevant only when the operation is "Search & Delete". Soft - the email is moved to a recoverable location. Hard - the email is permanently deleted, where the vendor supports it. Microsoft Graph Mail does not support a hard delete (the email is moved to Deleted Items). Default is Soft. |
| time_frame | The period to search in, for example "1 hour", "3 hours" or "7 days". Only emails received within this period are returned. Default is 1 hour. |
| subject | The subject of the emails to search for. Ignored when "internet_message_id" is specified. |
| sender_address | The sender address of the emails to search for. Can be combined with the subject. Ignored when "internet_message_id" is specified. |
| retrieve_files | Whether to retrieve the attachments of the found emails. The attachments are added to the "Attachments" key of the EmailData and returned as file entries (File context key). The attachments are retrieved before the emails are deleted. Default is false. |
| target_mailbox | A comma-separated list of the mailboxes to search in. Required when "mailbox_scope" is "Specific". |
| mailbox_scope | The scope of the mailboxes to search in. Specific - search only in the mailboxes specified in "target_mailbox". All - search in all the mailboxes of the organization. Default is Specific. |
| brands | Specify the integration brands to run the command for. If not provided, the command runs for all the available (enabled) supported integrations. For multi-select, provide a comma-separated list. For example: 'Gmail, EWS v2'. Supported brands: Gmail, MicrosoftGraphMail, Microsoft Graph, EWS v2. |
| verbose | Whether to return additional email details (body, headers, labels and so on) in the "AdditionalFields" key of the EmailData. Default is false. |
| verify_deletion | Whether to verify with the vendor that the emails were deleted, by checking that they no longer exist. Not supported for Microsoft Graph Security - a warning is returned and the deletion is performed without verification. Default is false. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | The emails that were found (or the failures that occurred), one item per email and brand. | Unknown |
| EmailData.Mailbox | The mailbox addresses of the email. | String |
| EmailData.Subject | The subject of the email. | String |
| EmailData.From | The sender of the email. | String |
| EmailData.To | The recipients of the email. | String |
| EmailData.CC | The CC recipients of the email. | String |
| EmailData.BCC | The BCC recipients of the email. | String |
| EmailData.HTML | The HTML body of the email. | String |
| EmailData.Timestamp | The time the email was received. | String |
| EmailData.Attachments | The attachments of the email, as a dictionary of the attachment name to its SHA256 hash. Populated only when "retrieve_files" is true. | Unknown |
| EmailData.Success | Whether the operation succeeded for the email. | Boolean |
| EmailData.Reason | The failure reason, if the operation failed. | String |
| EmailData.Operation | The operation that was performed ("Search Only" or "Search & Delete"). | String |
| EmailData.Brand | The integration brand that was used. | String |
| EmailData.AdditionalFields | Additional details of the email (the object ID, the internet message ID, the deletion status and, when "verbose" is true, the body, headers and other vendor fields). | Unknown |
| TotalFound | The total number of emails that were found. | Number |
| TotalDeleted | The total number of emails that were deleted. | Number |
| TotalFailed | The total number of emails (or integrations) for which the operation failed. | Number |
| File.Name | The name of the retrieved attachment. Relevant only when "retrieve_files" is true. | String |
| File.SHA256 | The SHA256 hash of the retrieved attachment. Relevant only when "retrieve_files" is true. | String |
| File.Size | The size of the retrieved attachment. Relevant only when "retrieve_files" is true. | Number |
| File.Extension | The extension of the retrieved attachment. Relevant only when "retrieve_files" is true. | String |

## Notes

---

* **Microsoft Graph Security** is an eDiscovery-based integration. The script creates an eDiscovery search, executes it, waits for it to complete, optionally purges the matching emails and always deletes the search it created, even if an error occurs. Because eDiscovery returns statistics rather than individual emails, the matching emails are reported as a single aggregated EmailData item (the number of emails is added to *TotalFound* and *TotalDeleted*). Retrieving attachments and *object_id* are not supported for this brand.
* **Verification** (*verify_deletion*) is performed by searching again (Gmail) or by looking up the item (Microsoft Graph Mail, EWS v2). It is not supported for Microsoft Graph Security: a warning is returned and the deletion proceeds without verification.
* A failure in one integration does not stop the script. The failure is reported as an EmailData item with *Success* set to false and the *Reason*, and counted in *TotalFailed*.
