Searches for emails (and optionally deletes them) across multiple email integrations - Gmail, Microsoft Graph Mail, Microsoft Graph Security and EWS v2 (on-premise). This script replaces the "Search And Delete Emails - Generic v2" and "Get Original Email - Generic v2" playbooks.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| internet_message_id | A comma-separated list of one or more Internet Message IDs \(the "Message-ID" email header\) of the emails to search for. When specified, it is preferred over the subject and sender address. |
| object_id | The vendor-specific ID of the email \(for example, the ItemID in EWS or the message ID in Gmail and Microsoft Graph Mail\). When specified, the "target_mailbox" and "brands" arguments must also be specified \(a single mailbox and a single brand\). Not supported for Microsoft Graph Security. |
| operation | The operation to perform. "Search Only" only searches for the emails, "Search &amp; Delete" also deletes the emails that were found. |
| delete_type | The type of deletion, relevant only when the operation is "Search &amp; Delete".<br/>Soft - the email is moved to a recoverable location \(for example, the trash or the recoverable items folder\).<br/>Hard - the email is permanently deleted, where the vendor supports it. Microsoft Graph Mail does not support a hard delete \(the email is moved to Deleted Items\). |
| time_frame | The period to search in, for example "1 hour", "3 hours" or "7 days". Only emails received within this period are returned. |
| subject | The subject of the emails to search for. Ignored when "internet_message_id" is specified. |
| sender_address | The sender address of the emails to search for. Can be combined with the subject. Ignored when "internet_message_id" is specified. |
| retrieve_files | Whether to retrieve the attachments of the found emails. The attachments are added to the "Attachments" key of the EmailData and returned as file entries \(File context key\). The attachments are retrieved before the emails are deleted. |
| target_mailbox | A comma-separated list of the mailboxes to search in \(for example, user1@example.com,user2@example.com\). Required when "mailbox_scope" is "Specific". |
| mailbox_scope | The scope of the mailboxes to search in.<br/>Specific - search only in the mailboxes specified in "target_mailbox".<br/>All - search in all the mailboxes of the organization. |
| brands | Specify the integration brands to run the command for. If not provided, the command runs for all the available \(enabled\) supported integrations.<br/>For multi-select, provide a comma-separated list. For example: 'Gmail, EWS v2'. |
| verbose | Whether to return additional email details \(body, headers, labels and so on\) in the "AdditionalFields" key of the EmailData. |
| verify_deletion | Whether to verify with the vendor that the emails were deleted, by checking that they no longer exist. Not supported for Microsoft Graph Security - a warning is returned and the deletion is performed without verification. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | The emails that were found \(or the failures that occurred\), one item per email and brand. | Unknown |
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
| EmailData.Operation | The operation that was performed \("Search Only" or "Search &amp; Delete"\). | String |
| EmailData.Brand | The integration brand that was used. | String |
| EmailData.AdditionalFields | Additional details of the email \(the object ID, the internet message ID, the deletion status and, when "verbose" is true, the body, headers and other vendor fields\). | Unknown |
| TotalFound | The total number of emails that were found. | Number |
| TotalDeleted | The total number of emails that were deleted. | Number |
| TotalFailed | The total number of emails \(or integrations\) for which the operation failed. | Number |
| File.Name | The name of the retrieved attachment. Relevant only when "retrieve_files" is true. | String |
| File.SHA256 | The SHA256 hash of the retrieved attachment. Relevant only when "retrieve_files" is true. | String |
| File.Size | The size of the retrieved attachment. Relevant only when "retrieve_files" is true. | Number |
| File.Extension | The extension of the retrieved attachment. Relevant only when "retrieve_files" is true. | String |
