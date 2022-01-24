Parse an email from an eml or msg file and populate all relevant context data to investigate the email. Also extracts inner attachments and returns them to the war room. The incident labels themselves are preserved and not modified - only the "Label/x" context items that originated from the labels, and the best practice is to rely on these for the remainder of the playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | email, phishing, enhancement, file |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryid | Entry ID with the Email as a file in msg or eml format |
| parse_only_headers | Will parse only the headers and return headers table |
| max_depth | How many levels deep we should parse the attached emails \(e.g. email contains an emails contains an email\). Default depth level is 3. Minimum level is 1, if set to 1 the script will parse only the first level email |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.To | This shows to whom the message was addressed, but may not contain the recipient's address. | string |
| Email.CC | Email 'cc' addresses | string |
| Email.From | This displays who the message is from, however, this can be easily forged and can be the least reliable. | string |
| Email.Subject | Email subject | string |
| Email.HTML | Email 'html' body if exists | string |
| Email.Text | Email 'text' body if exists | string |
| Email.Depth | The depth of the email. Depth=0 for the first level email. If email1 contains email2 contains email3. Then email1 depth is 0, email2 depth is 1, email3 depth is 2 | number |
| Email.Headers | Deprecated - use Email.HeadersMap output instead. The full email headers as a single string | string |
| Email.HeadersMap | The full email headers json | Unknown |
| Email.HeadersMap.From | This displays who the message is from, however, this can be easily forged and can be the least reliable. | Unknown |
| Email.HeadersMap.To | This shows to whom the message was addressed, but may not contain the recipient's address. | Unknown |
| Email.HeadersMap.Subject | Email subject | String |
| Email.HeadersMap.Date | The date and time the email message was composed | Unknown |
| Email.HeadersMap.CC | Email 'cc' addresses | Unknown |
| Email.HeadersMap.Reply-To | The email address for return mail | String |
| Email.HeadersMap.Received | List of all the servers/computers through which the message traveled | String |
| Email.HeadersMap.Message-ID | A unique string assigned by the mail system when the message is first created. These can easily be forged. \(e.g. 5c530c1b.1c69fb81.bd826.0eff@mx.google.com\) | String |
| Email.AttachmentsData.Name | The name of the attachment | String |
| Email.AttachmentsData.Content-ID | The content-id of the attachment | String |
| Email.AttachmentsData.Content-Disposition | The content-disposition of the attachment | String |
| Email.AttachmentsData.FilePath | the location of the attachment, on the XSOAR server | String |
| Email.AttachmentNames | The list of attachment names in the email | string |
| Email.Format | The format of the email if available | string |
