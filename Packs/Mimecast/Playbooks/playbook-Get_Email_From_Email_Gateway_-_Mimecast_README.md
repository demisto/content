Retrieve a specified eml/msg file directly from Mimecast.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MimecastV2

### Scripts
This playbook does not use any scripts.

### Commands
* mimecast-get-message

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MessageID | The message ID provided by Mimecast |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Mimecast.Message.ID | Message ID | unknown |
| Mimecast.Message.Subject | The message subject. | unknown |
| Mimecast.Message.HeaderDate | The date of the message as defined in the message headers. | unknown |
| Mimecast.Message.Size | The message size. | unknown |
| Mimecast.Message.From | Sender of the message as defined in the message header. | unknown |
| Mimecast.Message.ReplyTo | The value of the Reply-To header. | unknown |
| Mimecast.Message.EnvelopeFrom | Sender of the message as defined in the message envelope. | unknown |
| Mimecast.Message.Processed | The date the message was processed by Mimecast in ISO 8601 format. | unknown |
| Mimecast.Message.HasHtmlBody | If the message has an HTML body part. | unknown |
| Mimecast.Message.To.EmailAddress | Recipient of the message. | unknown |
| Mimecast.Message.CC.EmailAddress | Each CC recipient of the message. | unknown |
| Mimecast.Message.Headers.Name | Header's name. | unknown |
| Mimecast.Message.Headers.Values | Header's value. | unknown |
| Mimecast.Message.Attachments.FileName | Message attachment's file name. | unknown |
| Mimecast.Message.Attachments.SHA256 | Message attachment's SHA256. | unknown |
| Mimecast.Message.Attachments.ID | Message attachment's ID. | unknown |
| Mimecast.Message.Attachments.Size | Message attachment's file size. | unknown |

## Playbook Image
---
![Get Email From Email Gateway - Mimecast](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/Mimecast/doc_files/Get_Email_From_Email_Gateway_-_Mimecast.png)