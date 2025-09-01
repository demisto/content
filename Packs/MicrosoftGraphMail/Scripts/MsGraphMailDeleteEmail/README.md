A polling wrapper script; deletes an email.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user_id | User ID or principal ID \(usually an email address in the format someuser@example.com\). |
| message_id | The unique ID of the mail. This could be extracted from - msgraph-mail-list-emails command results. You cannot use the the 'MessageID' key in the form '&lt;message-id&gt;'. |
| folder_id | A comma-separated list of folder IDs. For example, mailFolders,childFolders,childFolders. |
| ran_once_flag | A flag for rate limit retry. |

## Outputs

---
There are no outputs for this script.
