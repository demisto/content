After running DeleteContext, this script can repopulate all the file entries in the ${File} context key with ${AttachmentFile}.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility |

---
## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| fields | List of field name which to extract attachment files from. |

---
## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | Filename | String |
| File.Type | File type | String |
| File.Size | File size | Number |
| File.MD5 | MD5 hash of the file | String |
| File.SHA1 | SHA1 hash of the file | String |
| File.SHA256 | SHA256 hash of the file | String |
| File.EntryID | EntryID of the file | String |
| File.Info | File information | String |
| File.Extension | File extension | String |
| File.SSDeep | SSDeep hash of the file | String |
| AttachmentFile.Name | Filename | String |
| AttachmentFile.Type | File type | String |
| AttachmentFile.Size | File size | Number |
| AttachmentFile.MD5 | MD5 hash of the file | String |
| AttachmentFile.SHA1 | SHA1 hash of the file | String |
| AttachmentFile.SHA256 | SHA256 hash of the file | String |
| AttachmentFile.EntryID | EntryID of the file | String |
| AttachmentFile.Info | File information | String |
| AttachmentFile.Extension | File extension | String |
| AttachmentFile.SSDeep | SSDeep hash of the file | String |
| AttachmentFile.Attachment.description | File description | String |
| AttachmentFile.Attachment.name | File name | String |
| AttachmentFile.Attachment.path | File path | String |
| AttachmentFile.Attachment.showMediaFile | showMediaFile | Boolean |
| AttachmentFile.Attachment.type | File content type | String |
