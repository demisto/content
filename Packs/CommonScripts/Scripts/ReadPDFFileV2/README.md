Load a PDF file's content and metadata into context. Supports extraction of hashes, urls, and emails when available.


## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, ingestion |
| Cortex XSOAR Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The War Room entryID of the file to read. |
| userPassword | The password for the file, if encrypted. |
| maxImages | The maximum number of images to extract from the PDF file. |
| unescape_url | To unescape URLs that have been escaped as part of the URLs extraction. Invalid characters will be ignored. Default is true.|

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL.Data | The list of URLs that were extracted from the PDF file. | String |
| File.Text | The text that was extracted from the PDF file. | String |
| File.Producer | The producer of the PDF file. | String |
| File.Title | The title of the PDF file. | String |
| File.Author | The author of the PDF file. | String |
| File.ModDate | The ModDate of the PDF file. | Date |
| File.CreationDate | The CreationDate of the PDF file. | Date |
| File.Pages | The number of pages in the PDF file. | String |
| File.Size | The file size in bytes. | Number |
| File.Form | The PDF form type. | String |
| File.Encrypted | Whether the file is encrypted. | String |
| File.FileSize | The file size in bytes. | String |
| File.SHA1 | The SHA1 file hash of the file. | String |
| File.PageRot | The page rotation of the PDF file. | String |
| File.Optimized | Whether the page has been optimized. | String |
| File.SHA256 | The SHA256 file hash of the file. | String |
| File.PDFVersion | The PDF version. | String |
| File.Name | The name of the PDF file. | String |
| File.Creator | The creator of the PDF file. | String |
| File.Tagged | Whether the file has tagged meta-information. | String |
| File.SSDeep | The SSDeep hash of the file. | String |
| File.EntryID | The Entry ID of the file. | String |
| File.JavaScript | Whether the file is in JavaScript. | String |
| File.Info | The additional information about the file. | String |
| File.PageSize | The PDF file page size. | String |
| File.Type | The file type. | String |
| File.Suspects | Indicates the presence of tag suspects. | String |
| File.MD5 | The MD5 file hash of the file. | String |
| File.UserProperties | Indicates the presence of the structure elements that contain user properties attributes. | String |
| File.Extension | The file's extension. | String |
| Account.Email | The email address of the account. | String |
| Hashes.type | The hash type extracted from the PDF file. | String |
| Hashes.value | The hash value extracted from the PDF file. | String |
