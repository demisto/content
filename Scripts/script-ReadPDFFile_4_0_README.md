Loads the contents and metadata of a PDF file into context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility, ingestion |
| Demisto Version | 3.6.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The War Room entryID of the file to read. |
| maxFileSize | The maximal file size to load, in bytes. The default is 1MB. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL.Data | The list of URLs that were extracted from the PDF file. | Unknown |
| File.Text | The extracted text of the PDF file. | Unknown |
| File.Producer | The producer of the PDF file. | Unknown |
| File.Title | The title of the PDF file. | Unknown |
| File.xap | The XAP of the PDF file. | Unknown |
| File.Author | The author of the PDF file. | Unknown |
| File.dc | The DC of the PDF file.| Unknown |
| File.xapmm | The XAPMM of the PDF file. | Unknown |
| File.ModDate | The modification date of the PDF file. | Unknown |
| File.CreationDate | The creation date of the PDF file. | Unknown |
| File.Pages | The number of pages in the PDF file. | Unknown |
