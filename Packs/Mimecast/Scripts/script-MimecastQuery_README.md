Deprecated. Use mimecsat-query command instead.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Mimecast |


## Dependencies
---
This script uses the following commands and scripts.
* mimecast-query

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| queryXml | The query string XML to search for using Mimecast Unified Search Experience (MUSE) For more information click [here](https://community.mimecast.com/docs/DOC-2262). Using this script will override other query arguments. |
| text | Searches for text in API messages. |
| dryRun | Will not execute the query, but will just return the query string that was built. |
| date | Searches the specific dates only. |
| dateFrom | Searches emails from a specific date. In format 2015-09-21T23:00:00Z. |
| dateTo | Searches emails up until a specific date. In format 2015-09-21T23:00:00Z. |
| sentTo | The filter on the messages to a specific address. |
| sentFrom | The filter on the messages from a specific address. |
| subject | Searches emails by subject. This will override the text argument. |
| attachmentType |The messages with and without attachments. Any messages with any attachment documents can contain, "doc", "dot", "docx", "docm", "dotx", "dotm", "pdf", "rtf", "html" attachments. Spreadsheets can contain, "xls", "xlt", "xlsx", "xlsm", "xltx", "xltm", "xlsb", "xlam", "csv". Presentations can contain, "ppt", "pptx", "pptm", "potx", "potm", "ppam", "ppsx", "ppsm", "sldx", "sldm", "thms", "pps". Text messages can contain, "txt", "text", "html", "log". Images messages can contain, "jpg", "jpeg", "png", "bmp", "gif", "psd", "tif", "tiff". Media messages can contain, "mp3", "mp4", "m4a", "mpg", "mpeg", "avi", "wav", "aac", "wma", "mov". Zip messages can contain, "zip", "rar", "cab", "gz", "gzip", "7z". None messages will have no attachments and will not be present in the results. (optional) |
| attachmentText | Searches for text in the attachments. |
| body | Searches emails by text in the body. This will override the text and subject arguments. |
| pageSize | Sets the number of results to return per page. The default is 25. |
| startRow | Sets the result to start returning results. The default is 0. |
| active | Defines if the search should query recently received messages that are not fully indexed yet. The default is false. Search can be done by mailbox and date time across active messages. |

## Outputs
---
There are no outputs for this script.
