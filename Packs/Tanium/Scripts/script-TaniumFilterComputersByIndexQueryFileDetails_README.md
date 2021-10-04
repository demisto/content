Gets the requested sensors from all of the machines where the index query file details match the given filter.
For example, `!TaniumFilterQuestionByIndexQueryFileDetails sensors="Computer Name" filter_type=contains filter_value=Demisto limit=5` 
will be translated to the following plain text Tanium question:
"Get Computer Name from all machines with any Index Query File Details[*, *, *, *, *, *, *, 5] containing "Demisto"".

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | tanium |


## Dependencies
---
This script uses the following commands and scripts.
* tn-ask-manual-question

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| directoryPath | The glob of the directory's name used for searching. For example, "Windows". |
| fileName | The glob of the file's name used for searching. For example, "*exe". |
| fileSize | The glob of the file's size used for searching. For example, "10??". |
| fileMD5Hash | The glob of the file's MD5 hash used for searching. For example, "1c7b*". |
| fileSHA1Hash |  The glob of the file's SHA1 hash used for searching. For example, "1c7b*". |
| fileSHA256Hash | The gob of the file's SHA256 hash used for searching. For example, "1c7b*". |
| magicNumber | The glob of a magic number used for searching. For example, "4D54*". |
| limit | The maximum number of rows to return. |
| filter_type | The type of filter to apply to the question results. |
| filter_value | The value to filter the results by. |
| sensors | The semicolon separated list of columns to return. For example, "Computer Name;IP Address". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tanium.QuestionResults.Computer Name | The computer name that contains the index query file details as specified by the filters. | Unknown |
| Tanium.QuestionResults.Count | The number or results per computer name that match the filter. | Unknown |
