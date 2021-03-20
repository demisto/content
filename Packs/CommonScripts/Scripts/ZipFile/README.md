Zip a file and upload to war room

Supported Cortex XSOAR versions: 5.0.0 and later.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, file |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | CSV list of entry ids for the files to zip. |
| zipName | Name of the output file, for example: zipName="test" would result in output file "test.zip" |
| password | Used to create a password protected zip file. Example: password="abcd" |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ZipFile.ZippedFile | The zipped file | string |
| File.Name | The full file name \(including file extension\). | String |
| File.EntryID | The ID for locating the file in the War Room. | String |
| File.Size | The size of the file in bytes. | Number |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA1 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.SSDeep | The ssdeep hash of the file \(same as displayed in file entries\). | String |
| File.Extension | The file extension, for example: 'xls'. | String |
| File.Type | The file type, as determined by libmagic \(same as displayed in file entries\). | String |
