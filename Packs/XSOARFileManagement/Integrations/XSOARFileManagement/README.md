This integration uses the XSOAR API to perform basic but essentials actions on files.

## Configure XSOAR File Management in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) | Make sure XSOAR config 'External Host Name' is set and let this field empty otherwise set the external ip of XSOAR. Using https://127.0.0.1 don't work. | False |
| XSOAR Server API Key |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### file-management-upload-file-to-incident

***
Copies a file from this incident to the specified incident. Usefull if you want to manipule file in the preprocessing

#### Base Command

`file-management-upload-file-to-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentID | Incident ID to upload the file. If empty, the current incident ID is taken. | Optional | 
| fileContent | Non binary content of the file (if set let filePath and filePath empty). | Optional | 
| entryID | Entry ID of the file to read (if set let filePath and fileContent empty). | Optional | 
| filePath | Path of the file to read ex: incident.attachment.path (if set let entryID and fileContent empty). | Optional | 
| fileName | Name of the file. Mandatory if used with filePath and fileContent otherwise the name of the file will not change. | Optional | 
| target | Where to upload the file - Available options are: - 'war room entry': the file will be uploaded as war room entry. - 'incident attachment': the file will be uploaded as incident attachment. - default are 'war room entry'. Possible values are: war room entry, incident attachment. Default is war room entry. | Optional | 

#### Context Output

There is no context output for this command.
### file-management-delete-file

***
Delete the file from the incident and from the XSOAR server

#### Base Command

`file-management-delete-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | Entry ID of the file. | Required | 

#### Context Output

There is no context output for this command.
### file-management-check-file

***
Check if entry ID exist

#### Base Command

`file-management-check-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | Entry ID of the file. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IsFileExists | unknown | Dictionary with EntryID as key and boolean if the file exists as value | 

### file-management-delete-attachment

***
Delete the attachment from the incident and from the XSOAR server.

#### Base Command

`file-management-delete-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filePath | File path of the file. | Required | 
| incidentID | ID of the incident to delete attachment. | Optional | 
| fieldName | Name of the field (type attachment) you want to remove the attachment by default it's the incident attachment (incident.attachment) field. | Optional | 

#### Context Output

There is no context output for this command.

### file-management-delete-custom-attachment

***
Delete the custom field attachment from the incident and from the XSOAR server.

#### Base Command

`file-management-delete-custom-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filePath | File path of the file. | Required | 
| incidentID | ID of the incident to delete attachment. | Optional | 
| fieldName | Name of the custom field (type attachment) you want to remove the attachment. | Required | 

#### Context Output

There is no context output for this command.

### file-management-rename-file

***
Rename a file. Warning: use this only if necessary, it's HEAVY to run, this will delete and recreate the file with another name !

#### Base Command

`file-management-rename-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | Entry ID of the file to rename. | Required | 
| newFileName | New name for the file. | Required | 

#### Context Output

There is no context output for this command.
### file-management-download-file

***
Download files from server.

#### Base Command

`file-management-download-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileURI | File URI ex:'/markdown/image/123_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg'. | Required | 
| fileName | Name of the new downloaded file. | Required | 
| incidentID | Incident ID to upload the file. If empty, the current incident ID is taken. | Optional | 
| target | Where to upload the file - Available options are: - 'war room entry': the file will be uploaded as war room entry. - 'incident attachment': the file will be uploaded as incident attachment. - default are 'war room entry'. Possible values are: war room entry, incident attachment. Default is war room entry. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```
!file-management-download-file file_uri="/markdown/image/12142_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg"
!file-management-download-file file_uri="/markdown/image/12142_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg" fileName="my_image.jpg"
!file-management-download-file file_uri="/markdown/image/12142_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg" fileName="my_image.jpg" incidentID="1234"
```

#### Human Readable Output

> File my_image.jpg uploaded successfully to incident 1234. Entry ID is 1@1234

### file-management-get-file-hash

***
Get file hash from URI.

#### Base Command

`file-management-get-file-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileURI | File URI ex:'/markdown/image/123_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg'. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File_Hash.Extension | String | Extension of the file. | 
| File_Hash.MD5 | String | MD5 of the file. | 
| File_Hash.Name | String | Name of the file. | 
| File_Hash.SHA1 | String | SHA1 of the file. | 
| File_Hash.SHA256 | String | SHA256 of the file. | 
| File_Hash.SHA512 | String | SHA512 of the file. | 
| File_Hash.Size | String | Size of the file. | 

#### Command Example

```!file-management-get-file-hash fileURI="/markdown/image/12142_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg" ```

#### Context Example

```json
{
  "File_Hash": {
    "Extension": "jpg",
    "MD5": "e2f28a722de24003257ded589ac10eee",
    "Name": "12142_60cad1a9-6f90-42c5-8b1b-514d66d74fc0.jpg",
    "SHA1": "0e5e761a2e6794a4d1c445667d4944db34f78d22",
    "SHA256": "877383f34532683580b53d2f5a36e68155de58175524a99d4c25d0da96202e5c",
    "SHA512": "5ba5455f0ff3e545f8212b4811d22c66451e1a96a0d886b4550bb287c310f52b4ac37559e90546ef2eae69c1a7942223fb0d2660b9fe273562a96376bc0fdd03",
    "Size": "1569787"
  }
}
```

#### Human Readable Output

> Hash save under the key 'File_Hash'.