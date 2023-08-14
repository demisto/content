This integration uses the XSOAR API to perform basic but essentials actions on files.

## Configure XSOAR File Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR File Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://example.net) | Make sure XSOAR config 'External Host Name' is set and let this field empty otherwise set the external ip of XSOAR. Using https://127.0.0.1 don't work. | False |
    | XSOAR Server API Key |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
Delete the attachment from the incident and from the XSOAR server

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
