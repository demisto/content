Use Core REST APIs
This integration was integrated and tested with version xx of Core REST API_mm

## Configure Core REST API_mm on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Core REST API_mm.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Core Server URL |  | True |
    | API Key ID | Please provide API Key ID when using Cortex XSIAM or Cortex XSOAR 8.0.0 and above. | False |
    | API Key |  | False |
    | Authentication method | Whether authentication should be using "Standard" API key or "Advanced" API key. For XSOAR version &amp;lt; 8.0.0, choose "Standard". | False |
    | Base marketplace url |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Use tenant | Whether API calls should be made to the current tenant instead of the main tenant. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### demisto-api-post

***
send HTTP POST request

#### Base Command

`demisto-api-post`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /incident). | Required | 
| body | Body of HTTP POST. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-get

***
send HTTP GET requests

#### Base Command

`demisto-api-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /user). | Required | 

#### Context Output

There is no context output for this command.
### demisto-api-put

***
send HTTP PUT request

#### Base Command

`demisto-api-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /user). | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-delete

***
send HTTP DELETE request

#### Base Command

`demisto-api-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /user). | Required | 

#### Context Output

There is no context output for this command.
### demisto-api-download

***
Download files from Demisto server

#### Base Command

`demisto-api-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI. | Required | 
| filename | File name of download. | Optional | 
| description | Description of file entry. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-multipart

***
Send HTTP Multipart request to upload files to Demisto server

#### Base Command

`demisto-api-multipart`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI. | Required | 
| entryID | File entry ID. | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-delete-incidents

***
Delete Demisto incidents

#### Base Command

`demisto-delete-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of the incidents to delete. | Required | 
| fields | Comma separated list of fields to return, case sensitive. Set "all" for all fields. WARNING: Setting all fields may result in big results. Default is id,name,type,severity,status. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-install-packs

***
Upload packs to Demisto server from url or the marketplace.

#### Base Command

`demisto-api-install-packs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| packs_to_install | The packs to install in JSON format (e.g. [{"AutoFocus": "2.0.8"}] ). | Optional | 
| file_url | The pack zip file url. | Optional | 
| entry_id | The War Room entry ID of the pack zip file. | Optional | 
| skip_verify | If true will skip pack signature validation, Available from 6.5.0 server version. Possible values are: true, false. Default is true. | Optional | 
| skip_validation | If true will skip all pack validations, Available from 6.6.0 server version. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-post

***
send HTTP POST request

#### Base Command

`core-api-post`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /incident). | Required | 
| body | Body of HTTP POST. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-get

***
send HTTP GET requests

#### Base Command

`core-api-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /user). | Required | 

#### Context Output

There is no context output for this command.
### core-api-put

***
send HTTP PUT request

#### Base Command

`core-api-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /user). | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-delete

***
send HTTP DELETE request

#### Base Command

`core-api-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI (i.e. /user). | Required | 

#### Context Output

There is no context output for this command.
### core-api-download

***
Download files from core server

#### Base Command

`core-api-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI. | Required | 
| filename | File name of download. | Optional | 
| description | Description of file entry. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-multipart

***
Send HTTP Multipart request to upload files to core server

#### Base Command

`core-api-multipart`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request URI. | Required | 
| entryID | File entry ID. | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### core-delete-incidents

***
Delete core incidents

#### Base Command

`core-delete-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of the incidents to delete. | Required | 
| fields | Comma separated list of fields to return, case sensitive. Set "all" for all fields. WARNING: Setting all fields may result in big results. Default is id,name,type,severity,status. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-install-packs

***
Upload packs to core server from url or the marketplace.

#### Base Command

`core-api-install-packs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| packs_to_install | The packs to install in JSON format (e.g. [{"AutoFocus": "2.0.8"}] ). | Optional | 
| file_url | The pack zip file url. | Optional | 
| entry_id | The War Room entry ID of the pack zip file. | Optional | 
| skip_verify | If true will skip pack signature validation, Available from 6.5.0 server version. Possible values are: true, false. Default is true. | Optional | 
| skip_validation | If true will skip all pack validations, Available from 6.6.0 server version. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-file-upload

***
This command uploads to the incident a file that the user provided according to the entry_id or the content of the file

#### Base Command

`core-api-file-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident's id. | Required | 
| file_name | The new file's name. | Required | 
| file_content | The new file's content. | Optional | 
| entry_id | The War Room entry ID of the pack zip file. | Optional | 
| target | Where to upload the file. Possible values are: War Room Entry, Incident Attachment. Default is War Room Entry. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-file-delete

***
This command deletes a file from Xsoar by entry_id.

#### Base Command

`core-api-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the pack zip file. | Required | 

#### Context Output

There is no context output for this command.
### core-api-file-attachment-delete

***
This command deletes the attachment from the incident and from the XSOAR server

#### Base Command

`core-api-file-attachment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident's id. | Required | 
| file_path | The file's path. | Required | 
| field_name | Name of the field (type attachment) you want to remove the attachment. Default is incident.attachment. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!core-api-file-attachment-delete file_path=2@1 incident_id=1```
#### Human Readable Output

>Attachment 2@1 deleted !

### core-api-file-check

***
This command checks if the file is existing in Xsoar by entry_id

#### Base Command

`core-api-file-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the pack zip file. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!core-api-file-check entry_id=111```
#### Human Readable Output

>```
>{
>    "HumanReadable": "File 111 exists",
>    "outputs": {
>        "response": "<!doctype html><html lang=\"en\"><head><title>Cortex XSOAR</title><meta charset=\"utf-8\"><meta name=\"description\" content=\"Cortex XSOAR\"><meta name=\"keywords\" content=\"security,incident response,attack playback,forensics\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,maximum-scale=1\"><link rel=\"shortcut icon\" href=\"/favicon.ico?v=1645910757727\"><link href=\"/assets/light-bundle-1645910757727.css?v=1645910757727\" rel=\"stylesheet\"></head><body><div id=\"app\"></div><script src=\"/assets/light-bundle-1645910757727.js?v=1645910757727\"></script></body></html>"
>    },
>    "outputs_prefix": "IsFileExists"
>}
>```

### core-api-file-rename

***
This command “rename” the given file by deleting the current file (by entry_id) and uploading a new file with the new name and the current content.

#### Base Command

`core-api-file-rename`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the pack zip file. | Required | 
| new_file_name | The new file's name. | Required | 

#### Context Output

There is no context output for this command.
