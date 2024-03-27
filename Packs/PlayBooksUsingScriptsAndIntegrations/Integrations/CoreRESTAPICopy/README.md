Use Core REST APIs.
## Configure Core REST API_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Core REST API_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Core Server URL |  | True |
    | API Key ID | Please provide API Key ID when using Cortex XSIAM or Cortex XSOAR 8.0.0 and above. | False |
    | API Key |  | False |
    | Authentication method | Whether authentication should be using "Standard" API key or "Advanced" API key. For XSOAR version &lt; 8.0.0, choose "Standard". | False |
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
send HTTP POST request.

#### Base Command

`demisto-api-post`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /incident or /public_api/v1/incidents/update_incident). | Required | 
| body | Body of HTTP POST. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-get

***
send HTTP GET requests.

#### Base Command

`demisto-api-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user or /public_api/v1/rbac/get_users). | Required | 

#### Context Output

There is no context output for this command.
### demisto-api-put

***
send HTTP PUT request.

#### Base Command

`demisto-api-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user). | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-delete

***
send HTTP DELETE request.

#### Base Command

`demisto-api-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user). | Required | 

#### Context Output

There is no context output for this command.
### demisto-api-download

***
Download files from Demisto server.

#### Base Command

`demisto-api-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint. | Required | 
| filename | File name of download. | Optional | 
| description | Description of file entry. | Optional | 

#### Context Output

There is no context output for this command.
### demisto-api-multipart

***
Send HTTP Multipart request to upload files to Demisto server.

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
Delete Demisto incidents.

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
send HTTP POST request.

#### Base Command

`core-api-post`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /incident or /public_api/v1/incidents/update_incident). | Required | 
| body | Body of HTTP POST. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-get

***
send HTTP GET requests.

#### Base Command

`core-api-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user or /public_api/v1/rbac/get_users). | Required | 

#### Context Output

There is no context output for this command.
### core-api-put

***
send HTTP PUT request.

#### Base Command

`core-api-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user). | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-delete

***
send HTTP DELETE request.

#### Base Command

`core-api-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user). | Required | 

#### Context Output

There is no context output for this command.
### core-api-download

***
Download files from Core server.

#### Base Command

`core-api-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint. | Required | 
| filename | File name of download. | Optional | 
| description | Description of file entry. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-multipart

***
Send HTTP Multipart request to upload files to Core server.

#### Base Command

`core-api-multipart`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint. | Required | 
| entryID | File entry ID. | Required | 
| body | Request body. | Optional | 

#### Context Output

There is no context output for this command.
### core-delete-incidents

***
Delete Core incidents.

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
Upload packs to the core server from the URL or marketplace.

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
Upload to the incident a file that the user provided according to the entry_id or the content of the file.

#### Base Command

`core-api-file-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident's ID. | Optional | 
| file_name | The new file's name. | Optional | 
| file_content | The new file's content. | Optional | 
| entry_id | The War Room entry ID of the pack zip file. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-file-delete

***
Delete a file from Cortex XSOAR by entry_id.

#### Base Command

`core-api-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file. | Required | 

#### Context Output

There is no context output for this command.
### core-api-file-attachment-delete

***
Delete the attachment from the incident and from the Cortex XSOAR server.

#### Base Command

`core-api-file-attachment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident's ID. | Required | 
| file_path | The file's path. | Required | 
| field_name | Name of the field (type attachment) from which to remove the attachment. Default is attachment. | Optional | 

#### Context Output

There is no context output for this command.
### core-api-file-check

***
Check if the file exists in Cortex XSOAR by entry_id.

#### Base Command

`core-api-file-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IsFileExists | unknown | Dictionary with EntryID as the key and boolean if the file exists as a value. | 
