
## Configure Core REST API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Core Server URL | For Cortex XSOAR 8 or Cortex XSIAM, use the Copy API URL button on the **API Keys** page. For Cortex XSOAR 6, use the server URL. | True |
| API Key ID | The API Key ID that is linked to the API Key (relevant for Cortex XSIAM and Cortex XSOAR 8.0.0 and above). | True |
| API Key (Password) | The core server API key. | True |
| Authentication method | Whether authentication should be using "Standard" API key or "Advanced" API key. | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

***Please Note:*** When updating or making changes to a custom content item (integration, script, list, etc.), it may be necessary to increment the version of the item. To do so, first fetch the current version (usually via a GET command) and then increment the version by 1. Lastly, when updating an item, please use this incremented value for the `version` field.

### core-api-post
***
send HTTP POST request


#### Base Command

`core-api-post`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /incident or /public_api/v1/incidents/update_incident). | Required | 
| body | Body of HTTP POST. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!core-api-post uri=/lists/save body={\"name\":\"list_name\",\"data\":\"list_data\"}```

#### Human Readable Output

>{"response":{"commitMessage":"","data":"list_data","definitionId":"","description":"","fromServerVersion":"","id":"list_name","itemVersion":"","locked":false,"modified":"2022-05-29T12:20:14.988577Z","name":"list_name","nameLocked":false,"packID":"","prevName":"list_name","primaryTerm":6,"propagationLabels":["all"],"sequenceNumber":907233,"shouldCommit":false,"system":false,"tags":null,"toServerVersion":"","truncated":false,"type":"plain_text","vcShouldIgnore":false,"vcShouldKeepItemLegacyProdMachine":false,"version":1}}

### core-api-get
***
send HTTP GET requests


#### Base Command

`core-api-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user or /public_api/v1/rbac/get_users). | Required | 

#### Context Output

There is no context output for this command.

#### Command Example
```!core-api-get uri=/user```

#### Human Readable Output

>{"response":{"addedSharedDashboards":["Threat Intelligence Feeds","Troubleshooting Instances"],"allRoles":["Administrator"],"defaultAdmin":true,"email":"admintest@core.com","id":"admin","image":"8327000###user_image_admin.png","lastLogin":"2022-05-29T15:13:46.224432+03:00","name":"Admin Dude","notificationsSettings":{"email":{"all":true},"pushNotifications":{"all":true}},"permissions":{"core":["scripts.rwx","playbooks.rw"]},"phone":"+650-123456","playgroundId":"beda-02ab-49ef-8fc1-c43a36f"}}

### core-api-put
***
send HTTP PUT request


#### Base Command

`core-api-put`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user). | Required | 
| body | Request body. | Optional | 


### core-api-delete
***
send HTTP DELETE request


#### Base Command

`core-api-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uri | Request endpoint (e.g. /user). | Required | 

#### Context Output

There is no context output for this command.

#### Command Example
```!core-api-delete uri=/dashboards/9a6cc590-72bb-4ed5-84e9-4577c6d8cbb9```

#### Human Readable Output

>{"response":""}

### core-api-download
***
Download files from core server


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

#### Command Example
```!core-api-download uri=/log/bundle```

#### Context Example
```json
{
    "File": {
        "EntryID": "yukswe2UVanMjyvEANmLBH@bed9ccda-02ab-49ef-8fc1-c43a",
        "Extension": "gz",
        "Info": "gz",
        "MD5": "e4e0a23740dfaa27f00b276af",
        "Name": "logs-bundle-29May2215_14IDT.tar.gz",
        "SHA1": "95e0ebd554ea107f04508d6c2d9e6361",
        "SHA256": "83032a86295279ecdf516b63eae7a7e3e5af301bf4dfed3c82faa23b58",
        "SHA512": "88a3fa0194c7dd439c749b2b0b9cbef64ce18e469d0b8b62bcf18919ffcefd1c99119c993070454d48061357ff0dd0ffe0a070936b62c7ac35035de3",
        "SSDeep": "98304:wAjPMXI9/8BoAKIxrVqJVAw6LgJEBFCH73LOOFdWgiwvSJdBo:3PmI9/8jKIxrVOELrCHwq7O",
        "Size": 4052002,
        "Type": "gzip compressed data, original size modulo 2^32 46240256"
    }
}
```

#### Human Readable Output



### core-api-multipart
***
Send HTTP Multipart request to upload files to Core server


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

#### Command Example
```!core-api-multipart uri=/incident/upload/204 entryID=evnKTiujxaZEkeKRxiBMig@bed9ccda-02ab-49ef-8fc1-c43a36ff38f5 body=test_bark```

#### Human Readable Output

>{"response":{"activated":"0001-01-01T00:00:00Z","attachment":[{"description":"","name":"logs-bundle-29May2214_36IDT.tar.gz","path":"204_34d-836b-4b38-81eb-9b90af9c1a_logs-bundle-29May2214_36IDT.tar.gz","showMediaFile":false,"type":"application/octet-stream"}],"autime":1653651342394000,"closed":"0001-01-01T00:00:00Z","created":"2022-05-27T13:15:51.342394+03:00","dueDate":"0001-01-01T00:00:00Z","id":"204","labels":[{"type":"Brand","value":"Grafana"},{"type":"Instance","value":"Grafana_instance_1"}],"modified":"2022-05-29T12:20:17.196279Z","name":"Adi's Alert","numericId":204,"occurred":"2022-05-27T02:02:30Z","rawName":"Adi's Alert","rawType":"Grafana Alert","sequenceNumber":545,"sourceBrand":"Grafana","sourceInstance":"Grafana_instance_1","type":"Grafana Alert","version":2}}
> 
### core-delete-incidents
***
Delete Core incidents


#### Base Command

`core-delete-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of the incidents to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!core-delete-incidents ids=152```

#### Human Readable Output

>### Core delete incidents
>totalDeleted | total | notUpdated
> --- | --- | ---
>  1  | 143 |  0 

### core-api-install-packs
***
Upload packs to Core server from url or the marketplace.


#### Base Command

`core-api-install-packs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| packs_to_install | The packs to install in JSON format (e.g. [{"AutoFocus": "2.0.8"}] ). | Optional |
| file_url | The pack zip file url. | Optional | 
| skip_verify | If true will skip pack signature validation, Available from 6.5.0 server version. | Optional | 
| skip_validation | If true will skip all pack validations, Available from 6.6.0 server version. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!core-api-install-packs packs_to_install=[{"AutoFocus": "2.0.8"}]```

#### Human Readable Output

>The following packs installed successfully: AutoFocus

### core-api-file-upload

***
Upload to the incident a file that the user provided according to the entry_id or the content of the file.

#### Base Command

`core-api-file-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident's ID. | Required | 
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

#### Command example
```!core-api-file-attachment-delete file_path=1@1 incident_id=1```
#### Human Readable Output

>Attachment 1@1 deleted.
### core-api-file-check

***
Check if the file exists in Cortex XSOAR (Context) by entry_id.

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