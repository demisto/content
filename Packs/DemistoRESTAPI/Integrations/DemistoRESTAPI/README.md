Deprecated. Use Core REST API instead.

## Configure Demisto REST API in Cortex


| **Parameter** | **Description** | **Required** |
| --- |--------------| --- |
| Demisto Server URL |  | True         |
| Demisto Server API Key |  | False        |
| Base marketplace url |  | False           |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False        |
| Demisto Server API Key |  | False        |
| Use system proxy settings | Use system proxy settings. | False        |
| Use tenant | Whether API calls should be made to the current tenant instead of the master tenant. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

***Please Note:*** When updating or making changes to a custom content item (integration, script, list, etc.), it may be necessary to increment the version of the item. To do so, first fetch the current version (usually via a GET command) and then increment the version by 1. Lastly, when updating an item, please use this incremented value for the `version` field.

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

#### Command Example
```!demisto-api-post uri=/lists/save body={\"name\":\"list_name\",\"data\":\"list_data\"}```

#### Human Readable Output

>{"response":{"commitMessage":"","data":"list_data","definitionId":"","description":"","fromServerVersion":"","id":"list_name","itemVersion":"","locked":false,"modified":"2022-05-29T12:20:14.988577Z","name":"list_name","nameLocked":false,"packID":"","prevName":"list_name","primaryTerm":6,"propagationLabels":["all"],"sequenceNumber":907233,"shouldCommit":false,"system":false,"tags":null,"toServerVersion":"","truncated":false,"type":"plain_text","vcShouldIgnore":false,"vcShouldKeepItemLegacyProdMachine":false,"version":1}}

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

#### Command Example
```!demisto-api-get uri=/user```

#### Human Readable Output

>{"response":{"addedSharedDashboards":["Threat Intelligence Feeds","Troubleshooting Instances"],"allRoles":["Administrator"],"defaultAdmin":true,"email":"admintest@demisto.com","id":"admin","image":"8327000###user_image_admin.png","lastLogin":"2022-05-29T15:13:46.224432+03:00","name":"Admin Dude","notificationsSettings":{"email":{"all":true},"pushNotifications":{"all":true}},"permissions":{"demisto":["scripts.rwx","playbooks.rw"]},"phone":"+650-123456","playgroundId":"beda-02ab-49ef-8fc1-c43a36f"}}

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

#### Command Example
```!demisto-api-delete uri=/dashboards/9a6cc590-72bb-4ed5-84e9-4577c6d8cbb9```

#### Human Readable Output

>{"response":""}

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

#### Command Example
```!demisto-api-download uri=/log/bundle```

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

#### Command Example
```!demisto-api-multipart uri=/incident/upload/204 entryID=evnKTiujxaZEkeKRxiBMig@bed9ccda-02ab-49ef-8fc1-c43a36ff38f5 body=test_bark```

#### Human Readable Output

>{"response":{"activated":"0001-01-01T00:00:00Z","attachment":[{"description":"","name":"logs-bundle-29May2214_36IDT.tar.gz","path":"204_34d-836b-4b38-81eb-9b90af9c1a_logs-bundle-29May2214_36IDT.tar.gz","showMediaFile":false,"type":"application/octet-stream"}],"autime":1653651342394000,"closed":"0001-01-01T00:00:00Z","created":"2022-05-27T13:15:51.342394+03:00","dueDate":"0001-01-01T00:00:00Z","id":"204","labels":[{"type":"Brand","value":"Grafana"},{"type":"Instance","value":"Grafana_instance_1"}],"modified":"2022-05-29T12:20:17.196279Z","name":"Adi's Alert","numericId":204,"occurred":"2022-05-27T02:02:30Z","rawName":"Adi's Alert","rawType":"Grafana Alert","sequenceNumber":545,"sourceBrand":"Grafana","sourceInstance":"Grafana_instance_1","type":"Grafana Alert","version":2}}
> 
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

#### Command Example
```!demisto-delete-incidents ids=152 fields=id,occurred```

#### Human Readable Output

>### Demisto delete incidents
>data|total|notUpdated
>---|---|---
>{"id":"206","occurred":"2022-05-29T02:02:30Z"},{"id":"205","occurred":"2022-05-27T12:00:40Z"},{"id":"204","occurred":"2022-05-27T02:02:30Z"},{"id":"203","occurred":"2022-05-27T04:51:03Z"},{"id":"202","occurred":"2022-05-26T18:16:47Z"},{"id":"201","occurred":"2022-05-26T18:03:55Z"},{"id":"200","occurred":"2022-05-26T15:36:08Z"},{"id":"199","occurred":"2022-05-26T15:31:19Z"},{"id":"198","occurred":"2022-05-26T12:00:39Z"},{"id":"197","occurred":"2022-05-26T02:42:30Z"},{"id":"196","occurred":"2022-05-25T16:02:22Z"},{"id":"195","occurred":"2022-05-25T15:58:22Z"},{"id":"194","occurred":"2022-05-25T15:55:14Z"},{"id":"193","occurred":"2022-05-25T15:54:49Z"},{"id":"192","occurred":"2022-05-25T15:54:38Z"},{"id":"191","occurred":"2022-05-25T15:41:25Z"},{"id":"190","occurred":"2022-05-25T15:39:36Z"},{"id":"189","occurred":"2022-05-25T14:52:47Z"},{"id":"188","occurred":"2022-05-25T14:52:21Z"},{"id":"187","occurred":"2022-05-25T14:43:45Z"},{"id":"186","occurred":"2022-05-25T14:38:58Z"},{"id":"185","occurred":"2022-05-25T14:36:08Z"},{"id":"184","occurred":"2022-05-25T14:28:30Z"},{"id":"183","occurred":"2022-05-25T13:36:31Z"},{"id":"182","occurred":"2022-05-25T12:00:40Z"},{"id":"181","occurred":"2022-05-25T09:52:13Z"},{"id":"180","occurred":"2022-05-25T09:45:05Z"},{"id":"179","occurred":"2022-05-25T01:59:43Z"},{"id":"161","occurred":"2022-05-24T14:47:48Z"},{"id":"160","occurred":"2022-05-24T14:47:34Z"},{"id":"159","occurred":"2022-05-24T14:45:38Z"},{"id":"158","occurred":"2022-05-24T14:45:35Z"},{"id":"157","occurred":"2022-05-24T14:39:51Z"},{"id":"156","occurred":"2022-05-24T14:37:10Z"},{"id":"155","occurred":"2022-05-24T14:37:08Z"},{"id":"154","occurred":"2022-05-24T14:37:01Z"},{"id":"153","occurred":"2022-05-24T14:29:19Z"},{"id":"151","occurred":"2022-05-24T14:27:20Z"},{"id":"150","occurred":"2022-05-24T14:27:08Z"},{"id":"149","occurred":"2022-05-24T14:24:38Z"},{"id":"148","occurred":"2022-05-24T14:24:37Z"},{"id":"147","occurred":"2022-05-24T14:24:38Z"},{"id":"146","occurred":"2022-05-24T13:43:01Z"},{"id":"145","occurred":"2022-05-24T13:41:42Z"},{"id":"144","occurred":"2022-05-24T13:41:38Z"},{"id":"143","occurred":"2022-05-24T13:40:39Z"},{"id":"142","occurred":"2022-05-24T09:43:15Z"},{"id":"141","occurred":"2022-05-24T09:43:09Z"},{"id":"140","occurred":"2022-05-24T09:39:41Z"},{"id":"139","occurred":"2022-05-24T09:17:49Z"},{"id":"138","occurred":"2022-05-24T09:15:11Z"},{"id":"137","occurred":"2022-05-24T09:15:07Z"},{"id":"136","occurred":"2022-05-24T07:14:18Z"},{"id":"135","occurred":"2022-05-24T07:14:13Z"},{"id":"134","occurred":"2022-05-24T07:13:59Z"},{"id":"133","occurred":"2022-05-24T03:12:30Z"},{"id":"132","occurred":"2022-05-24T04:16:32Z"},{"id":"131","occurred":"2022-05-24T04:13:20Z"},{"id":"130","occurred":"2022-05-24T03:08:14Z"},{"id":"129","occurred":"2022-05-24T02:42:50Z"},{"id":"128","occurred":"2022-05-23T06:51:14Z"},{"id":"127","occurred":"2022-05-23T06:51:10Z"},{"id":"126","occurred":"2022-05-23T06:34:44Z"},{"id":"125","occurred":"2022-05-23T06:34:40Z"},{"id":"124","occurred":"2022-05-23T06:32:37Z"},{"id":"123","occurred":"2022-05-23T06:32:34Z"},{"id":"122","occurred":"2022-05-23T06:31:39Z"},{"id":"121","occurred":"2022-05-23T06:31:36Z"},{"id":"120","occurred":"2022-05-23T06:30:39Z"},{"id":"119","occurred":"2022-05-23T06:30:34Z"},{"id":"118","occurred":"2022-05-23T06:12:30Z"},{"id":"117","occurred":"2022-05-23T06:09:35.746115001Z"},{"id":"116","occurred":"2022-05-23T06:08:08.132076423Z"},{"id":"115","occurred":"2022-05-23T06:07:59.975247045Z"},{"id":"114","occurred":"2022-05-23T02:42:30Z"},{"id":"113","occurred":"2022-05-23T02:23:50Z"},{"id":"112","occurred":"2022-05-23T02:17:34Z"},{"id":"111","occurred":"2022-05-22T11:16:49Z"},{"id":"110","occurred":"2022-05-22T11:16:47Z"},{"id":"109","occurred":"2022-05-22T10:23:37Z"},{"id":"108","occurred":"2022-05-22T10:23:28Z"},{"id":"107","occurred":"2022-05-22T10:23:24Z"},{"id":"106","occurred":"2022-05-22T10:23:07Z"},{"id":"105","occurred":"2022-05-22T10:23:01Z"},{"id":"104","occurred":"2022-05-22T10:22:59Z"},{"id":"103","occurred":"2022-05-22T10:22:40Z"},{"id":"102","occurred":"2022-05-22T10:22:37Z"},{"id":"101","occurred":"2022-05-22T10:22:33Z"},{"id":"100","occurred":"2022-05-22T10:16:50Z"},{"id":"99","occurred":"2022-05-22T10:16:41Z"},{"id":"98","occurred":"2022-05-22T10:16:39Z"},{"id":"97","occurred":"2022-05-22T10:16:38Z"},{"id":"96","occurred":"2022-05-22T02:18:11Z"},{"id":"95","occurred":"2022-05-22T02:11:59Z"},{"id":"94","occurred":"2022-05-21T02:28:46Z"},{"id":"93","occurred":"2022-05-21T02:21:58Z"},{"id":"92","occurred":"2022-05-20T02:02:57Z"},{"id":"91","occurred":"2022-05-20T01:56:34Z"},{"id":"90","occurred":"2022-05-22T02:32:30Z"},{"id":"89","occurred":"2022-05-21T02:42:30Z"},{"id":"88","occurred":"2022-05-20T02:22:30Z"},{"id":"87","occurred":"2022-05-19T12:40:33Z"},{"id":"86","occurred":"2022-05-19T12:40:20Z"},{"id":"85","occurred":"2022-05-19T12:39:58Z"},{"id":"84","occurred":"2022-05-19T15:39:45.467321+03:00"},{"id":"83","occurred":"2022-05-19T11:07:32Z"},{"id":"82","occurred":"2022-05-19T10:10:20Z"},{"id":"81","occurred":"2022-05-19T10:02:49Z"},{"id":"80","occurred":"2022-05-19T02:22:30Z"},{"id":"79","occurred":"2022-05-19T02:11:15Z"},{"id":"78","occurred":"2022-05-18T23:12:49Z"},{"id":"77","occurred":"2022-05-18T23:07:27Z"},{"id":"76","occurred":"2022-05-18T22:49:04Z"},{"id":"75","occurred":"2022-05-18T22:43:53Z"},{"id":"74","occurred":"2022-05-18T22:35:27Z"},{"id":"73","occurred":"2022-05-18T22:33:00Z"},{"id":"72","occurred":"2022-05-18T14:40:02Z"},{"id":"71","occurred":"2022-05-18T14:38:03Z"},{"id":"70","occurred":"2022-05-18T14:19:54Z"},{"id":"69","occurred":"2022-05-17T02:52:30Z"},{"id":"68","occurred":"2022-05-16T10:22:30Z"},{"id":"67","occurred":"2022-05-16T06:52:30Z"},{"id":"66","occurred":"2022-05-16T06:45:24.600415024Z"},{"id":"65","occurred":"2022-05-16T06:42:30Z"},{"id":"64","occurred":"2022-05-16T06:36:15.112637478Z"},{"id":"63","occurred":"2022-05-16T06:28:02.589558435Z"},{"id":"62","occurred":"2022-05-15T02:12:30Z"},{"id":"61","occurred":"2022-05-13T03:02:30Z"},{"id":"60","occurred":"2022-05-12T02:22:30Z"},{"id":"59","occurred":"2022-05-10T02:52:30Z"},{"id":"58","occurred":"2022-05-09T03:02:30Z"},{"id":"57","occurred":"2022-05-08T02:02:30Z"},{"id":"56","occurred":"2022-05-07T02:32:30Z"},{"id":"55","occurred":"2022-05-05T03:02:30Z"},{"id":"54","occurred":"2022-05-03T02:52:30Z"},{"id":"53","occurred":"2022-05-03T17:59:41.498326+03:00"},{"id":"52","occurred":"2022-03-30T01:56:47Z"},{"id":"51","occurred":"2022-03-27T10:52:09Z"},{"id":"50","occurred":"2022-03-27T09:24:29Z"},{"id":"49","occurred":"2022-03-27T09:23:57Z"},{"id":"48","occurred":"2022-03-22T05:05:28Z"},{"id":"47","occurred":"2022-03-20T11:08:56Z"},{"id":"46","occurred":"2022-03-20T07:56:41Z"} | 143 | 0

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
| skip_verify | If true will skip pack signature validation, Available from 6.5.0 server version. | Optional | 
| skip_validation | If true will skip all pack validations, Available from 6.6.0 server version. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!demisto-api-install-packs packs_to_install=[{"AutoFocus": "2.0.8"}]```

#### Human Readable Output

>The following packs installed successfully: AutoFocus