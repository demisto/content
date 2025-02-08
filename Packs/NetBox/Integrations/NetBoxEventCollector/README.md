This is the NetBox event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 3.0 and above of NetBox API. 

## Configure NetBox Event Collector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://www.example.com) | True |
| API Key | True |
| First fetch time | False |
| The maximum number of alerts per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### netbox-get-events
***
Gets events from NetBox.


#### Base Command

`netbox-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 


#### Context Output

There is no context output for this command.


#### Command Example
```!netbox-get-events should_push_events=true limit=1```

#### Human Readable Output
### journal-entries Events
|assigned_object|assigned_object_id|assigned_object_type|comments|created|created_by|custom_fields|display|id|kind|last_updated|tags|url|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| id: 4<br>url: https://www.example.com/api/dcim/devices/4/<br>display: test3<br>name: test3 | 4 | dcim.device |  | 2022-12-04T14:33:52.067484Z | 1 |  | 2022-12-04 14:33 (Info) | 6 | value: info<br>label: Info | 2022-12-07T08:19:57.807055Z |  | https://www.example.com/api/extras/journal-entries/6/ |

### object-changes Events
|action|changed_object|changed_object_id|changed_object_type|display|id|postchange_data|prechange_data|request_id|time|url|user|user_name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| value: update<br>label: Updated | id: 6<br>url: https://www.example.com/api/extras/journal-entries/6/<br>display: 2022-12-04 14:33 (Info)<br>created: 2022-12-04T14:33:52.067484Z | 6 | extras.journalentry | extras \| journal entry 2022-12-04 14:33 (Info) updated by netbox | 10 | kind: info<br>tags: <br>created: 2022-12-04T14:33:52.067Z<br>comments: <br>created_by: 1<br>last_updated: 2022-12-07T08:19:57.807Z<br>custom_fields: {}<br>assigned_object_id: 4<br>assigned_object_type: 25 | kind: <br>tags: <br>created: 2022-12-04T14:33:52.067Z<br>comments: <br>created_by: 1<br>last_updated: 2022-12-04T14:33:52.067Z<br>custom_fields: {}<br>assigned_object_id: 4<br>assigned_object_type: 25 | 12345678-abcd-1234-abcd-1234567890ab | 2022-12-07T08:19:57.810348Z | https://www.example.com/api/extras/object-changes/10/ | id: 1<br>url: https://www.example.com/api/users/users/1/<br>display: netbox<br>username: netbox | netbox |