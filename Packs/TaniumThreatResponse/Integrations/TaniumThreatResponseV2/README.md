Use the Tanium Threat Response integration to manage endpoints processes, evidence, alerts, files, snapshots, and connections. This Integration works with Tanium Threat Response version 3.0.159 and above.
This integration was integrated and tested with versions 3.5.284 and 4.x of Tanium Threat Response v2.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Tanium Threat Response v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Hostname, IP address, or server URL | True |
| Username | False |
| Password | False |
| Fetch incidents | False |
| Incident type | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Maximum number of incidents to fetch each time | False |
| Alert states to filter by in fetch incidents command. Empty list won't filter the incidents by state. | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| API Version | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tanium-tr-get-intel-doc-by-id
***
Returns an intel document object based on ID.


#### Base Command

`tanium-tr-get-intel-doc-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | The intel document ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. | 
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. | 
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. | 
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. | 
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. | 


#### Command Example
```!tanium-tr-get-intel-doc-by-id intel_doc_id=509```

#### Context Example
```json
{
    "Tanium": {
        "IntelDoc": {
            "AlertCount": 0,
            "Compiled": "{\"expressions\":[],\"terms\":[{\"condition\":\"contains\",\"negate\":false,\"value\":\"RouteTheCall\",\"object\":\"process\",\"property\":\"command_line\"},{\"condition\":\"ends with\",\"negate\":false,\"value\":\"\\\\rundll32.exe\",\"object\":\"process\",\"property\":\"path\"},{\"condition\":\"contains\",\"negate\":false,\"value\":\"zipfldr\",\"object\":\"process\",\"property\":\"command_line\"}],\"operator\":\"and\",\"text\":\"process.path ends with '\\\\\\\\rundll32.exe' AND process.command_line contains 'zipfldr' AND process.command_line contains 'RouteTheCall'\",\"syntax_version\":1}",
            "Contents": "{\"id\":\"Zipfldr Library Proxy Execution via RouteTheCall\",\"name\":\"Zipfldr Library Proxy Execution via RouteTheCall\",\"description\":\"Detects the use of rundll32.exe to execute the RouteTheCall function in zipfldr.dll. This can be used for proxy execution to bypass AppLocker or to execute an arbitrary binary.\",\"contents\":\"process.path ends with '\\\\\\\\rundll32.exe' AND process.command_line contains 'zipfldr' AND process.command_line contains 'RouteTheCall'\",\"syntax_version\":1,\"mitreAttack\":{\"techniques\":[{\"id\":\"T1218\",\"name\":\"Signed Binary Proxy Execution\"},{\"id\":\"T1218.011\",\"name\":\"Signed Binary Proxy Execution: Rundll32\"},{\"id\":\"T1059\",\"name\":\"Command and Scripting Interpreter\"},{\"id\":\"T1059.003\",\"name\":\"Command and Scripting Interpreter: Windows Command Shell\"}]},\"platforms\":[\"windows\"]}",
            "CreatedAt": "2021-08-31T21:06:02.932Z",
            "Description": "Detects the use of rundll32.exe to execute the RouteTheCall function in zipfldr.dll. This can be used for proxy execution to bypass AppLocker or to execute an arbitrary binary.",
            "ID": 509,
            "IntrinsicId": "Zipfldr Library Proxy Execution via RouteTheCall",
            "IsSchemaValid": true,
            "LabelIds": [
                2,
                7,
                11,
                16
            ],
            "Md5": "f3ddf06be9e182ae7ddc16192dc5b846",
            "MitreAttack": "{\"techniques\":[{\"id\":\"T1218\",\"name\":\"Signed Binary Proxy Execution\"},{\"id\":\"T1218.011\",\"name\":\"Signed Binary Proxy Execution: Rundll32\"},{\"id\":\"T1059\",\"name\":\"Command and Scripting Interpreter\"},{\"id\":\"T1059.003\",\"name\":\"Command and Scripting Interpreter: Windows Command Shell\"}]}",
            "Name": "Zipfldr Library Proxy Execution via RouteTheCall",
            "Platforms": [
                "windows"
            ],
            "RevisionId": 1,
            "Size": 795,
            "SourceId": 2,
            "Type": "tanium-signal",
            "TypeVersion": "1.0",
            "UnresolvedAlertCount": 0,
            "UpdatedAt": "2021-08-31T21:06:02.932Z"
        }
    }
}
```

#### Human Readable Output

>### Intel Doc information
>|ID|Name|Type|Description|Alert Count|Unresolved Alert Count|Created At|Updated At|Label Ids|
>|---|---|---|---|---|---|---|---|---|
>| 509 | Zipfldr Library Proxy Execution via RouteTheCall | tanium-signal | Detects the use of rundll32.exe to execute the RouteTheCall function in zipfldr.dll. This can be used for proxy execution to bypass AppLocker or to execute an arbitrary binary. | 0 | 0 | 2021-08-31T21:06:02.932Z | 2021-08-31T21:06:02.932Z | 2, 7, 11, 16 |


### tanium-tr-list-intel-docs
***
Returns a list of all intel documents.


#### Base Command

`tanium-tr-list-intel-docs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of intel documents to return. Default is 50. | Optional | 
| offset | The offset number to begin listing intel documents. Default is 0. | Optional | 
| name | The name of the intel document to show. | Optional | 
| description | The description of the intel document to show. | Optional | 
| type | The type of the intel document to show. | Optional | 
| label_id | The label Id of the intel document to show. | Optional | 
| mitre_technique_id | The mitre technique Id of the intel document to show. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. | 
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. | 
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. | 
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. | 
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. | 


#### Command Example
```!tanium-tr-list-intel-docs```

#### Context Example
```json
{
    "Tanium": {
        "IntelDoc": [
            {
                "AlertCount": 0,
                "CreatedAt": "2021-09-26T20:42:12.761Z",
                "ID": 538,
                "IntrinsicId": "file",
                "IsSchemaValid": true,
                "Md5": "45d4f6197504b0cf17ca4425b27c4123",
                "Name": "file",
                "RevisionId": 1,
                "Size": 2211,
                "SourceId": 1,
                "Type": "yara",
                "TypeVersion": "3",
                "UnresolvedAlertCount": 0,
                "UpdatedAt": "2021-09-26T20:42:12.761Z"
            },
            {
                "AlertCount": 0,
                "CreatedAt": "2021-09-26T15:40:18.967Z",
                "ID": 537,
                "IntrinsicId": "111-72ad-40cc-abbf-90846fa4afec",
                "IsSchemaValid": true,
                "Md5": "45d4f619750434cf17ca4425b27c4774",
                "Name": "111-72ad-40cc-abbf-90846fa4a123",
                "RevisionId": 11,
                "Size": 2211,
                "SourceId": 1,
                "Type": "openioc",
                "TypeVersion": "1.0",
                "UnresolvedAlertCount": 0,
                "UpdatedAt": "2021-09-26T20:47:53.586Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Intel docs
>|ID|Name|Type|Alert Count|Unresolved Alert Count|Created At|Updated At|Label Ids|
>|---|---|---|---|---|---|---|---|
>| 538 | file | yara | 0 | 0 | 2021-09-26T20:42:12.761Z | 2021-09-26T20:42:12.761Z |  |
>| 537 | 111-72ad-40cc-abbf-90846fa4afec | openioc | 0 | 0 | 2021-09-26T15:40:18.967Z | 2021-09-26T20:47:53.586Z |  |
>| 536 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-26T08:18:57.462Z | 2021-09-26T08:18:57.462Z |  |
>| 535 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-26T08:11:30.717Z | 2021-09-26T08:11:30.717Z |  |
>| 534 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-26T08:11:25.484Z | 2021-09-26T08:11:25.484Z |  |
>| 533 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-26T08:11:20.802Z | 2021-09-26T08:11:20.802Z |  |
>| 532 | file.yaraaaaaa | yara | 0 | 0 | 2021-09-26T08:09:54.927Z | 2021-09-26T08:09:54.927Z |  |
>| 531 | file.yaraa | yara | 0 | 0 | 2021-09-26T08:09:52.564Z | 2021-09-26T08:09:52.564Z |  |
>| 530 | yar | yara | 0 | 0 | 2021-09-26T08:09:28.253Z | 2021-09-26T08:09:28.253Z |  |
>| 529 | file.yar | yara | 0 | 0 | 2021-09-23T15:35:01.784Z | 2021-09-23T15:35:01.784Z |  |
>| 528 | file.stix | yara | 0 | 0 | 2021-09-23T15:33:49.920Z | 2021-09-23T15:33:49.920Z |  |
>| 527 | file.stix | yara | 0 | 0 | 2021-09-23T15:32:25.580Z | 2021-09-23T15:32:25.580Z |  |
>| 526 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T15:00:32.350Z | 2021-09-23T15:00:32.350Z |  |
>| 525 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T14:41:32.831Z | 2021-09-23T14:41:32.831Z |  |
>| 524 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T14:41:07.857Z | 2021-09-23T14:41:07.857Z |  |
>| 523 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T14:32:26.310Z | 2021-09-23T14:32:26.310Z |  |
>| 522 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T13:47:31.088Z | 2021-09-23T13:47:31.088Z |  |
>| 521 | STUXNET VIRUS (METHODOLOGY) | openioc | 0 | 0 | 2021-09-23T12:18:03.865Z | 2021-09-23T12:18:03.865Z |  |
>| 520 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T12:04:08.473Z | 2021-09-23T12:04:08.473Z |  |
>| 519 | CybOX-represented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-09-23T12:03:50.295Z | 2021-09-23T12:03:50.295Z |  |
>| 518 | New Test5 | openioc | 0 | 0 | 2021-09-23T12:03:10.503Z | 2021-09-23T12:03:10.503Z |  |
>| 517 | New Test5 | openioc | 0 | 0 | 2021-09-23T07:21:07.201Z | 2021-09-23T07:21:07.201Z |  |
>| 516 | New Test5 | openioc | 0 | 0 | 2021-09-22T16:27:09.399Z | 2021-09-22T16:27:09.399Z |  |
>| 515 | New Test5 | openioc | 0 | 0 | 2021-09-22T07:52:58.242Z | 2021-09-22T07:52:58.242Z |  |
>| 514 | New Test5 | openioc | 0 | 0 | 2021-09-22T07:47:43.503Z | 2021-09-22T07:47:43.503Z |  |
>| 513 | RDP Enabled via Registry Modification | tanium-signal | 0 | 0 | 2021-09-22T07:47:02.110Z | 2021-09-22T07:47:02.110Z |  |
>| 512 | New Test5 | openioc | 0 | 0 | 2021-09-22T07:17:26.951Z | 2021-09-22T07:17:26.951Z |  |
>| 511 | New Test5 | openioc | 0 | 0 | 2021-09-19T06:33:12.579Z | 2021-09-19T06:33:12.579Z |  |
>| 510 | file.yar | yara | 0 | 0 | 2021-09-12T14:02:03.769Z | 2021-09-12T14:02:03.769Z |  |
>| 509 | Zipfldr Library Proxy Execution via RouteTheCall | tanium-signal | 0 | 0 | 2021-08-31T21:06:02.932Z | 2021-08-31T21:06:02.932Z | 2, 7, 11, 16 |
>| 508 | Url Library Proxy Execution via OpenURL | tanium-signal | 0 | 0 | 2021-08-31T21:06:02.639Z | 2021-08-31T21:06:02.639Z | 2, 7, 11, 16 |
>| 507 | Url Library Proxy Execution via FileProtocolHandler | tanium-signal | 0 | 0 | 2021-08-31T21:06:02.611Z | 2021-08-31T21:06:02.611Z | 2, 7, 11, 16 |
>| 506 | Shell32 Library Proxy Execution via ShellExec_RunDLL | tanium-signal | 0 | 0 | 2021-08-31T21:06:02.140Z | 2021-08-31T21:06:02.140Z | 2, 7, 11, 16 |
>| 505 | Shdocvw Library Proxy Execution via OpenURL | tanium-signal | 0 | 0 | 2021-08-31T21:06:02.116Z | 2021-08-31T21:06:02.116Z | 2, 7, 11, 16 |
>| 504 | Pcwutl Library Proxy Execution via LaunchApplication | tanium-signal | 0 | 0 | 2021-08-31T21:06:01.540Z | 2021-08-31T21:06:01.540Z | 2, 7, 11, 16 |
>| 503 | Ieframe Library Proxy Execution via OpenURL | tanium-signal | 0 | 0 | 2021-08-31T21:06:00.862Z | 2021-08-31T21:06:00.862Z | 2, 7, 11, 16 |
>| 502 | Reputation Malicious Hashes | reputation | 0 | 0 | 2021-08-19T06:54:59.350Z | 2021-08-19T06:57:47.882Z |  |
>| 501 | file.yar | yara | 0 | 0 | 2021-07-28T12:37:29.611Z | 2021-07-28T12:37:29.611Z |  |
>| 500 | file.yar | yara | 0 | 0 | 2021-07-28T12:35:41.367Z | 2021-07-28T12:35:41.367Z |  |
>| 499 | file.yar | yara | 0 | 0 | 2021-07-28T12:35:39.670Z | 2021-07-28T12:35:39.670Z |  |
>| 498 | Vssadmin Create Shadow Copy | tanium-signal | 0 | 0 | 2021-07-27T21:56:02.320Z | 2021-07-27T21:56:02.320Z | 2, 8, 16 |
>| 497 | Volume Shadow Copy Creation | tanium-signal | 0 | 0 | 2021-07-27T21:56:02.295Z | 2021-07-27T21:56:02.295Z | 2, 8, 16 |
>| 496 | Remote Proxy Execution | tanium-signal | 0 | 0 | 2021-07-27T21:56:01.712Z | 2021-07-27T21:56:01.712Z | 2, 7, 11, 16 |
>| 495 | Non-Ssms Spawned SQL Client Tools PowerShell Session | tanium-signal | 0 | 0 | 2021-07-27T21:56:01.246Z | 2021-07-27T21:56:01.246Z | 2, 7, 11, 16 |
>| 494 | Non-Microsoft Signed Print Spooler Driver | tanium-signal | 0 | 0 | 2021-07-27T21:56:01.227Z | 2021-07-27T21:56:01.227Z | 2, 6, 16 |
>| 493 | file.yar | yara | 0 | 0 | 2021-07-27T14:44:32.182Z | 2021-07-27T14:44:32.182Z |  |
>| 492 | file.yar | yara | 0 | 0 | 2021-07-27T14:44:19.862Z | 2021-07-27T14:44:19.862Z |  |
>| 491 | file.yar | yara | 0 | 0 | 2021-07-27T14:44:15.595Z | 2021-07-27T14:44:15.595Z |  |
>| 490 | file.yar | yara | 0 | 0 | 2021-07-27T14:44:13.294Z | 2021-07-27T14:44:13.294Z |  |
>| 489 | CybOX-re presented Indicator Created from OpenIOC File | stix | 0 | 0 | 2021-07-27T14:42:43.888Z | 2021-07-27T14:42:43.888Z |  |


### tanium-tr-list-alerts
***
Returns a list of all alerts.


#### Base Command

`tanium-tr-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts to return. Default is 5. | Optional | 
| offset | The offset number to begin listing alerts. | Optional | 
| computer_ip_address | Filter alerts by the specified computer IP addresses. | Optional | 
| computer_name | Filter alerts by the specified computer name. | Optional | 
| scan_config_id | Filter alerts by the specified scan config ID. | Optional | 
| intel_doc_id | Filter alerts by the specified intel document ID. | Optional | 
| severity | Filter alerts by the specified severity. | Optional | 
| priority | Filter alerts by the specified priority. | Optional | 
| type | Filter alerts by the specified type. | Optional | 
| state | Filter alerts by the specified state. Can be "Unresolved", "In Progress", "Dismissed" "Ignored", or "Resolved". Possible values are: Unresolved, In Progress, Ignored, Resolved, Dismissed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The moment that the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The last time the alert state was updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress", and so on. | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The name of the alert type. For example, "detect.endpoint.match". | 
| Tanium.Alert.ID | Number | The ID of the alert. For example, "123". | 
| Tanium.Alert.CreatedAt | Date | The date when the alert was received by the Detect product. | 
| Tanium.Alert.IntelDocId | Number | The intel document revision, if intelDocId is present. | 
| Tanium.Alert.Severity | String | The severity of the alert. | 


#### Command Example
```!tanium-tr-list-alerts limit=2```

#### Context Example
```json
{
    "Tanium": {
        "Alert": [
            {
                "AlertedAt": "2019-09-22T14:01:31.000Z",
                "ComputerIpAddress": "1.1.1.1",
                "ComputerName": "host0",
                "CreatedAt": "2019-09-22T14:01:59.768Z",
                "GUID": "a33e3482-556e-4e9d-bbbd-2fdbe330d492",
                "ID": 1,
                "IntelDocId": 64,
                "Priority": "high",
                "Severity": "info",
                "State": "Unresolved",
                "Type": "detect.match",
                "UpdatedAt": "2021-10-24T01:28:04.275Z"
            },
            {
                "AlertedAt": "2020-02-29T15:29:59.000Z",
                "ComputerIpAddress": "1.1.1.1",
                "ComputerName": "host0",
                "CreatedAt": "2020-02-29T15:30:29.893Z",
                "GUID": "626821e1-6b0a-4afb-a1f9-8fb7ef741736",
                "ID": 2,
                "IntelDocId": 17,
                "Priority": "high",
                "Severity": "info",
                "State": "Unresolved",
                "Type": "detect.match",
                "UpdatedAt": "2021-10-24T01:28:04.275Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts
>|ID|Type|Severity|Priority|Alerted At|Created At|Updated At|Computer Ip Address|Computer Name|GUID|State|Intel Doc Id|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2021-10-24T01:28:04.275Z | 1.1.1.1 | host0 | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |
>| 2 | detect.match | info | high | 2020-02-29T15:29:59.000Z | 2020-02-29T15:30:29.893Z | 2021-10-24T01:28:04.275Z | 1.1.1.1 | host0 | 626821e1-6b0a-4afb-a1f9-8fb7ef741736 | Unresolved | 17 |


### tanium-tr-get-alert-by-id
***
Returns an alert object based on alert ID.


#### Base Command

`tanium-tr-get-alert-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Alert.Priority | String | The priority of the alert. | 
| Tanium.Alert.ComputerName | String | The hostname of the computer that generated the alert. | 
| Tanium.Alert.GUID | String | A globally unique identifier for this alert in the customer environment. | 
| Tanium.Alert.AlertedAt | Date | The date when the alert was generated. | 
| Tanium.Alert.UpdatedAt | Date | The date when the alert state was last updated. | 
| Tanium.Alert.State | String | The current state of the alert. For example, "unresolved", "inprogress". | 
| Tanium.Alert.ComputerIpAddress | String | The IP address of the computer that generated the alert. | 
| Tanium.Alert.Type | String | The name of the alert type. For example, "detect.endpoint.match". | 
| Tanium.Alert.ID | Number | The ID of the alert. For example, "123". | 
| Tanium.Alert.CreatedAt | Date | The date when the alert was received by the Detect product. | 
| Tanium.Alert.IntelDocId | Number | The intel document revision, if intelDocId is present. | 
| Tanium.Alert.Severity | String | The severity of the alert. | 


#### Command Example
```!tanium-tr-get-alert-by-id alert_id=1```

#### Context Example
```json
{
    "Tanium": {
        "Alert": {
            "AlertedAt": "2019-09-22T14:01:31.000Z",
            "ComputerIpAddress": "1.1.1.1",
            "ComputerName": "host0",
            "CreatedAt": "2019-09-22T14:01:59.768Z",
            "GUID": "a33e3482-556e-4e9d-bbbd-2fdbe330d492",
            "ID": 1,
            "IntelDocId": 64,
            "Priority": "high",
            "Severity": "info",
            "State": "Unresolved",
            "Type": "detect.match",
            "UpdatedAt": "2021-10-24T01:28:04.275Z"
        }
    }
}
```

#### Human Readable Output

>### Alert information
>|ID|Type|Severity|Priority|Alerted At|Created At|Updated At|Computer Ip Address|Computer Name|GUID|State|Intel Doc Id|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | detect.match | info | high | 2019-09-22T14:01:31.000Z | 2019-09-22T14:01:59.768Z | 2021-10-24T01:28:04.275Z | 1.1.1.1 | host0 | a33e3482-556e-4e9d-bbbd-2fdbe330d492 | Unresolved | 64 |


### tanium-tr-alert-update-state
***
Updates the state of the specified alerts.


#### Base Command

`tanium-tr-alert-update-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alert IDs to update. | Required | 
| state | The new state for the alerts. Can be "Unresolved", "In Progress", "Dismissed", "Ignored", or "Resolved". Possible values are: dismissed, unresolved, inprogress, ignored, resolved. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-alert-update-state alert_ids=1 state=resolved```

#### Human Readable Output

>Alert state updated to resolved.

### tanium-tr-create-snapshot
***
Captures a new snapshot by connection id.


#### Base Command

`tanium-tr-create-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.SnapshotTask.connection | String | Connection id of the snapshot. | 
| Tanium.SnapshotTask.startTime | Date | Snapshot start time. | 
| Tanium.SnapshotTask.status | String | Snapshot creation task status. | 
| Tanium.SnapshotTask.taskId | Number | Snapshot creation task id. You can get task status using \`tanium-tr-get-task-by-id\` command. | 


#### Command Example
```!tanium-tr-create-snapshot connection_id=remote:hostname:123:```

#### Context Example
```json
{
    "Tanium": {
        "SnapshotTask": {
            "connection": "remote:hostname:123:",
            "startTime": "2021-10-07T12:22:29.550Z",
            "status": "STARTED",
            "taskId": 1177
        }
    }
}
```

#### Human Readable Output

>Initiated snapshot creation request for remote:hostname:123:. Task id: 1177.

### tanium-tr-delete-snapshot
***
Deletes a snapshot by connection name and snapshot ID.


#### Base Command

`tanium-tr-delete-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshot_ids | The snapshot IDs to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-delete-snapshot snapshot_ids=eda5ddce-0f8c-48e8-8dd5-6aa18681d539,3893fa77-4829-4e48-9364-40a16ad6cc0f```

#### Human Readable Output

>Snapshot eda5ddce-0f8c-48e8-8dd5-6aa18681d539,3893fa77-4829-4e48-9364-40a16ad6cc0f deleted successfully.

### tanium-tr-list-snapshots
***
Returns all local snapshots of a single connection.


#### Base Command

`tanium-tr-list-snapshots`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of local snapshots to return. Default is 50. | Optional | 
| offset | The offset number to begin listing local snapshots. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Snapshot.size | String | The snapshot size. | 
| Tanium.Snapshot.created | String | The snapshot creation date. | 
| Tanium.Snapshot.completed | String | The snapshot completed date. | 
| Tanium.Snapshot.name | String | The snapshot name. | 
| Tanium.Snapshot.isUpload | Boolean | Is the snapshot uplaod. | 
| Tanium.Snapshot.evidenceType | String | Evidence type. | 
| Tanium.Snapshot.hostname | String | Hxstname of the snapshot. | 
| Tanium.Snapshot.connectionId | String | The snapshot connection ID. | 
| Tanium.Snapshot.recorderVersion | String | Recorder Version. | 
| Tanium.Snapshot.uuid | String | The snapshot uuid. | 


#### Command Example
```!tanium-tr-list-snapshots limit=2```

#### Context Example
```json
{
    "Tanium": {
        "Snapshot": [
            {
                "completed": "2021-10-06T06:42:03.260Z",
                "connectionId": "remote:hostname:123:",
                "created": "2021-10-06T06:40:48.297Z",
                "evidenceType": "snapshot",
                "hostname": "hostname2",
                "isUpload": false,
                "name": "host1-1633502448297.db",
                "recorderVersion": 2,
                "size": 152064000,
                "username": "administrator",
                "uuid": "832dec40-1cc2-4e53-881a-7f61cba835bc"
            },
            {
                "completed": "2021-10-06T06:43:21.474Z",
                "connectionId": "remote:hostname:123:",
                "created": "2021-10-06T06:42:07.010Z",
                "evidenceType": "snapshot",
                "hostname": "hostname1",
                "isUpload": false,
                "name": "host1-1633502527010.db",
                "recorderVersion": 2,
                "size": 152064000,
                "username": "administrator",
                "uuid": "340a3ac4-560d-430f-bd50-96615d763171"
            }
        ]
    }
}
```

#### Human Readable Output

>### Snapshots:
>|Uuid|Name|Evidence Type|Hostname|Created|
>|---|---|---|---|---|
>| 832dec40-1cc2-4e53-881a-7f61cba835bc | host1-1633502448297.db | snapshot | hostname2 | 2021-10-06T06:40:48.297Z |
>| 340a3ac4-560d-430f-bd50-96615d763171 | host2-1633502527010.db | snapshot | hostname1 | 2021-10-06T06:42:07.010Z |


### tanium-tr-delete-local-snapshot
***
Deletes a local snapshot by connection id.


#### Base Command

`tanium-tr-delete-local-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-delete-local-snapshot connection_id=remote:hostname:123:```

#### Human Readable Output

>Local snapshot of connection remote:hostname:123: was deleted successfully.

### tanium-tr-list-connections
***
Returns all connections.


#### Base Command

`tanium-tr-list-connections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of connections to return. Default is 50. | Optional | 
| offset | The offset number to begin listing connections. Default is 0. | Optional | 
| status | Comma-seperated list of statuses to get the connections that match only those statuses, for example status=connected,waiting. Possible values are: disconnected, timeout, waiting, connected. | Optional | 
| ip | Comma-seperated list of ips to get the connections that match only those ips, for example status=1.1.1.1,1.1.1.1. | Optional | 
| platform | Comma-seperated list of platforms to get the connections that match only those platforms, for example platform=Linux,Windows. | Optional | 
| hostname | Comma-seperated list of hostnames to get the connections that match only those hostnames, for example hostname=host1,host2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Connection.id | String | The connection id. | 
| Tanium.Connection.initiatedAt | Date | Time when the connection was first created. | 
| Tanium.Connection.hostname | String | The connection hostname. | 
| Tanium.Connection.status | String | Current connection state. | 
| Tanium.Connection.platform | String | The connection operating system. | 
| Tanium.Connection.ip | String | The connection ip. | 
| Tanium.Connection.connectedAt | String | Time when the connection was connected. | 
| Tanium.Connection.message | String | The connection message describing the status. | 
| Tanium.Connection.personaId | String | The connection persona Id. | 
| Tanium.Connection.clientId | String | The client id. | 
| Tanium.Connection.userId | String | The connection user id. | 
| Tanium.Connection.eid | String | The connection eid. | 
| Tanium.Connection.hasTools | Boolean | Has connection tools. | 


#### Command Example
```!tanium-tr-list-connections```

#### Context Example
```json
{
    "Tanium": {
        "Connection": [
            {
                "clientId": "123",
                "connectedAt": "2021-09-22T12:08:39.000Z",
                "eid": "2",
                "hasTools": true,
                "hostname": "hostname",
                "id": "remote:hostname:123:",
                "initiatedAt": "2021-09-22T12:08:35.000Z",
                "ip": "1.1.1.1",
                "message": "The connection has been disconnected.",
                "personaId": 0,
                "platform": "Windows",
                "status": "disconnected",
                "userId": "1"
            },
            {
                "clientId": "11111",
                "hostname": "localhost",
                "id": "remote:localhost:11111:",
                "initiatedAt": "2021-09-09T08:17:38.000Z",
                "ip": "1.2.3.4",
                "message": "The connection has timed out.",
                "personaId": 0,
                "platform": "Linux",
                "status": "timeout",
                "userId": "1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Connections
>|Id|Status|Hostname|Message|Ip|Platform|Connected At|
>|---|---|---|---|---|---|---|
>| rremote:hostname:123: | disconnected | hostname | The connection has been disconnected. | 1.1.1.1 | Windows | 2021-09-22T12:08:39.000Z |
>| remote:localhost:1111: | timeout | localhost | The connection has timed out. | 1.2.3.4 | Linux |  |


### tanium-tr-create-connection
***
Creates a local or remote connection.


#### Base Command

`tanium-tr-create-connection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Client id. Use `tanium-tr-get-system-status` to get all possible client_ids. | Required | 
| ip | IP address to connect. Use `tanium-tr-get-system-status` to get all possible ips. | Required | 
| platform | Commputers platform - "Windows", "Linux", etc. | Required | 
| hostname | Hostname of the computer to connect. Use `tanium-tr-get-system-status` to get all possible hostnames. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Connection.id | String | New connection id. | 


#### Command Example
```!tanium-tr-create-connection client_id=123 ip=1.1.1.1 hostname=host1 platform=Windows```

#### Context Example
```json
{
    "Tanium": {
        "Connection": {
            "id": "remote:host1:123:"
        }
    }
}
```

#### Human Readable Output

>Initiated connection request to "remote:host1:123:".

### tanium-tr-delete-connection
***
Deletes a connection by connection id.


#### Base Command

`tanium-tr-delete-connection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-delete-connection connection_id=remote:host1:123:```

#### Human Readable Output

>Connection `remote:host1:123:` deleted successfully.

### tanium-tr-close-connection
***
Closes a connection by connection id.


#### Base Command

`tanium-tr-close-connection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-close-connection connection_id=remote:host1:123:```

#### Human Readable Output

>Connection `remote:host1:123:` closed successfully.

### tanium-tr-list-labels
***
Returns all available labels in the system.


#### Base Command

`tanium-tr-list-labels`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of labels to return. Default is 50. | Optional | 
| offset | The offset number to begin listing labels. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Label.createdAt | Date | The date when this label was created. | 
| Tanium.Label.description | String | An extended description of the label. | 
| Tanium.Label.id | Number | The unique identifier for this label. | 
| Tanium.Label.indicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.Label.name | String | The display name of the label. | 
| Tanium.Label.signalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.Label.updatedAt | Date | The date when this label was last updated, not including the intel and signal counts. | 


#### Command Example
```!tanium-tr-list-labels limit=2```

#### Context Example
```json
{
    "Tanium": {
        "Label": [
            {
                "createdAt": "2019-07-31T18:46:28.629Z",
                "description": "These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed.",
                "id": 1,
                "indicatorCount": 0,
                "name": "Alpha",
                "signalCount": 0,
                "updatedAt": "2019-07-31T18:46:28.629Z"
            },
            {
                "createdAt": "2019-07-31T18:46:28.629Z",
                "description": "These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed.",
                "id": 2,
                "indicatorCount": 0,
                "name": "Beta",
                "signalCount": 420,
                "updatedAt": "2019-07-31T18:46:28.629Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Labels
>|Name|Description|Id|Indicator Count|Signal Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 1 | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
>| Beta | These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed. | 2 | 0 | 420 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |


### tanium-tr-get-label-by-id
***
Returns a label object based on label ID.


#### Base Command

`tanium-tr-get-label-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label_id | The label ID. (Use tanium-tr-intel-docs-labels-list command in order to get the available label IDs). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Label.createdAt | Date | The date when this label was created. | 
| Tanium.Label.description | String | An extended description of the label. | 
| Tanium.Label.id | Number | The unique identifier for this label. | 
| Tanium.Label.indicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.Label.name | String | The display name of the label. | 
| Tanium.Label.signalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.Label.updatedAt | Date | The date this label was last updated, not including the intel and signal counts. | 


#### Command Example
```!tanium-tr-get-label-by-id label_id=1```

#### Context Example
```json
{
    "Tanium": {
        "Label": {
            "createdAt": "2019-07-31T18:46:28.629Z",
            "description": "These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed.",
            "id": 1,
            "indicatorCount": 0,
            "name": "Alpha",
            "signalCount": 0,
            "updatedAt": "2019-07-31T18:46:28.629Z"
        }
    }
}
```

#### Human Readable Output

>### Label information
>|Name|Description|Id|Indicator Count|Signal Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 1 | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |


### tanium-tr-list-file-downloads
***
Returns all downloaded files in the system.


#### Base Command

`tanium-tr-list-file-downloads`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of files to return. Default is 50. | Optional | 
| offset | Offset to start getting file downloads. Default is 0. | Optional | 
| sort | Column which to sort by. | Optional | 
| hostname | Comma-seperated list of hostnames to get the downloaded files that match only those hostnames, for example hostname=host1,host2. | Optional | 
| hash | Comma-seperated list of hashes to get the downloaded files that match only those hashes, for example hash=123,456. | Optional | 
| process_time_start | Get the downloaded files that match only to the process time start, for example process_time_start=2019-09-03T17:51:40.000Z. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.size | Number | The size of the file, in bytes. | 
| Tanium.FileDownload.path | String | The path of the file. | 
| Tanium.FileDownload.downloaded | Date | The date when this file was downloaded. | 
| Tanium.FileDownload.hostname | String | The hostname of the downloaded file. | 
| Tanium.FileDownload.processCreationTime | Date | The date when the file was created. | 
| Tanium.FileDownload.hash | String | The file hash. | 
| Tanium.FileDownload.uuid | Number | The downloaded file uuid. | 
| Tanium.FileDownload.lastModified | Date | The date when the file was last modified. | 
| Tanium.FileDownload.createdBy | String | The user that created this file. | 
| Tanium.FileDownload.createdByProc | String | The process path that created this file. | 
| Tanium.FileDownload.lastModifiedBy | String | The user that last modified this file. | 
| Tanium.FileDownload.lastModifiedByProc | String | The process path that modified this file. | 
| Tanium.FileDownload.evidenceType | String | The evidence type - file. | 


#### Command Example
```!tanium-tr-list-file-downloads limit=2```

#### Context Example
```json
{
    "Tanium": {
        "FileDownload": [
            {
                "downloaded": "2020-01-15 13:04:02.827",
                "evidenceType": "file",
                "hash": "99297a0e626ca092ff1884ad28f54453",
                "hostname": "host1",
                "lastModified": "2020-01-15T08:57:19.000Z",
                "path": "C:\\Program Files (x86)\\log1.txt",
                "processCreationTime": "2019-09-03T17:51:40.000Z",
                "size": 10485904,
                "uuid": "c0531415-87a6-4d28-a226-b485784b1881"
            },
            {
                "downloaded": "2020-01-15 18:17:10.595",
                "evidenceType": "file",
                "hash": "7d1677decbfaf1598ccd745fc197eb1c",
                "hostname": "host2",
                "lastModified": "2020-01-13T13:11:35.000Z",
                "path": "C:\\Program Files (x86)\\log8.txt",
                "processCreationTime": "2019-09-03T17:51:40.000Z",
                "size": 10485940,
                "uuid": "3043ef9c-78a9-4f19-8fb9-ddbab202d03b"
            }
        ]
    }
}
```

#### Human Readable Output

>### File downloads
>|Uuid|Path|Evidence Type|Hostname|Process Creation Time|Size|
>|---|---|---|---|---|---|
>| c0531415-87a6-4d28-a226-b485784b1881 | C:\Program Files (x86)\log1.txt | file | host1 | 2019-09-03T17:51:40.000Z | 10485904 |
>| 3043ef9c-78a9-4f19-8fb9-ddbab202d03b | C:\Program Files (x86)\log8.txt | file | host2 | 2019-09-03T17:51:40.000Z | 10485940 |


### tanium-tr-get-downloaded-file
***
Gets the actual content of a downloaded file by file ID. Downloaded file password: `infected`.


#### Base Command

`tanium-tr-get-downloaded-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The file ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.EntryID | String | File entry ID. | 
| File.Extension | String | The extension of the file. | 
| File.Info | String | Information about the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.SSDeep | String | The SSDeep hash of the file \(same as displayed in file entries\). | 
| File.Size | Number | The size of the file in bytes. | 
| File.Type | String | The file type. | 


#### Command Example
```!tanium-tr-get-downloaded-file file_id=c0531415-87a6-4d28-a226-b485784b1881```

#### Context Example
```json
{
    "File": {
        "EntryID": "7608@e99f97d1-7225-4c75-896c-3c960febbe8c",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "217cac2e10c1d11ed55ab2ede6bdb0ea",
        "Name": "c0531415-87a6-4d28-a226-b485784b1881.zip",
        "SHA1": "20808150526b092f5e4e19c82af2e9b2a1303e89",
        "SHA256": "40c605face875cd53f07c1301ffc9fce0ed5b12a65c729fe73895e44cdcdebdf",
        "SHA512": "50415634cae426da763a39532f3d22eeea5a79a8868044f6b3ffca8b528cce92cbe9f4d7b98d6d1cb49a705f3182b2c43f84f628acd748fb78e6cca85939b10c",
        "SSDeep": "12288:npzKFzLrU/2fzXVPkrnjuYyTNW+o4T5SD7BDy6PFP8NjglLSAK:npeFzLI/6FknjuY4nojJm6NP8NjQi",
        "Size": 598728,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output



### tanium-tr-list-events-by-connection
***
Queries events for a connection.


#### Base Command

`tanium-tr-list-events-by-connection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 
| type | The type of event. Can be "File", "Network", "Registry", "Process", "Driver", "Combined", "DNS", or "Image". The default is "Combined". Possible values are: File, Network, Registry, Process, Driver, Combined, DNS, Image. Default is combined. | Required | 
| limit | The maximum number of events to return. Default is 50. | Optional | 
| offset | Offset to start getting the result set. Default is 0. | Optional | 
| filter | Advanced search that filters according to event fields. For example: [['process_id', 'gt', '30'], ['username', 'ne', 'administrator']]. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time (UTC). Optional operators: eq (equals), ne (does not equal); for integers/date: gt (greater than), gte (greater than or equals), ls (less than), lse (less than or equals); for strings: co (contains), nc (does not contain). . | Optional | 
| match | Whether the results should fit all filters or at least one filter. Possible values are: all, any. Default is all. | Optional | 
| sort | A comma-separated list of fields to sort on prefixed by +/- for ascending or descending and ordered by priority left to right. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time (UTC). | Optional | 
| fields | A comma-separated list of fields on which to search. Optional fields: process_id, process_name, process_hash, process_command_line, username, process_name, create_time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TaniumEvent.id | String | The ID of the event. | 
| TaniumEvent.groupName | String | The group name of the event. | 
| TaniumEvent.file | String | The path of the file in the event. | 
| TaniumEvent.operation | String | The event operation. | 
| TaniumEvent.processId | Number | The ID of the process. | 
| TaniumEvent.pid | Number | The ID of the process. | 
| TaniumEvent.processPath | String | The path of the process. | 
| TaniumEvent.processTableId | Number | The ID of the process table. | 
| TaniumEvent.timestamp | Date | The date when the event was created. | 
| TaniumEvent.userName | String | The username associated with the event. | 
| TaniumEvent.remoteAddress | String | The network event destination address. | 
| TaniumEvent.remoteAddressPort | Number | The network event destination port. | 
| TaniumEvent.localAddress | String | The network event source address. | 
| TaniumEvent.localAddressPort | Number | The network event source port. | 
| TaniumEvent.keyPath | String | The registry key path. | 
| TaniumEvent.valueName | String | The registry value name. | 
| TaniumEvent.exitCode | Number | The process exit code. | 
| TaniumEvent.processCommandLine | String | The process command line. | 
| TaniumEvent.parentCommandLine | String | The parent command line. | 
| TaniumEvent.processHash | String | The hash value of the process. | 
| TaniumEvent.hashes | String | The hashes of the driver. | 
| TaniumEvent.imageLoaded | String | The image loaded path of the driver. | 
| TaniumEvent.signature | String | The signature of the driver. | 
| TaniumEvent.signed | Boolean | Whether the driver is signed. | 
| TaniumEvent.eventId | Number | The ID of the event. | 
| TaniumEvent.eventOpcode | Number | The event opcode. | 
| TaniumEvent.eventRecordId | Number | The ID of the event record. | 
| TaniumEvent.eventTaskId | Number | The ID of the event task. | 
| TaniumEvent.query | String | The query of the DNS. | 
| TaniumEvent.response | String | The response of the DNS. | 
| TaniumEvent.imagePath | String | The image path. | 
| TaniumEvent.createTime | Date | The process creation time | 
| TaniumEvent.endTime | Date | The process end time. | 
| TaniumEvent.eventTaskName | String | The name of the event task. | 
| TaniumEvent.hash | String | The process hash. | 


#### Command Example
```!tanium-tr-list-events-by-connection connection_id=remote:hostname:123: type=File limit=2```

#### Context Example
```json
{
    "TaniumEvent": [
        {
            "eventOperationId": 0,
            "file": "C:\\Windows\\f1.dat",
            "groupName": "NT AUTHORITY",
            "id": "4611686018470089188",
            "operation": "Create",
            "pid": 736,
            "processPath": "C:\\Windows\\t.exe",
            "processTableId": "72057594038528503",
            "timestamp": "2021-07-18 07:28:04.007",
            "timestampRaw": 1626593284007,
            "userName": "LOCAL SERVICE"
        },
        {
            "eventOperationId": 1,
            "file": "C:\\Windows\\f2.dat",
            "groupName": "NT AUTHORITY",
            "id": "4611686018470089189",
            "operation": "Write",
            "pid": 736,
            "processPath": "C:\\Windows\\d.exe",
            "processTableId": "72057594038528503",
            "timestamp": "2021-07-18 07:28:04.007",
            "timestampRaw": 1626593284007,
            "userName": "LOCAL SERVICE"
        }
    ]
}
```

#### Human Readable Output

>### Events for remote:hostname:123:
>|Id|File|Timestamp|Process Table Id|Process Path|User Name|
>|---|---|---|---|---|---|
>| 4611686018470089188 | C:\Windows\f1.dat | 2021-07-18 07:28:04.007 | 72057594038528503 | C:\Windows\t.exe | LOCAL SERVICE |
>| 4611686018470089189 | C:\Windows\f2.dat | 2021-07-18 07:28:04.007 | 72057594038528503 | C:\Windows\d.exe | LOCAL SERVICE |


### tanium-tr-get-file-download-info
***
Gets the metadata of a file download.


#### Base Command

`tanium-tr-get-file-download-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | File download ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownload.size | Number | The size of the file, in bytes. | 
| Tanium.FileDownload.path | String | The path of the file. | 
| Tanium.FileDownload.downloaded | Date | The date when this file was downloaded. | 
| Tanium.FileDownload.hostname | String | The hostname of the downloaded file. | 
| Tanium.FileDownload.processCreationTime | Date | The date when the file was created. | 
| Tanium.FileDownload.hash | String | The file hash. | 
| Tanium.FileDownload.uuid | Number | The downloaded file uuid. | 
| Tanium.FileDownload.lastModified | Date | The date when the file was last modified. | 
| Tanium.FileDownload.createdBy | String | The user that created this file. | 
| Tanium.FileDownload.createdByProc | String | The process path that created this file. | 
| Tanium.FileDownload.lastModifiedBy | String | The user that last modified this file. | 
| Tanium.FileDownload.lastModifiedByProc | String | The process path that modified this file. | 
| Tanium.FileDownload.evidenceType | String | The evidence type - file. | 


#### Command Example
```!tanium-tr-get-file-download-info file_id=c0531415-87a6-4d28-a226-b485784b1881```

#### Context Example
```json
{
    "Tanium": {
        "FileDownload": {
            "downloaded": "2020-01-15 13:04:02.827",
            "evidenceType": "file",
            "hash": "123456789",
            "hostname": "host1",
            "lastModified": "2020-01-15T08:57:19.000Z",
            "path": "C:\\log1.txt",
            "processCreationTime": "2019-09-03T17:51:40.000Z",
            "size": 10485904,
            "uuid": "c0531415-87a6-4d28-a226-b485784b1881"
        }
    }
}
```

#### Human Readable Output

>### File download
>|Uuid|Path|Evidence Type|Hostname|Process Creation Time|Size|
>|---|---|---|---|---|---|
>| c0531415-87a6-4d28-a226-b485784b1881 | C:\log1.txt | file | host1 | 2019-09-03T17:51:40.000Z | 10485904 |


### tanium-tr-get-process-info
***
Get information for a process.


#### Base Command

`tanium-tr-get-process-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 
| ptid | The process table ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessInfo.childrenCount | Number | Nuber of process children. | 
| Tanium.ProcessInfo.context | String | Process tree context. | 
| Tanium.ProcessInfo.createTime | Date | Time when the process was created. | 
| Tanium.ProcessInfo.createTimeRaw | Date | Timestamp when the process was created. | 
| Tanium.ProcessInfo.dnsEventsCount | Number | Number of DNS events in the process. | 
| Tanium.ProcessInfo.driverEventsCount | Number | Number of Driver events in the process. | 
| Tanium.ProcessInfo.endTime | Date | Process termination time. | 
| Tanium.ProcessInfo.endTimeRaw | Date | Process termination timestamp. | 
| Tanium.ProcessInfo.exitCode | Number | Process exit code. | 
| Tanium.ProcessInfo.fileEventsCount | Number | Number of File events in the process. | 
| Tanium.ProcessInfo.groupName | String | Process group name. | 
| Tanium.ProcessInfo.hashTypeName | String | Hash type. | 
| Tanium.ProcessInfo.id | String | Process id at the tanium system. | 
| Tanium.ProcessInfo.imageEventsCount | Number | Number of Image events in the process. | 
| Tanium.ProcessInfo.networkEventsCount | Number | Number of network events in the process. | 
| Tanium.ProcessInfo.parentProcessTableId | String | Parent process table id. | 
| Tanium.ProcessInfo.pid | Number | The ID of the process. | 
| Tanium.ProcessInfo.processEventsCount | Number | Number of process events in the process. | 
| Tanium.ProcessInfo.processHash | String | Process hash. | 
| Tanium.ProcessInfo.processPath | String | The process path. | 
| Tanium.ProcessInfo.processTableId | String | The ID of the process table. | 
| Tanium.ProcessInfo.registryEventsCount | Number | Number of registry events in the process. | 
| Tanium.ProcessInfo.securityEventsCount | Number | Number of security events in the process. | 
| Tanium.ProcessInfo.uniqueProcessId | String | Unique process id. | 
| Tanium.ProcessInfo.userName | String | The username who created the process. | 


#### Command Example
```!tanium-tr-get-process-info ptid=72057594038510321 connection_id=remote:hostname:123:```

#### Context Example
```json
{
    "Tanium": {
        "ProcessInfo": {
            "childrenCount": 0,
            "context": "node",
            "createTime": "2021-07-09 12:38:19.372",
            "createTimeRaw": 1625834299372,
            "dnsEventsCount": 0,
            "driverEventsCount": 0,
            "endTime": "2021-07-09 12:39:49.413",
            "endTimeRaw": 1625834389413,
            "exitCode": 0,
            "fileEventsCount": 0,
            "groupName": "NT AUTHORITY",
            "hashTypeName": "MD5",
            "id": "72057594038510321",
            "imageEventsCount": 0,
            "networkEventsCount": 0,
            "parentProcessTableId": "72057594038528485",
            "pid": 3648,
            "processEventsCount": 1,
            "processHash": "e1bce838cd2695999ab34215bf94b501",
            "processPath": "C:\\test.exe",
            "processTableId": "72057594038510321",
            "registryEventsCount": 0,
            "securityEventsCount": 0,
            "uniqueProcessId": "-8410859473941295552",
            "userName": "LOCAL SERVICE"
        }
    }
}
```

#### Human Readable Output

>### Process information for process with PTID 72057594038510321
>|Pid|Process Table Id|Parent Process Table Id|Process Path|
>|---|---|---|---|
>| 3648 | 72057594038510321 | 72057594038528485 | C:\test.exe |


### tanium-tr-get-events-by-process
***
Gets the events for a process.


#### Base Command

`tanium-tr-get-events-by-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection name. | Required | 
| ptid | The process instance ID. | Required | 
| type | The type of event. Can be "File", "Network", "Registry", "Process", "Driver", "Combined", "DNS", or "Image". The default is "Combined". Possible values are: File, Network, Registry, Process, Driver, Combined, DNS, Image. Default is combined. | Required | 
| limit | The maximum number of events to return. Default is 50. | Optional | 
| offset | The offset number to begin listing events. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessEvent.id | Number | The ID of the event. | 
| Tanium.ProcessEvent.detail | Unknown | The event details. | 
| Tanium.ProcessEvent.operation | String | The event operation. | 
| Tanium.ProcessEvent.timestamp | Date | Time when the event was created. | 
| Tanium.ProcessEvent.type | String | The event type. | 


#### Command Example
```!tanium-tr-get-events-by-process connection_id=remote:hostname:123: type=Process ptid=72057594038528485 limit=2```

#### Context Example
```json
{
    "Tanium": {
        "ProcessEvent": [
            {
                "detail": "4428: C:\\test.exe",
                "id": "72057594038510294",
                "operation": "CreateChild",
                "timestamp": "2021-07-09 12:20:05.490",
                "timestampRaw": 1625833205490,
                "type": "Process"
            },
            {
                "detail": "1792: C:\\test.exe",
                "id": "72057594038510295",
                "operation": "CreateChild",
                "timestamp": "2021-07-09 12:20:05.541",
                "timestampRaw": 1625833205541,
                "type": "Process"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events for process 72057594038528485
>|Id|Detail|Type|Timestamp|Operation|
>|---|---|---|---|---|
>| 72057594038510294 | 4428: C:\test.exe | Process | 2021-07-09 12:20:05.490 | CreateChild |
>| 72057594038510295 | 1792: C:\test.exe | Process | 2021-07-09 12:20:05.541 | CreateChild |



### tanium-tr-get-process-children
***
Gets the children of this process instance.


#### Base Command

`tanium-tr-get-process-children`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 
| ptid | The process table ID. | Required | 
| limit | The maximum number of entries to return. Default is 50. | Optional | 
| offset | The offset number to begin listing entries. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessChildren.childrenCount | Number | Nuber of process children. | 
| Tanium.ProcessChildren.context | String | Process tree context. | 
| Tanium.ProcessChildren.createTime | Date | Time when the process was created. | 
| Tanium.ProcessChildren.createTimeRaw | Date | Timestamp when the process was created. | 
| Tanium.ProcessChildren.dnsEventsCount | Number | Number of DNS events in the process. | 
| Tanium.ProcessChildren.driverEventsCount | Number | Number of Driver events in the process. | 
| Tanium.ProcessChildren.endTime | Date | Process termination time. | 
| Tanium.ProcessChildren.endTimeRaw | Date | Process termination timestamp. | 
| Tanium.ProcessChildren.exitCode | Number | Process exit code. | 
| Tanium.ProcessChildren.fileEventsCount | Number | Number of File events in the process. | 
| Tanium.ProcessChildren.groupName | String | Process group name. | 
| Tanium.ProcessChildren.hashTypeName | String | Hash type. | 
| Tanium.ProcessChildren.id | String | Process id at the tanium system. | 
| Tanium.ProcessChildren.imageEventsCount | Number | Number of Image events in the process. | 
| Tanium.ProcessChildren.networkEventsCount | Number | Number of network events in the process. | 
| Tanium.ProcessChildren.parentProcessTableId | String | Parent process table id. | 
| Tanium.ProcessChildren.pid | Number | The ID of the process. | 
| Tanium.ProcessChildren.processEventsCount | Number | Number of process events in the process. | 
| Tanium.ProcessChildren.processHash | String | Process hash. | 
| Tanium.ProcessChildren.processPath | String | The process path. | 
| Tanium.ProcessChildren.processTableId | String | The ID of the process table. | 
| Tanium.ProcessChildren.registryEventsCount | Number | Number of registry events in the process. | 
| Tanium.ProcessChildren.securityEventsCount | Number | Number of security events in the process. | 
| Tanium.ProcessChildren.uniqueProcessId | String | Unique process id. | 
| Tanium.ProcessChildren.userName | String | The username who created the process. | 


#### Command Example
```!tanium-tr-get-process-children connection_id=remote:hostname:123: ptid=72057594038528485```

#### Context Example
```json
{
    "Tanium": {
        "ProcessChildren": [
            {
                "childrenCount": 0,
                "context": "child",
                "createTime": "2021-07-18 07:26:12.820",
                "createTimeRaw": 1626593172820,
                "dnsEventsCount": 0,
                "driverEventsCount": 0,
                "endTime": "2021-07-18 07:26:13.483",
                "endTimeRaw": 1626593173483,
                "exitCode": 0,
                "fileEventsCount": 0,
                "groupName": "NT AUTHORITY",
                "hashTypeName": "MD5",
                "id": "72057594038528483",
                "imageEventsCount": 0,
                "networkEventsCount": 0,
                "parentProcessTableId": "72057594038528485",
                "pid": 5284,
                "processCommandLine": "\"Logon.exe\" /flags:0x0 /state0:0xa3856855 /state1:0x41c64e6d",
                "processEventsCount": 1,
                "processHash": "b38dfcf985d8ae5b1a17c264981e61c7",
                "processPath": "C:\\Logon1.exe",
                "processTableId": "72057594038528483",
                "registryEventsCount": 39,
                "securityEventsCount": 0,
                "uniqueProcessId": "-5151524022684478300",
                "userName": "SYSTEM"
            },
            {
                "childrenCount": 0,
                "context": "child",
                "createTime": "2021-07-18 07:25:43.456",
                "createTimeRaw": 1626593143456,
                "dnsEventsCount": 0,
                "driverEventsCount": 0,
                "endTime": "2021-07-18 07:26:56.000",
                "endTimeRaw": 1626593216000,
                "fileEventsCount": 0,
                "groupName": "NT AUTHORITY",
                "hashTypeName": "MD5",
                "id": "72057594038528482",
                "imageEventsCount": 0,
                "networkEventsCount": 0,
                "parentProcessTableId": "72057594038528485",
                "pid": 2856,
                "processCommandLine": "C:\\test.exe -secured -Embedding",
                "processEventsCount": 1,
                "processHash": "e1bce838cd2695999ab34215bf94b501",
                "processPath": "C:\\test.exe",
                "processTableId": "72057594038528482",
                "registryEventsCount": 0,
                "securityEventsCount": 0,
                "uniqueProcessId": "-5151647460044567768",
                "userName": "LOCAL SERVICE"
            }
        ]
    }
}
```

#### Human Readable Output

>### Children for process with PTID 72057594038528485
>|Pid|Process Table Id|Parent Process Table Id|
>|---|---|---|
>| 5284 | 72057594038528483 | 72057594038528485 |
>| 2856 | 72057594038528482 | 72057594038528485 |



### tanium-tr-get-parent-process
***
Gets information for the parent process.


#### Base Command

`tanium-tr-get-parent-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 
| ptid | The process table ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessParent.childrenCount | Number | Nuber of process children. | 
| Tanium.ProcessParent.context | String | Process tree context. | 
| Tanium.ProcessParent.createTime | Date | Time when the process was created. | 
| Tanium.ProcessParent.createTimeRaw | Date | Timestamp when the process was created. | 
| Tanium.ProcessParent.dnsEventsCount | Number | Number of DNS events in the process. | 
| Tanium.ProcessParent.driverEventsCount | Number | Number of Driver events in the process. | 
| Tanium.ProcessParent.endTime | Date | Process termination time. | 
| Tanium.ProcessParent.endTimeRaw | Date | Process termination timestamp. | 
| Tanium.ProcessParent.exitCode | Number | Process exit code. | 
| Tanium.ProcessParent.fileEventsCount | Number | Number of File events in the process. | 
| Tanium.ProcessParent.groupName | String | Process group name. | 
| Tanium.ProcessParent.hashTypeName | String | Hash type. | 
| Tanium.ProcessParent.id | String | Process id at the tanium system. | 
| Tanium.ProcessParent.imageEventsCount | Number | Number of Image events in the process. | 
| Tanium.ProcessParent.networkEventsCount | Number | Number of network events in the process. | 
| Tanium.ProcessParent.parentProcessTableId | String | Parent process table id. | 
| Tanium.ProcessParent.pid | Number | The ID of the process. | 
| Tanium.ProcessParent.processEventsCount | Number | Number of process events in the process. | 
| Tanium.ProcessParent.processHash | String | Process hash. | 
| Tanium.ProcessParent.processPath | String | The process path. | 
| Tanium.ProcessParent.processTableId | String | The ID of the process table. | 
| Tanium.ProcessParent.registryEventsCount | Number | Number of registry events in the process. | 
| Tanium.ProcessParent.securityEventsCount | Number | Number of security events in the process. | 
| Tanium.ProcessParent.uniqueProcessId | String | Unique process id. | 
| Tanium.ProcessParent.userName | String | The username who created the process. | 


#### Command Example
```!tanium-tr-get-parent-process connection_id=remote:hostname:123: ptid=72057594038510321```

#### Context Example
```json
{
    "Tanium": {
        "ProcessParent": {
            "childrenCount": 5664,
            "context": "parent",
            "createTime": "2021-07-18 07:26:55.000",
            "createTimeRaw": 1626593215000,
            "dnsEventsCount": 0,
            "driverEventsCount": 0,
            "fileEventsCount": 0,
            "id": "72057594038528485",
            "imageEventsCount": 0,
            "networkEventsCount": 0,
            "parentProcessTableId": "0",
            "pid": -2,
            "processEventsCount": 1,
            "processPath": "<Pruned Process>",
            "processTableId": "72057594038528485",
            "registryEventsCount": 0,
            "securityEventsCount": 0,
            "uniqueProcessId": "-5151340193789247490"
        }
    }
}
```

#### Human Readable Output

>### Parent process for process with PTID 72057594038510321
>|Id|Pid|Process Table Id|Parent Process Table Id|
>|---|---|---|---|
>| 72057594038528485 | -2 | 72057594038528485 | 0 |


### tanium-tr-get-process-tree
***
Gets the process tree for the process instance.


#### Base Command

`tanium-tr-get-process-tree`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The connection id. | Required | 
| ptid | The process instance ID. | Required | 
| context | The process context. Can be `parent`, `node`, `siblings`, `children`. Possible values are: parent, node, siblings, children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ProcessTree.childrenCount | Number | Nuber of process children. | 
| Tanium.ProcessTree.context | String | Process tree context. | 
| Tanium.ProcessTree.createTime | Date | Time when the process was created. | 
| Tanium.ProcessTree.createTimeRaw | Date | Timestamp when the process was created. | 
| Tanium.ProcessTree.dnsEventsCount | Number | Number of DNS events in the process. | 
| Tanium.ProcessTree.driverEventsCount | Number | Number of Driver events in the process. | 
| Tanium.ProcessTree.endTime | Date | Process termination time. | 
| Tanium.ProcessTree.endTimeRaw | Date | Process termination timestamp. | 
| Tanium.ProcessTree.exitCode | Number | Process exit code. | 
| Tanium.ProcessTree.fileEventsCount | Number | Number of File events in the process. | 
| Tanium.ProcessTree.groupName | String | Process group name. | 
| Tanium.ProcessTree.hashTypeName | String | Hash type. | 
| Tanium.ProcessTree.id | String | Process id at the tanium system. | 
| Tanium.ProcessTree.imageEventsCount | Number | Number of Image events in the process. | 
| Tanium.ProcessTree.networkEventsCount | Number | Number of network events in the process. | 
| Tanium.ProcessTree.parentProcessTableId | String | Parent process table id. | 
| Tanium.ProcessTree.pid | Number | The ID of the process. | 
| Tanium.ProcessTree.processEventsCount | Number | Number of process events in the process. | 
| Tanium.ProcessTree.processHash | String | Process hash. | 
| Tanium.ProcessTree.processPath | String | The process path. | 
| Tanium.ProcessTree.processTableId | String | The ID of the process table. | 
| Tanium.ProcessTree.registryEventsCount | Number | Number of registry events in the process. | 
| Tanium.ProcessTree.securityEventsCount | Number | Number of security events in the process. | 
| Tanium.ProcessTree.uniqueProcessId | String | Unique process id. | 
| Tanium.ProcessTree.userName | String | The username who created the process. | 


#### Command Example
```!tanium-tr-get-process-tree connection_id=remote:hostname:123: ptid=72057594038528485```

#### Context Example
```json
{
    "Tanium": {
        "ProcessTree": [
            {
                "childrenCount": 5664,
                "context": "node",
                "createTime": "2021-07-18 07:26:55.000",
                "createTimeRaw": 1626593215000,
                "dnsEventsCount": 0,
                "driverEventsCount": 0,
                "fileEventsCount": 0,
                "id": "72057594038528485",
                "imageEventsCount": 0,
                "networkEventsCount": 0,
                "parentProcessTableId": "0",
                "pid": -2,
                "processEventsCount": 1,
                "processPath": "<Pruned Process>",
                "processTableId": "72057594038528485",
                "registryEventsCount": 0,
                "securityEventsCount": 0,
                "uniqueProcessId": "-5151340193789247490"
            },
            {
                "childrenCount": 0,
                "context": "child",
                "createTime": "2021-07-18 07:26:12.820",
                "createTimeRaw": 1626593172820,
                "dnsEventsCount": 0,
                "driverEventsCount": 0,
                "endTime": "2021-07-18 07:26:13.483",
                "endTimeRaw": 1626593173483,
                "exitCode": 0,
                "fileEventsCount": 0,
                "groupName": "NT AUTHORITY",
                "hashTypeName": "MD5",
                "id": "72057594038528483",
                "imageEventsCount": 0,
                "networkEventsCount": 0,
                "parentProcessTableId": "72057594038528485",
                "pid": 5284,
                "processCommandLine": "\"LogonUI.exe\" /flags:0x0 /state0:0xa3856855 /state1:0x41c64e6d",
                "processEventsCount": 1,
                "processHash": "b38dfcf985d8ae5b1a17c264981e61c7",
                "processPath": "C:\\Windows\\System32\\LogonUI.exe",
                "processTableId": "72057594038528483",
                "registryEventsCount": 39,
                "securityEventsCount": 0,
                "uniqueProcessId": "-5151524022684478300",
                "userName": "SYSTEM"
            }
        ]
    }
}
```

#### Human Readable Output

>### Process information for process with PTID 72057594038528485
>|Id|Pid|Process Table Id|Parent Process Table Id|
>|---|---|---|---|
>| 72057594038528485 | -2 | 72057594038528485 | 0 |
>| 72057594038528483 | 5284 | 72057594038528483 | 72057594038528485 |


### tanium-tr-event-evidence-list
***
Returns a list of all available evidence in the system.


#### Base Command

`tanium-tr-event-evidence-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of evidences to return. Default is 50. | Optional | 
| offset | Offset to start getting the events result set. Default is 0. | Optional | 
| sort | A comma-separated list of fields by which to sort, using +/- prefixes for ascending/descending, in order of priority (left to right). | Optional | 
| hostname | Comma-seperated list of hostnames to get the event evidences that match only those hostnames, for example hostname=123,456. | Optional | 
| type | Get the event evidences that match only to a specific type, for example type=file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Evidence.name | String | The evidence name. | 
| Tanium.Evidence.uuid | String | The evidence UUID. | 
| Tanium.Evidence.createdAt | Date | Time when the process was created. | 
| Tanium.Evidence.hostname | String | The evidence connection hostname. | 
| Tanium.Evidence.evidenceType | Number | The evidence type. | 
| Tanium.Evidence.size | Number | The evidence size. | 


#### Command Example
```!tanium-tr-event-evidence-list limit=3```

#### Context Example
```json
{
    "Tanium": {
        "Evidence": [
            {
                "createdAt": "2021-10-06T06:40:48.297Z",
                "evidenceType": "snapshot",
                "hostname": "host1",
                "name": "host1.db",
                "size": 152064000,
                "username": "administrator",
                "uuid": "832dec40-1cc2-4e53-881a-7f61cba835bc"
            },
            {
                "createdAt": "2021-10-06T06:42:07.010Z",
                "evidenceType": "snapshot",
                "hostname": "host2",
                "name": "host2.db",
                "size": 152064000,
                "username": "administrator",
                "uuid": "340a3ac4-560d-430f-bd50-96615d763171"
            },
            {
                "createdAt": "2021-10-07T12:15:30.711Z",
                "evidenceType": "snapshot",
                "hostname": "host3",
                "name": "host3.db",
                "size": 152064000,
                "username": "administrator",
                "uuid": "cf4d8628-8527-4014-8ed2-bdca6c592488"
            }
        ]
    }
}
```

#### Human Readable Output

>### Evidence list
>|Uuid|Name|Evidence Type|Hostname|Created At|Username|
>|---|---|---|---|---|---|
>| 832dec40-1cc2-4e53-881a-7f61cba835bc | host1.db | snapshot | host1 | 2021-10-06T06:40:48.297Z | administrator |
>| 340a3ac4-560d-430f-bd50-96615d763171 | host2.db | snapshot | host2 | 2021-10-06T06:42:07.010Z | administrator |
>| cf4d8628-8527-4014-8ed2-bdca6c592488 | host3.db | snapshot | host3 | 2021-10-07T12:15:30.711Z | administrator |


### tanium-tr-event-evidence-get-properties
***
Returns event evidence properties for IOC generation.


#### Base Command

`tanium-tr-event-evidence-get-properties`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.EvidenceProperties.type | String | The evidence property type. | 
| Tanium.EvidenceProperties.value | String | The evidence property value. | 


#### Command Example
```!tanium-tr-event-evidence-get-properties```

#### Context Example
```json
{
    "Tanium": {
        "EvidenceProperties": [
            {
                "type": "MD5Hash",
                "value": "92ee791a630830452485e8e375f8db35"
            },
            {
                "type": "MD5Hash",
                "value": "e1bce838cd2695999ab34215bf94b501"
            },
            {
                "type": "MD5Hash",
                "value": "0e1853d3339d2963d2bc6ac1fdc1c811"
            },
            {
                "type": "MD5Hash",
                "value": "41b0ade03cd365a5cc99f748c5ffcadc"
            },
            {
                "type": "MD5Hash",
                "value": "a9a89cb1838373c365f2b8af72b1f1c2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Evidence Properties
>|Type|Value|
>|---|---|
>| MD5Hash | 92ee791a630830452485e8e375f8db35 |
>| MD5Hash | e1bce838cd2695999ab34215bf94b501 |
>| MD5Hash | 0e1853d3339d2963d2bc6ac1fdc1c811 |
>| MD5Hash | 41b0ade03cd365a5cc99f748c5ffcadc |
>| MD5Hash | a9a89cb1838373c365f2b8af72b1f1c2 |


### tanium-tr-get-evidence-by-id
***
Gets event evidence by evidence ID.


#### Base Command

`tanium-tr-get-evidence-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| evidence_id | The ID of the evidence. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Evidence.commandline | String | Process command line. | 
| Tanium.Evidence.createTime | Date | Time when the process was created. | 
| Tanium.Evidence.createTimeRaw | Number | Timestamp when the process was created. | 
| Tanium.Evidence.created | Date | Time when the event was created. | 
| Tanium.Evidence.domain | String | Event domain. | 
| Tanium.Evidence.eventtype | String | The event type. | 
| Tanium.Evidence.evidencetype | String | The evidence type. | 
| Tanium.Evidence.exitCode | Number | Process exit code. | 
| Tanium.Evidence.hostname | String | Connection host name. | 
| Tanium.Evidence.summary | String | Evidence summary. | 
| Tanium.Evidence.timestamp | Date | Eveidence creation date. | 
| Tanium.Evidence.type | String | The evidence type. | 
| Tanium.Evidence.username | String | Evidence creator Username. | 
| Tanium.Evidence.utctimecreated | Date | Evidence creation utc date. | 
| Tanium.Evidence.uuid | String | The evidence UUID. | 


#### Command Example
```!tanium-tr-get-evidence-by-id evidence_id=b684f9be-80ee-483d-8dca-a4d5cd3aeaa6```

#### Context Example
```json
{
    "Tanium": {
        "Evidence": {
            "createTime": "2021-07-07 11:00:01.973",
            "createTimeRaw": 1625655601973,
            "created": "2021-10-05T10:44:36.697Z",
            "endTime": "2021-07-07 11:01:32.006",
            "endTimeRaw": 1625655692006,
            "eventtype": "ProcessEvent",
            "evidencetype": "event",
            "exitCode": 0,
            "groupName": "NT AUTHORITY",
            "hash": "e1bce838cd2695999ab34215bf94b501",
            "hashTypeName": "MD5",
            "hostname": "host1",
            "id": "72057594038506412",
            "parentCommandLine": "<Pruned Process>",
            "parentPath": "<Pruned Process>",
            "parentPid": -2,
            "parentProcessTableId": "72057594038528485",
            "pid": 6056,
            "processPath": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "processTableId": "72057594038506412",
            "recorderid": "72057594038506412",
            "summary": "Test description.",
            "userName": "NETWORK SERVICE",
            "username": "administrator",
            "uuid": "b684f9be-80ee-483d-8dca-a4d5cd3aeaa6"
        }
    }
}
```

#### Human Readable Output

>### Evidence information
>|Uuid|Hostname|Username|Summary|Created|Process Table Id|
>|---|---|---|---|---|---|
>| b684f9be-80ee-483d-8dca-a4d5cd3aeaa6 | host1 | administrator | Test description. | 2021-10-05T10:44:36.697Z | 72057594038506412 |


### tanium-tr-create-evidence
***
Creates an event evidence from process.


#### Base Command

`tanium-tr-create-evidence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The id of the connection. | Required | 
| ptid | The process instance ID. | Required | 
| hostname | The hostname of the connection. | Required | 
| summary | The summary of the event evidence. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-create-evidence ptid=72057594038510321 connection_id=remote:hostname:123: hostname=host1 summary="Create Process"```

#### Human Readable Output

>Evidence have been created.

### tanium-tr-delete-evidence
***
Deletes event evidences from tanium.


#### Base Command

`tanium-tr-delete-evidence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| evidence_ids | The IDs of the evidences to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-delete-evidence evidence_ids=53630ca0-e55a-4f6d-9451-d1c2c277530b```

#### Human Readable Output

>Evidence 53630ca0-e55a-4f6d-9451-d1c2c277530b has been deleted successfully.

### tanium-tr-request-file-download
***
Requests a new file download.


#### Base Command

`tanium-tr-request-file-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path to file. | Required | 
| connection_id | Connection id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.FileDownloadTask.compress | String | Is file compressed. | 
| Tanium.FileDownloadTask.connection | String | The file download host. | 
| Tanium.FileDownloadTask.taskId | Number | ID of the file download task. | 
| Tanium.FileDownloadTask.paths | String | The file download paths. | 
| Tanium.FileDownloadTask.startTime | Date | Download start time. | 
| Tanium.FileDownloadTask.status | String | Status of the file download request. | 


#### Command Example
```!tanium-tr-request-file-download connection_id=remote:hostname:123: path="C:\\Users\\Administrator\\Desktop\\testD.txt"```

#### Context Example
```json
{
    "Tanium": {
        "FileDownloadTask": {
            "compress": "true",
            "connection": "remote:hostname:123:",
            "paths": [
                "C:\\Users\\Administrator\\Desktop\\testD.txt"
            ],
            "startTime": "2021-10-07T12:23:06.824Z",
            "status": "STARTED",
            "taskId": 1178
        }
    }
}
```

#### Human Readable Output

>Download request of file C:\Users\Administrator\Desktop\testD.txt has been sent successfully. Task id: 1178.

### tanium-tr-delete-file-download
***
Deletes a file download.


#### Base Command

`tanium-tr-delete-file-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | File download ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-delete-file-download file_id=0367c8b2-eed9-4124-b173-1c83cbf3ba6f```

#### Human Readable Output

>Delete request of file with ID 0367c8b2-eed9-4124-b173-1c83cbf3ba6f has been sent successfully.

### tanium-tr-list-files-in-directory
***
Gets a list of files in the given directory.


#### Base Command

`tanium-tr-list-files-in-directory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path to the directory. | Required | 
| connection_id | Connection id. | Required | 
| limit | The maximum number of files to return. Default is 50. | Optional | 
| offset | Offset to start getting files. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.connectionId | String | Connection ID. | 
| Tanium.File.createdDate | Date | Time the file was created. | 
| Tanium.File.modifiedDate | Date | The date that the file was last modified. | 
| Tanium.File.name | String | The file name. | 
| Tanium.File.path | String | The file path. | 
| Tanium.File.permissions | Number | The file permissions. | 
| Tanium.File.size | Number | The file size. | 
| Tanium.File.type | String | The file type. | 


#### Command Example
```!tanium-tr-list-files-in-directory connection_id=remote:hostname:123: path=`C:\Users\Administrator\Desktop\` limit=2```

#### Context Example
```json
{
    "Tanium": {
        "File": [
            {
                "connectionId": "remote:hostname:123:",
                "createdDate": "2020-02-06T08:34:17.000Z",
                "modifiedDate": "2018-08-12T11:11:02.000Z",
                "name": "ChromeSetup.exe",
                "path": "C:\\Users\\Administrator\\Desktop\\",
                "permissions": 438,
                "size": 1130840,
                "type": "FILE"
            },
            {
                "connectionId": "remote:hostname:123:",
                "createdDate": "2020-01-07T11:53:20.000Z",
                "modifiedDate": "2020-01-07T11:53:46.000Z",
                "name": "test.txt",
                "path": "C:\\Users\\Administrator\\Desktop\\",
                "permissions": 438,
                "size": 11,
                "type": "FILE"
            }
        ]
    }
}
```

#### Human Readable Output

>### Files in directory `C:\Users\Administrator\Desktop\`
>|Name|Path|Connection Id|Created Date|Modified Date|Permissions|Size|
>|---|---|---|---|---|---|---|
>| ChromeSetup.exe | C:\Users\Administrator\Desktop\ | remote:hostname:123: | 2020-02-06T08:34:17.000Z | 2018-08-12T11:11:02.000Z | 438 | 1130840 |
>| test.txt | C:\Users\Administrator\Desktop\ | remote:hostname:123: | 2020-01-07T11:53:20.000Z | 2020-01-07T11:53:46.000Z | 438 | 11 |


### tanium-tr-get-file-info
***
Gets information about a file from a remote connection.


#### Base Command

`tanium-tr-get-file-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | The ID of the connection. Default is Connection id.. | Required | 
| path | The path to the file. Default is Path to file.. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.File.canonicalPath | String | The file path. | 
| Tanium.File.cid | String | Cid. | 
| Tanium.File.connectionId | String | Connection ID. | 
| Tanium.File.createdDate | Date | Time the file was created. | 
| Tanium.File.modifiedDate | Date | The date that the file was last modified. | 
| Tanium.File.name | String | The file name. | 
| Tanium.File.path | String | The file path. | 
| Tanium.File.permissions | Number | The file permissions. | 
| Tanium.File.size | Number | The file size. | 
| Tanium.File.type | String | The file type. | 
| Tanium.File.sessionId | String | Session ID. | 


#### Command Example
```!tanium-tr-get-file-info connection_id=remote:hostname:123: path="C:\\log1.txt"```

#### Context Example
```json
{
    "Tanium": {
        "File": {
            "canonicalPath": "C:\\log1.txt",
            "cid": "d65ba018-346c-497e-8f18-252036fd87f9",
            "connectionId": "remote:hostname:123:",
            "createdDate": "2019-09-03T17:51:40.000Z",
            "modifiedDate": "2021-09-27T19:36:07.000Z",
            "name": "C:\\log1.txt",
            "path": "C:\\log1.txt",
            "permissions": 438,
            "sessionId": "1ce0f8e7-c180-4467-bf8e-0a313c4eb5f4",
            "size": 2913,
            "type": "FILE"
        }
    }
}
```

#### Human Readable Output

>### Information for file `C:\log1.txt`
>|Path|Name|Connection Id|Type|Created Date|Modified Date|
>|---|---|---|---|---|---|
>| C:\log1.txt | C:\log1.txt | remote:hostname:123: | FILE | 2019-09-03T17:51:40.000Z | 2021-09-27T19:36:07.000Z |


### tanium-tr-delete-file-from-endpoint
***
Deletes a file from the given endpoint.


#### Base Command

`tanium-tr-delete-file-from-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connection_id | Connection ID. | Required | 
| path | Path to file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-delete-file-from-endpoint connection_id=remote:hostname:123: path=`C:\Users\Administrator\Desktop\to_delete.txt````

#### Human Readable Output

>Delete request of file C:\Users\Administrator\Desktop\to_delete.txt from endpoint remote:hostname:123: has been sent successfully.

### tanium-tr-intel-docs-labels-list
***
List all labels for the identified intel document.


#### Base Command

`tanium-tr-intel-docs-labels-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | List the label IDs for the intel document with this ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDocLabel.IntelDocID | String | The requested intel doc ID. | 
| Tanium.IntelDocLabel.LabelsList.ID | Number | The unique identifier for this label. | 
| Tanium.IntelDocLabel.LabelsList.Name | String | The display name of the label. | 
| Tanium.IntelDocLabel.LabelsList.Description | String | An extended description of the label. | 
| Tanium.IntelDocLabel.LabelsList.IndicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.IntelDocLabel.LabelsList.SignalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.IntelDocLabel.LabelsList.CreatedAt | Date | The date this label was created. | 
| Tanium.IntelDocLabel.LabelsList.UpdatedAt | Date | The date this label was last updated, not including the intel and signal counts. | 


#### Command Example
```!tanium-tr-intel-docs-labels-list intel_doc_id=509```

#### Context Example
```json
{
    "Tanium": {
        "IntelDocLabel": {
            "IntelDocID": "509",
            "LabelsList": [
                {
                    "CreatedAt": "2019-07-31T18:46:28.629Z",
                    "Description": "These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed.",
                    "ID": 1,
                    "IndicatorCount": 0,
                    "Name": "Alpha",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.629Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.629Z",
                    "Description": "These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed.",
                    "ID": 2,
                    "IndicatorCount": 0,
                    "Name": "Beta",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.629Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.644Z",
                    "Description": "MITRE ATT&CK matrix category",
                    "ID": 7,
                    "IndicatorCount": 0,
                    "Name": "Defense Evasion",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.644Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.660Z",
                    "Description": "MITRE ATT&CK matrix category",
                    "ID": 11,
                    "IndicatorCount": 0,
                    "Name": "Execution",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.660Z"
                },
                {
                    "CreatedAt": "2020-01-14T21:37:30.528Z",
                    "Description": "These signals are built for Windows hosts.",
                    "ID": 16,
                    "IndicatorCount": 0,
                    "Name": "Windows",
                    "SignalCount": 0,
                    "UpdatedAt": "2020-01-14T21:37:30.528Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Intel doc (509) labels
>|ID|Name|Description|Indicator Count|Signal Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 1 | Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
>| 2 | Beta | These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed. | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
>| 7 | Defense Evasion | MITRE ATT&CK matrix category | 0 | 0 | 2019-07-31T18:46:28.644Z | 2019-07-31T18:46:28.644Z |
>| 11 | Execution | MITRE ATT&CK matrix category | 0 | 0 | 2019-07-31T18:46:28.660Z | 2019-07-31T18:46:28.660Z |
>| 16 | Windows | These signals are built for Windows hosts. | 0 | 0 | 2020-01-14T21:37:30.528Z | 2020-01-14T21:37:30.528Z |


### tanium-tr-intel-docs-add-label
***
Create a new label association for the identified intel document.


#### Base Command

`tanium-tr-intel-docs-add-label`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | Associate the new label with the intel document with this ID. | Required | 
| label_id | The ID of the new label to associate with the target intel document. (Use tanium-tr-intel-docs-labels-list command in order to get the available label IDs). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDocLabel.IntelDocID | String | The requested intel doc ID. | 
| Tanium.IntelDocLabel.LabelsList.ID | Number | The unique identifier for this label. | 
| Tanium.IntelDocLabel.LabelsList.Name | String | The display name of the label. | 
| Tanium.IntelDocLabel.LabelsList.Description | String | An extended description of the label. | 
| Tanium.IntelDocLabel.LabelsList.IndicatorCount | Number | The number of indicator-based intel documents associated with this label, not including Tanium Signals. | 
| Tanium.IntelDocLabel.LabelsList.SignalCount | Number | The number of Tanium Signal documents associated with this label. | 
| Tanium.IntelDocLabel.LabelsList.CreatedAt | Date | The date this label was created. | 
| Tanium.IntelDocLabel.LabelsList.UpdatedAt | Date | The date this label was last updated, not including the intel and signal counts. | 


#### Command Example
```!tanium-tr-intel-docs-add-label intel_doc_id=509 label_id=1```

#### Context Example
```json
{
    "Tanium": {
        "IntelDocLabel": {
            "IntelDocID": "509",
            "LabelsList": [
                {
                    "CreatedAt": "2019-07-31T18:46:28.629Z",
                    "Description": "These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed.",
                    "ID": 1,
                    "IndicatorCount": 0,
                    "Name": "Alpha",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.629Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.629Z",
                    "Description": "These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed.",
                    "ID": 2,
                    "IndicatorCount": 0,
                    "Name": "Beta",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.629Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.644Z",
                    "Description": "MITRE ATT&CK matrix category",
                    "ID": 7,
                    "IndicatorCount": 0,
                    "Name": "Defense Evasion",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.644Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.660Z",
                    "Description": "MITRE ATT&CK matrix category",
                    "ID": 11,
                    "IndicatorCount": 0,
                    "Name": "Execution",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.660Z"
                },
                {
                    "CreatedAt": "2020-01-14T21:37:30.528Z",
                    "Description": "These signals are built for Windows hosts.",
                    "ID": 16,
                    "IndicatorCount": 0,
                    "Name": "Windows",
                    "SignalCount": 0,
                    "UpdatedAt": "2020-01-14T21:37:30.528Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Successfully created a new label (1) association for the identified intel document (509).
>|ID|Name|Description|Indicator Count|Signal Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 1 | Alpha | These signals have been tested and reviewed internally for syntax. Little or no testing of expected alert generation has been conducted. These signals are not included on the external feed. | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
>| 2 | Beta | These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed. | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
>| 7 | Defense Evasion | MITRE ATT&CK matrix category | 0 | 0 | 2019-07-31T18:46:28.644Z | 2019-07-31T18:46:28.644Z |
>| 11 | Execution | MITRE ATT&CK matrix category | 0 | 0 | 2019-07-31T18:46:28.660Z | 2019-07-31T18:46:28.660Z |
>| 16 | Windows | These signals are built for Windows hosts. | 0 | 0 | 2020-01-14T21:37:30.528Z | 2020-01-14T21:37:30.528Z |


### tanium-tr-intel-docs-remove-label
***
Delete a label association for the identified intel document.


#### Base Command

`tanium-tr-intel-docs-remove-label`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | Remove the label from the intel document with this ID. | Required | 
| label_id | The ID of the label to disassociate from the target intel document. (Use tanium-tr-intel-docs-labels-list command in order to get the available label IDs). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDocLabel.IntelDocID | String | Requested doc ID. | 
| Tanium.IntelDocLabel.LabelsList.CreatedAt | Date | Date when label was created. | 
| Tanium.IntelDocLabel.LabelsList.Description | String | Label description. | 
| Tanium.IntelDocLabel.LabelsList.ID | Number | Label ID. | 
| Tanium.IntelDocLabel.LabelsList.IndicatorCount | Number | Number of related indicators. | 
| Tanium.IntelDocLabel.LabelsList.Name | String | Label name. | 
| Tanium.IntelDocLabel.LabelsList.SignalCount | Number | Number of related signal counts. | 
| Tanium.IntelDocLabel.LabelsList.UpdatedAt | Date | Date when label was last updated. | 


#### Command Example
```!tanium-tr-intel-docs-remove-label intel_doc_id=509 label_id=1```

#### Context Example
```json
{
    "Tanium": {
        "IntelDocLabel": {
            "IntelDocID": "509",
            "LabelsList": [
                {
                    "CreatedAt": "2019-07-31T18:46:28.629Z",
                    "Description": "These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed.",
                    "ID": 2,
                    "IndicatorCount": 0,
                    "Name": "Beta",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.629Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.644Z",
                    "Description": "MITRE ATT&CK matrix category",
                    "ID": 7,
                    "IndicatorCount": 0,
                    "Name": "Defense Evasion",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.644Z"
                },
                {
                    "CreatedAt": "2019-07-31T18:46:28.660Z",
                    "Description": "MITRE ATT&CK matrix category",
                    "ID": 11,
                    "IndicatorCount": 0,
                    "Name": "Execution",
                    "SignalCount": 0,
                    "UpdatedAt": "2019-07-31T18:46:28.660Z"
                },
                {
                    "CreatedAt": "2020-01-14T21:37:30.528Z",
                    "Description": "These signals are built for Windows hosts.",
                    "ID": 16,
                    "IndicatorCount": 0,
                    "Name": "Windows",
                    "SignalCount": 0,
                    "UpdatedAt": "2020-01-14T21:37:30.528Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Successfully removed the label (1) association for the identified intel document (509).
>|ID|Name|Description|Indicator Count|Signal Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 2 | Beta | These signals have been tested and reviewed internally for syntax. Internal testing of expected alert generation has been verified. Testing on internal systems for false positives has been conducted and tuned if necessary. These signals are included on the external feed. | 0 | 0 | 2019-07-31T18:46:28.629Z | 2019-07-31T18:46:28.629Z |
>| 7 | Defense Evasion | MITRE ATT&CK matrix category | 0 | 0 | 2019-07-31T18:46:28.644Z | 2019-07-31T18:46:28.644Z |
>| 11 | Execution | MITRE ATT&CK matrix category | 0 | 0 | 2019-07-31T18:46:28.660Z | 2019-07-31T18:46:28.660Z |
>| 16 | Windows | These signals are built for Windows hosts. | 0 | 0 | 2020-01-14T21:37:30.528Z | 2020-01-14T21:37:30.528Z |


### tanium-tr-intel-doc-create
***
Add a new intel document to the system by providing its document contents.


#### Base Command

`tanium-tr-intel-doc-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The file entry ID. | Required | 
| file_extension | The suffix at the end of a filename. (Available file types - yara, stix, ioc). Possible values are: ioc, yara, stix. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. | 
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. | 
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. | 
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. | 
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. | 
| Tanium.IntelDoc.revisionId | Number | The number of times the contents of the intel with this ID have been updated. | 
| Tanium.IntelDoc.Type | String | The shortened type name of the intel. For example, "openioc", "stix", "yara". | 
| Tanium.IntelDoc.typeVersion | String | The version number of the intel type. For example, "1.0", "2.3", etc. | 
| Tanium.IntelDoc.intrinsicId | String | The unique identifier claimed by the intel document, such as a guid or other built-in ID. | 
| Tanium.IntelDoc.Md5 | String | The hex digest of the MD5 sum of the contents of the document that represents this intel. | 
| Tanium.IntelDoc.Size | String | The size of the intel document contents, in bytes. | 


#### Command Example
```!tanium-tr-intel-doc-create entry_id=7173@e99f97d1-7225-4c75-896c-3c960febbe8c file_extension=yara```

#### Context Example
```json
{
    "Tanium": {
        "IntelDoc": {
            "AlertCount": 0,
            "CreatedAt": "2021-07-18T10:27:41.742Z",
            "ID": 438,
            "IntrinsicId": "file.yara",
            "IsSchemaValid": true,
            "Md5": "2bfe1da12a94fa4be3e9bcf6f59d024a",
            "Name": "file.yara",
            "RevisionId": 22,
            "Size": 3271,
            "SourceId": 1,
            "Type": "yara",
            "TypeVersion": "3",
            "UnresolvedAlertCount": 0,
            "UpdatedAt": "2021-10-07T12:23:35.947Z"
        }
    }
}
```

#### Human Readable Output

>### Intel Doc information
>|ID|Name|Type|Alert Count|Unresolved Alert Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 438 | file.yara | yara | 0 | 0 | 2021-07-18T10:27:41.742Z | 2021-10-24T09:00:52.609Z |


### tanium-tr-intel-doc-update
***
Update the contents of an existing intel document by providing the document contents.


#### Base Command

`tanium-tr-intel-doc-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | The ID of the intel document to update. | Required | 
| entry_id | The file entry ID. | Required | 
| file_extension | The suffix at the end of a filename. (Available file types - yara, stix, ioc). Possible values are: ioc, yara, stix. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDoc.AlertCount | Number | The number of alerts that currently exist for this intel. | 
| Tanium.IntelDoc.CreatedAt | Date | The date at which this intel was first added to the system. | 
| Tanium.IntelDoc.Description | String | The description of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.ID | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.IntelDoc.LabelIds | Number | The IDs of all labels applied to this intel. | 
| Tanium.IntelDoc.Name | String | The name of the intel, as declared in the document or as updated by a user. | 
| Tanium.IntelDoc.UnresolvedAlertCount | Number | The number of unresolved alerts that currently exist for this intel. | 
| Tanium.IntelDoc.UpdatedAt | Date | The date when this intel was last updated. | 
| Tanium.IntelDoc.revisionId | Number | The number of times the contents of the intel with this ID have been updated. | 
| Tanium.IntelDoc.Type | String | The shortened type name of the intel. For example, "openioc", "stix", "yara". | 
| Tanium.IntelDoc.typeVersion | String | The version number of the intel type. For example, "1.0", "2.3", etc. | 
| Tanium.IntelDoc.intrinsicId | String | The unique identifier claimed by the intel document, such as a guid or other built-in ID. | 
| Tanium.IntelDoc.Md5 | String | The hex digest of the MD5 sum of the contents of the document that represents this intel. | 
| Tanium.IntelDoc.Size | String | The size of the intel document contents, in bytes. | 


#### Command Example
```!tanium-tr-intel-doc-update entry_id=7173@e99f97d1-7225-4c75-896c-3c960febbe8c intel_doc_id=438 file_extension=yara```

#### Context Example
```json
{
    "Tanium": {
        "IntelDoc": {
            "AlertCount": 0,
            "CreatedAt": "2021-07-18T10:27:41.742Z",
            "ID": 438,
            "IntrinsicId": "file.yara",
            "IsSchemaValid": true,
            "Md5": "2bfe1da12a94fa4be3e9bcf6f59d024a",
            "Name": "file.yara",
            "RevisionId": 23,
            "Size": 3271,
            "SourceId": 1,
            "Type": "yara",
            "TypeVersion": "3",
            "UnresolvedAlertCount": 0,
            "UpdatedAt": "2021-10-07T12:23:39.573Z"
        }
    }
}
```

#### Human Readable Output

>### Intel Doc information
>|ID|Name|Type|Alert Count|Unresolved Alert Count|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 438 | file.yara | yara | 0 | 0 | 2021-07-18T10:27:41.742Z | 2021-10-07T12:23:39.573Z |


### tanium-tr-intel-doc-delete
***
Remove an intel document from the system by providing its ID


#### Base Command

`tanium-tr-intel-doc-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | The file entry ID. | Required | 


#### Context Output
None


#### Command Example
```!tanium-tr-intel-doc-delete intel_doc_id=509```

#### Context Example
None

#### Human Readable Output

>### Intel Doc deleted


### tanium-tr-start-quick-scan
***
Scan a computer group for hashes in intel document. Computer groups
      can be viewed by navigating to `Administration -> Computer Groups` in the Threat-Response
      product console. Computer group names and IDs can also be retrieved by using
      the `tn-list-groups` command in the `Tanium` integration.


#### Base Command

`tanium-tr-start-quick-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_doc_id | The intel document ID. | Required | 
| computer_group_name | The name of a Tanium computer group. See command description for possible ways to retrieve this value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.QuickScan.IntelDocId | Number | The unique identifier for this intel in this instance of the system. | 
| Tanium.QuickScan.ComputerGroupId | Number | The ID of a Tanium computer group. | 
| Tanium.QuickScan.ID | Number | The ID of the quick scan. | 
| Tanium.QuickScan.AlertCount | Number | The number of alerts returned from the quick scan. | 
| Tanium.QuickScan.CreatedAt | Date | The date the quick scan was created. | 
| Tanium.QuickScan.UserId | Number | The user ID which initiated the quick scan. | 
| Tanium.QuickScan.QuestionId | Number | The ID of the quick scan question. | 

#### Command Example
```!tanium-tr-start-quick-scan intel_doc_id=509 computer_group_name="All Computers"```

#### Context Example
```json
{
    "Tanium": {
        "QuickScan": {
            "AlertCount": 0,
            "ComputerGroupId": 1,
            "CreatedAt": "2022-01-05T19:53:43.049Z",
            "ID": 1000239,
            "IntelDocId": 509,
            "QuestionId": 2025697,
            "UserId": 64
        }
    }
}
```

#### Human Readable Output

>### Quick Scan started
>|AlertCount|ComputerGroupId|CreatedAt|ID|IntelDocId|QuestionId|UserId|
>|---|---|---|---|---|---|---|
>| 0 | 1 | 2022-01-05T19:53:43.049Z | 1000239 | 509 | 2025697 | 64 |


### tanium-tr-intel-deploy
***
Deploys intel using the service account context.


#### Base Command

`tanium-tr-intel-deploy`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!tanium-tr-intel-deploy```

#### Human Readable Output

>Successfully deployed intel.

### tanium-tr-intel-deploy-status
***
Displays status of last intel deployment.


#### Base Command

`tanium-tr-intel-deploy-status`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.IntelDeployStatus.CreatedAt | Date | The creation date of the last intel deployment. | 
| Tanium.IntelDeployStatus.ModifiedAt | Date | The modification date of the last intel deployment. | 
| Tanium.IntelDeployStatus.CurrentRevision | Number | Revision number, incremented each time the intel is modified | 
| Tanium.IntelDeployStatus.CurrentSize | Number | The size of the intel document contents, in bytes. | 


#### Command Example
```!tanium-tr-intel-deploy-status```

#### Context Example
```json
{
    "Tanium": {
        "IntelDeployStatus": {
            "CreatedAt": "2021-05-02T19:18:00.685Z",
            "CurrentRevision": 855,
            "CurrentSize": 1187840,
            "ModifiedAt": "2021-10-06T15:07:43.248Z"
        }
    }
}
```

#### Human Readable Output

>### Intel deploy status
>|Created At|Modified At|Current Revision|Current Size|
>|---|---|---|---|
>| 2021-05-02T19:18:00.685Z | 2021-10-06T15:07:43.248Z | 855 | 1187840 |


### tanium-tr-get-task-by-id
***
Get task by ID.


#### Base Command

`tanium-tr-get-task-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The task ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Task.createdAt | Date | The date at which this task was first added to the system. | 
| Tanium.Task.id | Number | The unique identifier for this task in this instance of the system. | 
| Tanium.Task.updatedAt | Date | The date when this task was last updated. | 
| Tanium.Task.startTime | Date | The date when this task started. | 
| Tanium.Task.endTime | Date | The date when this task ended. | 
| Tanium.Task.error | String | Task errors. | 
| Tanium.Task.status | String | Task status. | 
| Tanium.Task.type | String | Task type. | 
| Tanium.Task.metadata | Unknown | Task metadata. | 
| Tanium.Task.results | Unknown | Task results. | 


#### Command Example
```!tanium-tr-get-task-by-id task_id=833```

#### Context Example
```json
{
    "Tanium": {
        "Task": {
            "createdAt": "2021-09-05T13:46:16.603Z",
            "endTime": "2021-09-05T13:46:16.900Z",
            "id": 833,
            "metadata": {
                "compress": "true",
                "connection": "remote:hostname:123:",
                "paths": [
                    "C:\\test.exe"
                ]
            },
            "results": {
                "completed": [
                    "C:\\test.exe"
                ],
                "failed": [],
                "fileResults": [
                    {
                        "finalPath": "C:\\04828d87-a384-4a8b-a874-2438bf8b16ab.zip",
                        "response": {
                            "avgBytesPerSecond": 0,
                            "source": "C:\\test.exe",
                            "target": "C:\\temp\\36e80439-8866-4ada-9229-fb1e08f1a3f9",
                            "totalBytes": 55808,
                            "totalTimeMs": 205,
                            "transferHash": "a84417ee9d039891af43b267896db921a40838d8a17cc1be29785d031e5944d4"
                        }
                    }
                ]
            },
            "startTime": "2021-09-05T13:46:16.606Z",
            "status": "COMPLETED",
            "type": "fileDownload",
            "updatedAt": "2021-09-05T13:46:16.603Z"
        }
    }
}
```

#### Human Readable Output

>### Task information
>|Id|Status|
>|---|---|
>| 833 | COMPLETED |


### tanium-tr-get-system-status
***
Get system status, to retrieve all possible connection's client ids, hostnames, ips.


#### Base Command

`tanium-tr-get-system-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of entries to return. Default is 50. | Optional | 
| offset | The offset number to begin listing entries. Default is 0. | Optional | 
| status | Comma-seperated list of statuses to get the system-status that match only those statuses, for example status=Blocked,Leader. | Optional | 
| ip_server | Comma-seperated list of ip servers to get the system-status that match only those ip servers, for example ip_server=1.1.1.1,2.2.2.2. | Optional | 
| ip_client | Comma-seperated list of ip clients to get the system-status that match only those ip clients, for example ip_client=1.1.1.1,2.2.2.2. | Optional | 
| hostname | Comma-seperated list of hostnames to get the system-status that match only those hostnames, for example hostname=host1,host2. | Optional | 
| port | port to get the system-status that match only this port, for example port=80. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.SystemStatus.clientId | Number | Client id to use when creating new connection. | 
| Tanium.SystemStatus.computerId | Number | Computer ID. | 
| Tanium.SystemStatus.hostName | String | Hostname to connect. | 
| Tanium.SystemStatus.ipaddressClient | String | Client IP address. | 
| Tanium.SystemStatus.ipaddressServer | String | Server IP address. | 
| Tanium.SystemStatus.lastRegistration | Date | Host last registration time. | 
| Tanium.SystemStatus.portNumber | Number | Connection port number. | 
| Tanium.SystemStatus.protocolVersion | Number | Connection protocol version. | 
| Tanium.SystemStatus.publicKeyValid | Boolean | Is public key valid. | 
| Tanium.SystemStatus.status | String | Host status. | 


#### Command Example
```!tanium-tr-get-system-status```

#### Context Example
```json
{
    "Tanium": {
        "SystemStatus": [
            {
                "clientId": 11111,
                "computerId": 11111,
                "fullVersion": "7.2.314.3476",
                "hostName": "tanium",
                "ipaddressClient": "1.1.1.1",
                "ipaddressServer": "1.1.1.1",
                "lastRegistration": "2021-10-07T12:23:13Z",
                "portNumber": 17472,
                "protocolVersion": 314,
                "publicKeyValid": true,
                "receiveState": "None",
                "registeredWithTls": false,
                "sendState": "None",
                "status": "Leader"
            },
            {
                "clientId": 22222,
                "computerId": 22222,
                "fullVersion": "7.4.5.1204",
                "hostName": "hostname1",
                "ipaddressClient": "1.2.3.4",
                "ipaddressServer": "1.2.3.4",
                "lastRegistration": "2021-10-07T12:23:12Z",
                "portNumber": 17472,
                "protocolVersion": 315,
                "publicKeyValid": true,
                "receiveState": "None",
                "registeredWithTls": true,
                "sendState": "None",
                "status": "Leader"
            }
        ]
    }
}
```

#### Human Readable Output

>### Reporting clients
>|Host Name|Client Id|Ipaddress Client|Ipaddress Server|Port Number|
>|---|---|---|---|---|
>| taniumlinux | 11111 | 1.1.1.1 | 1.1.1.1 | 17472 |
>| hostname1 | 222222 | 1.2.3.4 | 1.2.3.4 | 17472 |

### tanium-tr-get-response-actions

***
Returns the Response Actions matching the specified filters

#### Base Command

`tanium-tr-get-response-actions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Offset to start getting response actions (default is '0'). | Optional | 
| limit | Max number of response actions to return (default is '50'). | Optional | 
| sort_order | Specify whether to sort by column in ascending or descending order (default is 'desc'). Possible values are: asc, desc. Default is desc. | Optional | 
| partial_computer_name | Filter on a partial computer name. | Optional | 
| status | Filter on status. | Optional | 
| type | Filter on type. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ResponseActions.id | String |  | 
| Tanium.ResponseActions.type | String |  | 
| Tanium.ResponseActions.status | String |  | 
| Tanium.ResponseActions.computerName | String |  | 
| Tanium.ResponseActions.userId | String |  | 
| Tanium.ResponseActions.userName | String |  | 
| Tanium.ResponseActions.results.taskIds | String |  | 
| Tanium.ResponseActions.results.actionIds | String |  | 
| Tanium.ResponseActions.results.snapshotName | String |  | 
| Tanium.ResponseActions.results.uuid | String |  | 
| Tanium.ResponseActions.expirationTime | Date |  | 
| Tanium.ResponseActions.createdAt | Date |  | 
| Tanium.ResponseActions.updatedAt | Date |  | 
| Tanium.ResponseActions.eid | String |  | 

### tanium-tr-response-action-gather-snapshot

***
Creates a "gatherSnapshot" Response Action for the specified host

#### Base Command

`tanium-tr-response-action-gather-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_name | Target computer name. | Required | 
| expiration_time | Time unit to specify how long a snapshot should persist (i.e. "7 days", "1 month". Default is "7 days"). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.ResponseActions.type | String |  | 
| Tanium.ResponseActions.computerName | String |  | 
| Tanium.ResponseActions.options | String |  | 
| Tanium.ResponseActions.status | String |  | 
| Tanium.ResponseActions.userId | String |  | 
| Tanium.ResponseActions.userName | String |  | 
| Tanium.ResponseActions.results | String |  | 
| Tanium.ResponseActions.expirationTime | Date |  | 
| Tanium.ResponseActions.createdAt | Date |  | 
| Tanium.ResponseActions.updatedAt | Date |  | 
| Tanium.ResponseActions.id | String |  | 
| Tanium.ResponseActions.eid | String |  | 

## Breaking changes from the previous version of this integration - Tanium Threat Response v2
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *tanium-tr-list-snapshots-by-connection*
* *tanium-tr-list-local-snapshots-by-connection*
* *tanium-tr-get-connection-by-name*
* *tanium-tr-get-parent-process-tree*
* *tanium-tr-list-evidence*
* *tanium-tr-get-process-timeline*
* *tanium-tr-get-download-file-request-status* - this command was replaced by *tanium-tr-get-task-by-id*.

### Arguments
#### The following arguments were removed in this version:

In the *tanium-tr-get-intel-doc-by-id* command:
* *intel-doc-id* - this argument was replaced by *intel_doc_id*.

In the *tanium-tr-list-alerts* command:
* *computer-ip-address* - this argument was replaced by *computer_ip_address*.
* *computer-name* - this argument was replaced by *computer_name*.
* *scan-config-id* - this argument was replaced by *scan_config_id*.
* *intel-doc-id* - this argument was replaced by *intel_doc_id*.

In the *tanium-tr-get-alert-by-id* command:
* *alert-id* - this argument was replaced by *alert_id*.

In the *tanium-tr-alert-update-state* command:
* *alert-id* - this argument was replaced by *alert_ids*.

In the *tanium-tr-create-snapshot* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-delete-snapshot* command:
* *connection-name* - this argument was replaced by *connection_id*.
* *snapshot-id* - this argument was replaced by *snapshot_ids*.

In the *tanium-tr-delete-local-snapshot* command:
* *connection-name* - this argument was replaced by *connection_id*.
* *file-name* - this argument was removed.

In the *tanium-tr-create-connection* command:
* *remote* - this argument was removed.
* *destination-type* - this argument was removed.
* *destination* - this argument was removed.
* *connection-timeout* - this argument was removed.
* This command receiving new arguments: *client_id*, *ip*, *platform*, *hostname*.

In the *tanium-tr-delete-connection* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-label-by-id* command:
* *label-id* - this argument was replaced by *label_id*.

In the *tanium-tr-list-file-downloads* command:
* *host* - this argument was removed.

In the *tanium-tr-get-downloaded-file* command:
* *file-id* - this argument was replaced by *file_id*.

In the *tanium-tr-list-events-by-connection* command:
* *connection-name* - this argument was replaced by *connection_id*.
* *event-type* - this argument was replaced by *type*.

In the *tanium-tr-get-file-download-info* command:
* *host* - this argument was removed.
* *path* - this argument was removed.
* *id* - this argument was replaced by *file_id*.

In the *tanium-tr-get-process-info* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-events-by-process* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-process-children* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-parent-process* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-process-tree* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-evidence-by-id* command:
* *evidence-id* - this argument was replaced by *evidence_id*.

In the *tanium-tr-create-evidence* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-delete-evidence* command:
* *evidence-id* - this argument was replaced by *evidence_ids*.

In the *tanium-tr-request-file-download* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-delete-file-download* command:
* *file-id* - this argument was replaced by *file_id*.

In the *tanium-tr-list-files-in-directory* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-get-file-info* command:
* *connection-name* - this argument was replaced by *connection_id*.

In the *tanium-tr-delete-file-from-endpoint* command:
* *connection-name* - this argument was replaced by *connection_id*.

#### The behavior of the following arguments was changed:

In the *tanium-tr-list-intel-docs* command:
* *limit* - The default value changed to '50'.

### Outputs
#### The following outputs were removed in this version:

In the *tanium-tr-list-connections* command:
* *Tanium.Connection.CreateTime* - this output was removed.
* *Tanium.Connection.Name* - this output was replaced by *Tanium.Connection.hostname*.
* *Tanium.Connection.Remote* - this output was removed.
* *Tanium.Connection.State* - this output was replaced by *Tanium.Connection.status*.
* *Tanium.Connection.Deleted* - this output was removed.
* *Tanium.Connection.DestionationType* - this output was removed.
* *Tanium.Connection.DST* - this output was removed.
* *Tanium.Connection.OSName* - this output was replaced by *Tanium.Connection.platform*.

In the *tanium-tr-list-labels* command:
* *Tanium.Label.CreatedAt* - this output was replaced by *Tanium.Label.createdAt*.
* *Tanium.Label.Description* - this output was replaced by *Tanium.Label.description*.
* *Tanium.Label.ID* - this output was replaced by *Tanium.Label.id*.
* *Tanium.Label.IndicatorCount* - this output was replaced by *Tanium.Label.indicatorCount*.
* *Tanium.Label.Name* - this output was replaced by *Tanium.Label.name*.
* *Tanium.Label.SignalCount* - this output was replaced by *Tanium.Label.signalCount*.
* *Tanium.Label.UpdatedAt* - this output was replaced by *Tanium.Label.updatedAt*.

In the *tanium-tr-get-label-by-id* command:
* *Tanium.Label.CreatedAt* - this output was replaced by *Tanium.Label.createdAt*.
* *Tanium.Label.Description* - this output was replaced by *Tanium.Label.description*.
* *Tanium.Label.ID* - this output was replaced by *Tanium.Label.id*.
* *Tanium.Label.IndicatorCount* - this output was replaced by *Tanium.Label.indicatorCount*.
* *Tanium.Label.Name* - this output was replaced by *Tanium.Label.name*.
* *Tanium.Label.SignalCount* - this output was replaced by *Tanium.Label.signalCount*.
* *Tanium.Label.UpdatedAt* - this output was replaced by *Tanium.Label.updatedAt*.

In the *tanium-tr-list-file-downloads* command:
* *Tanium.FileDownload.Size* - this output was replaced by *Tanium.FileDownload.size*.
* *Tanium.FileDownload.Path* - this output was replaced by *Tanium.FileDownload.path*.
* *Tanium.FileDownload.Downloaded* - this output was replaced by *Tanium.FileDownload.downloaded*.
* *Tanium.FileDownload.Host* - this output was replaced by *Tanium.FileDownload.hostname*.
* *Tanium.FileDownload.Created* - this output was replaced by *Tanium.FileDownload.processCreationTime*.
* *Tanium.FileDownload.Hash* - this output was replaced by *Tanium.FileDownload.hash*.
* *Tanium.FileDownload.SPath* - this output was removed.
* *Tanium.FileDownload.ID* - this output was replaced by *Tanium.FileDownload.uuid*.
* *Tanium.FileDownload.LastModified* - this output was replaced by *Tanium.FileDownload.lastModified*.
* *Tanium.FileDownload.CreatedBy* - this output was replaced by *Tanium.FileDownload.createdBy*.
* *Tanium.FileDownload.CreatedByProc* - this output was replaced by *Tanium.FileDownload.createdByProc*.
* *Tanium.FileDownload.LastModifiedBy* - this output was replaced by *Tanium.FileDownload.lastModifiedBy*.
* *Tanium.FileDownload.LastModifiedByProc* - this output was replaced by *Tanium.FileDownload.lastModifiedByProc*.
* *Tanium.FileDownload.Comments* - this output was removed.
* *Tanium.FileDownload.Tags* - this output was removed.
* *Tanium.FileDownload.Deleted* - this output was removed.

In the *tanium-tr-list-events-by-connection* command:
* *TaniumEvent.Domain* - this output was removed.
* *TaniumEvent.File* - this output was replaced by *TaniumEvent.file*.
* *TaniumEvent.Operation* - this output was replaced by *TaniumEvent.operation*.
* *TaniumEvent.ProcessID* - this output was replaced by *TaniumEvent.pid*.
* *TaniumEvent.ProcessName* - this output was removed.
* *TaniumEvent.ProcessTableID* - this output was replaced by *TaniumEvent.processTableId*.
* *TaniumEvent.Timestamp* - this output was removed.
* *TaniumEvent.Username* - this output was replaced by *TaniumEvent.userName*.
* *TaniumEvent.DestinationAddress* - this output was replaced by *TaniumEvent.remoteAddress*.
* *TaniumEvent.DestinationPort* - this output was replaced by *TaniumEvent.remoteAddressPort*.
* *TaniumEvent.SourceAddress* - this output was replaced by *TaniumEvent.localAddress*.
* *TaniumEvent.SourcePort* - this output was replaced by *TaniumEvent.localAddressPort*.
* *TaniumEvent.KeyPath* - this output was replaced by *TaniumEvent.keyPath*.
* *TaniumEvent.ValueName* - this output was replaced by *TaniumEvent.valueName*.
* *TaniumEvent.ExitCode* - this output was replaced by *TaniumEvent.exitCode*.
* *TaniumEvent.ProcessCommandLine* - this output was replaced by *TaniumEvent.processCommandLine*.
* *TaniumEvent.ProcessHash* - this output was removed.
* *TaniumEvent.SID* - this output was removed.
* *TaniumEvent.Hashes* - this output was replaced by *TaniumEvent.hashes*.
* *TaniumEvent.ImageLoaded* - this output was replaced by *TaniumEvent.imageLoaded*.
* *TaniumEvent.Signature* - this output was replaced by *TaniumEvent.signature*.
* *TaniumEvent.Signed* - this output was replaced by *TaniumEvent.signed*.
* *TaniumEvent.EventID* - this output was replaced by *TaniumEvent.eventId*.
* *TaniumEvent.EventOpcode* - this output was replaced by *TaniumEvent.eventOpcode*.
* *TaniumEvent.EventRecordID* - this output was replaced by *TaniumEvent.eventRecordId*.
* *TaniumEvent.EventTaskID* - this output was replaced by *TaniumEvent.eventTaskId*.
* *TaniumEvent.Query* - this output was replaced by *TaniumEvent.query*.
* *TaniumEvent.Response* - this output was replaced by *TaniumEvent.response*.
* *TaniumEvent.ImagePath* - this output was replaced by *TaniumEvent.imagePath*.
* *TaniumEvent.CreationTime* - this output was replaced by *TaniumEvent.createTime*.
* *TaniumEvent.EndTime* - this output was replaced by *TaniumEvent.endTime*.
* *TaniumEvent.EventTaskName* - this output was replaced by *TaniumEvent.eventTaskName*.
* *TaniumEvent.Property.Name* - this output was removed.
* *TaniumEvent.Property.Value* - this output was removed.

In the *tanium-tr-get-file-download-info* command:
* *Tanium.FileDownload.Size* - this output was replaced by *Tanium.FileDownload.size*.
* *Tanium.FileDownload.Path* - this output was replaced by *Tanium.FileDownload.path*.
* *Tanium.FileDownload.Downloaded* - this output was replaced by *Tanium.FileDownload.downloaded*.
* *Tanium.FileDownload.Host* - this output was replaced by *Tanium.FileDownload.hostname*.
* *Tanium.FileDownload.Created* - this output was replaced by *Tanium.FileDownload.processCreationTime*.
* *Tanium.FileDownload.Hash* - this output was replaced by *Tanium.FileDownload.hash*.
* *Tanium.FileDownload.SPath* - this output was removed.
* *Tanium.FileDownload.ID* - this output was replaced by *Tanium.FileDownload.uuid*.
* *Tanium.FileDownload.LastModified* - this output was replaced by *Tanium.FileDownload.lastModified*.
* *Tanium.FileDownload.CreatedBy* - this output was replaced by *Tanium.FileDownload.createdBy*.
* *Tanium.FileDownload.CreatedByProc* - this output was replaced by *Tanium.FileDownload.createdByProc*.
* *Tanium.FileDownload.LastModifiedBy* - this output was replaced by *Tanium.FileDownload.lastModifiedBy*.
* *Tanium.FileDownload.LastModifiedByProc* - this output was replaced by *Tanium.FileDownload.lastModifiedByProc*.
* *Tanium.FileDownload.Comments* - this output was removed.
* *Tanium.FileDownload.Tags* - this output was removed.
* *Tanium.FileDownload.Deleted* - this output was removed.

In the *tanium-tr-get-process-info* command:
* *Tanium.Process.CreateTime* - this output was replaced by *Tanium.ProcessInfo.createTime*.
* *Tanium.Process.Domain* - this output was removed.
* *Tanium.Process.ExitCode* - this output was replaced by *Tanium.ProcessInfo.exitCode*.
* *Tanium.Process.ProcessCommandLine* - this output was removed.
* *Tanium.Process.ProcessID* - this output was replaced by *Tanium.ProcessInfo.pid*.
* *Tanium.Process.ProcessName* - this output was removed.
* *Tanium.Process.ProcessTableId* - this output was replaced by *Tanium.ProcessInfo.processTableId*.
* *Tanium.Process.SID* - this output was removed
* *Tanium.Process.Username* - this output was replaced by *Tanium.ProcessInfo.userName*.

In the *tanium-tr-get-events-by-process* command:
* *Tanium.ProcessEvent.ID* - this output was replaced by *Tanium.ProcessEvent.id*.
* *Tanium.ProcessEvent.Detail* - this output was replaced by *Tanium.ProcessEvent.detail*.
* *Tanium.ProcessEvent.Operation* - this output was replaced by *Tanium.ProcessEvent.operation*.
* *Tanium.ProcessEvent.Timestamp* - this output was replaced by *Tanium.ProcessEvent.timestamp*.
* *Tanium.ProcessEvent.Type* - this output was replaced by *Tanium.ProcessEvent.type*.

In the *tanium-tr-get-process-children* command:
* *Tanium.ProcessChildren.ID* - this output was replaced by *Tanium.ProcessChildren.id*.
* *Tanium.ProcessChildren.Name* - this output was removed.
* *Tanium.ProcessChildren.PID* - this output was replaced by *Tanium.ProcessChildren.pid*.
* *Tanium.ProcessChildren.PTID* - this output was replaced by *Tanium.ProcessChildren.parentProcessTableId*.
* *Tanium.ProcessChildren.Parent* - this output was removed.

In the *tanium-tr-get-parent-process* command:
* *Tanium.Process.CreateTime* - this output was replaced by *Tanium.ProcessParent.createTime*.
* *Tanium.Process.Domain* - this output was removed.
* *Tanium.Process.ExitCode* - this output was replaced by *Tanium.ProcessParent.exitCode*.
* *Tanium.Process.ProcessCommandLine* - this output was removed.
* *Tanium.Process.ProcessID* - this output was replaced by *Tanium.ProcessParent.pid*.
* *Tanium.Process.ProcessName* - this output was removed.
* *Tanium.Process.ProcessTableId* - this output was replaced by *Tanium.ProcessParent.processTableId*.
* *Tanium.Process.SID* - this output was removed.
* *Tanium.Process.Username* - this output was replaced by *Tanium.ProcessParent.userName*.

In the *tanium-tr-get-process-tree* command:
* *Tanium.ProcessTree.ID* - this output was replaced by *Tanium.ProcessTree.id*.
* *Tanium.ProcessTree.Name* - this output was removed.
* *Tanium.ProcessTree.PID* - this output was replaced by *Tanium.ProcessTree.pid*.
* *Tanium.ProcessTree.PTID* - this output was replaced by *Tanium.ProcessTree.parentProcessTableId*.
* *Tanium.ProcessTree.Parent* - this output was removed.
* *Tanium.ProcessTree.Children* - this output was replaced by *Tanium.ProcessTree.childrenCount*.

In the *tanium-tr-get-evidence-by-id* command:
* *Tanium.Evidence.ID* - this output was replaced by *Tanium.Evidence.uuid*.
* *Tanium.Evidence.CreatedAt* - this output was replaced by *Tanium.Evidence.createTime*.
* *Tanium.Evidence.LastModified* - this output was removed.
* *Tanium.Evidence.User* - this output was replaced by *Tanium.Evidence.username*.
* *Tanium.Evidence.ConnectionName* - this output was replaced by *Tanium.Evidence.hostname*.
* *Tanium.Evidence.Type* - this output was replaced by *Tanium.Evidence.type*.
* *Tanium.Evidence.ProcessTableId* - this output was removed.
* *Tanium.Evidence.Timestamp* - this output was replaced by *Tanium.Evidence.timestamp*.
* *Tanium.Evidence.Summary* - this output was replaced by *Tanium.Evidence.summary*.
* *Tanium.Evidence.Comments* - this output was removed.
* *Tanium.Evidence.Tags* - this output was removed.
* *Tanium.Evidence.Deleted* - this output was removed.

In the *tanium-tr-request-file-download* command:
* *Tanium.FileDownload.Path* - this output was replaced by *Tanium.FileDownloadTask.paths*.
* *Tanium.FileDownload.ConnectionName* - this output was replaced by *Tanium.FileDownloadTask.connection*.
* *Tanium.FileDownload.Downloaded* - this output was removed.
* *Tanium.FileDownload.Status* - this output was replaced by *Tanium.FileDownloadTask.status*.
* *Tanium.FileDownload.ID* - this output was replaced by *Tanium.FileDownloadTask.taskId*.

In the *tanium-tr-list-files-in-directory* command:
* *Tanium.File.Created* - this output was replaced by *Tanium.File.createdDate*.
* *Tanium.File.Size* - this output was replaced by *Tanium.File.size*.
* *Tanium.File.IsDirectory* - this output was replaced by *Tanium.File.type*.
* *Tanium.File.LastModified* - this output was replaced by *Tanium.File.modifiedDate*.
* *Tanium.File.Path* - this output was replaced by *Tanium.File.path*.
* *Tanium.File.Permissions* - this output was replaced by *Tanium.File.permissions*.
* *Tanium.File.ConnectionName* - this output was replaced by *Tanium.File.connectionId*.
* *Tanium.File.Deleted* - this output was removed.

In the *tanium-tr-get-file-info* command:
* *Tanium.File.Created* - this output was replaced by *Tanium.File.createdDate*.
* *Tanium.File.Size* - this output was replaced by *Tanium.File.size*.
* *Tanium.File.IsDirectory* - this output was replaced by *Tanium.File.type*.
* *Tanium.File.LastModified* - this output was replaced by *Tanium.File.modifiedDate*.
* *Tanium.File.Path* - this output was replaced by *Tanium.File.path*.
* *Tanium.File.ConnectionName* - this output was replaced by *Tanium.File.connectionId*.
* *Tanium.File.Deleted* - this output was removed.