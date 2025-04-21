Symantec Data Loss Prevention enables you to discover, monitor and protect your sensitive corporate information.
This integration was integrated and tested with Symantec Data Loss Prevention version 15.7 RESTful API. 

[Check Symantec DLP 15.7 API docs](https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/information-security/data-loss-prevention/generated-pdfs/Symantec_DLP_15.7_REST_API_Guide.pdf)

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-symantec-data-loss-prevention-v2).

## Configure Symantec Data Loss Prevention v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Enforce Server (e.g. https://192.168.0.1) |  | True |
| Username |  | True |
| Password |  | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Fetch limit | Max fetch limit is 50 | False |
| Fetch incidents from type | If not selected, fetches all incident types. | False |
| Incident Status ID | The status ID of the incidents. To get the status IDs, run the \`symantec-dlp-list-incident-status\` command. | False |
| Incident Severity | If not selected, fetches high and medium incidents. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |


## Fetch Incidents
The integration fetches incidents in the order they were created. 
Note that incident IDs may not be fetched in order, due to creation time differences.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### symantec-dlp-list-incidents
***
Returns a list of incidents.


#### Base Command

`symantec-dlp-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| creation_date | The earliest time from which to get incidents. Supports ISO (e.g 2021-12-28T00:00:00Z) and free text (e.g. '2 days'). | Optional | 
| status_id | The status ID of the incidents. To get status IDs, run the `symantec-dlp-list-incident-status` command. | Optional | 
| severity | The severity of the incidents. Possible values are: Info, Low, Medium, High. | Optional | 
| incident_type | The incident type. Possible values are: Network, Discover, Endpoint. | Optional | 
| limit | The limit for number of incidents listed per page. Default is 50. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is 1. | Optional | 
| page_size | The number of results per page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.Incident.ID | Number | The ID of the Incident. | 
| SymantecDLP.Incident.messageType | String | Indicates the Symantec DLP product component that generated the incident. | 
| SymantecDLP.Incident.messageSource | String | The localized label that corresponds to the Symantec DLP product that generated the incident. | 
| SymantecDLP.Incident.detectionServerId | Number | The ID of the detection server that created the incident. | 
| SymantecDLP.Incident.policyVersion | Number | The version of the policy. | 
| SymantecDLP.Incident.matchCount | Number | Indicates the number of detection rule matches in the incident. | 
| SymantecDLP.Incident.policyId | Number | The ID of the policy. | 
| SymantecDLP.Incident.creationDate | Date | The creation date of the incident. | 
| SymantecDLP.Incident.detectionDate | Date | The detection date of the incident. | 
| SymantecDLP.Incident.severity | String | The severity of the incident. | 
| SymantecDLP.Incident.messageTypeId | Number | The ID of the message type. | 
| SymantecDLP.Incident.incidentStatusId | Number | The status ID of the incident. | 

#### Command example
```!symantec-dlp-list-incidents limit=2 severity=High incident_type=Network creation_date="4 days"```
#### Context Example
```json
{
    "SymantecDLP": {
        "Incident": [
            {
                "ID": 4044,
                "creationDate": "2022-03-27T03:23:52.315",
                "detectionDate": "2022-03-27T03:23:44.773",
                "detectionServerId": 1,
                "incidentStatusId": 1,
                "matchCount": 3,
                "messageSource": "NETWORK",
                "messageType": "HTTP",
                "messageTypeId": 3,
                "policyId": 2,
                "policyVersion": 4,
                "severity": "High"
            },
            {
                "ID": 4043,
                "creationDate": "2022-03-27T03:23:52.299",
                "detectionDate": "2022-03-27T03:23:44.773",
                "detectionServerId": 1,
                "incidentStatusId": 1,
                "matchCount": 2,
                "messageSource": "NETWORK",
                "messageType": "HTTP",
                "messageTypeId": 3,
                "policyId": 41,
                "policyVersion": 4,
                "severity": "High"
            }
        ]
    }
}
```

#### Human Readable Output

>### Symantec DLP incidents results
>|ID|Severity|Status|Creation Date|Incident Type|Message Type|Policy ID|Match Count|
>|---|---|---|---|---|---|---|---|
>| 4044 | High | 1 | 2022-03-27T03:23:52.315 | NETWORK | HTTP | 2 | 3 |
>| 4043 | High | 1 | 2022-03-27T03:23:52.299 | NETWORK | HTTP | 41 | 2 |


### symantec-dlp-get-incident-details
***
Returns details of the specified incident.


#### Base Command

`symantec-dlp-get-incident-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID for which to retrieve details. | Required | 
| custom_attributes | This argument can get the following values:<br/>all - All custom attributes are needed <br/>none - None of the custom attributes are needed<br/>specific attributes - A comma-separated list of custom attribute names. For example: ca1,ca2,ca3<br/>custom attribute group name - A comma-separated list of custom attribute group names. For example: cag1, cag2, cag3.<br/>This value retrieves all custom attributes in the mentioned group. The value "none" is default. Possible values are: all, none, specific attributes, custom attribute group name. Default is none. | Optional | 
| custom_data | A comma-separated list of custom attribute names or custom attribute group names. For example: item1,item2,item3. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.Incident.ID | Number | The ID of the incident. | 
| SymantecDLP.Incident.policyVersion | Number | The version of the policy. | 
| SymantecDLP.Incident.attachmentInfo.componentType | Number | The ID of the type of the message component that generated the incident. | 
| SymantecDLP.Incident.attachmentInfo.messageComponentName | String | The name of the file or attachment that generated the incident. | 
| SymantecDLP.Incident.attachmentInfo.messageComponentId | Number | The ID of the message component that generated the incident. | 
| SymantecDLP.Incident.attachmentInfo.wasCracked | Boolean | Indicates if the message component that generated the incident was cracked. | 
| SymantecDLP.Incident.attachmentInfo.documentFormat | String | The file format of the message component that generated the incident. | 
| SymantecDLP.Incident.attachmentInfo.mimeType | String | The standard mime type of the message component that generated the incident. | 
| SymantecDLP.Incident.attachmentInfo.originalSize | Number | The size, in bytes, of the file or attachment that generated the incident. | 
| SymantecDLP.Incident.messageSubject | String | The subject of the message that caused the incident. | 
| SymantecDLP.Incident.policyName | String | The name of the policy. | 
| SymantecDLP.Incident.policyGroupName | String | The name of the policy group. | 
| SymantecDLP.Incident.policyGroupId | Number | The ID of the policy group of the policy that was violated. | 
| SymantecDLP.Incident.messageSource | String | The localized label that corresponds to the Symantec DLP product that generated the incident. | 
| SymantecDLP.Incident.messageId | Number | The ID of the message that caused the incident. | 
| SymantecDLP.Incident.messageOriginatorID | Number | The ID of the sender or originator of the message that caused the incident. | 
| SymantecDLP.Incident.matchCount | Number | The total number of policy violation matches produced by policies for this incident. | 
| SymantecDLP.Incident.creationDate | Date | The creation date of the incident. | 
| SymantecDLP.Incident.isBlockedStatusSuperseded | Boolean | Specifies whether the incident response was superseded by another response. | 
| SymantecDLP.Incident.detectionServerName | String | The name of the detection server that created the incident. | 
| SymantecDLP.Incident.networkSenderPort | Number | The port number on the host from which network traffic originated. | 
| SymantecDLP.Incident.messageType | String | Indicates the Symantec DLP product component that generated the incident. | 
| SymantecDLP.Incident.policyId | Number | The ID of the policy. | 
| SymantecDLP.Incident.detectionDate | Date | The detection date of the incident. | 
| SymantecDLP.Incident.messageTypeId | Number | The ID of the message type. | 
| SymantecDLP.Incident.detectionServerId | Number | The ID of the detection server or cloud detector that created the incident. | 
| SymantecDLP.Incident.messageDate | Date | The date and time that the network message that caused the incident originated. | 
| SymantecDLP.Incident.senderIPAddress | String | The IP address of the sender. | 
| SymantecDLP.Incident.endpointMachineIpAddress | String | The IP address of the endpoint machine. | 
| SymantecDLP.Incident.recipientInfo.recipientType | Number | The type of the recipient. | 
| SymantecDLP.Incident.recipientInfo.recipientPort | Number | The port of the recipient. | 
| SymantecDLP.Incident.recipientInfo.recipientDomain | String | The domain of the recipient. | 
| SymantecDLP.Incident.recipientInfo.recipientIdentifier | String | The identifier of the recipient. | 
| SymantecDLP.Incident.recipientInfo.recipientIPAddress | String | The IP address of the recipient. | 
| SymantecDLP.Incident.recipientInfo.recipientUrl | String | The URL address of the recipient. | 
| SymantecDLP.Incident.networkSenderIdentifier | String | The name and/or IP address of the user who caused the incident. | 
| SymantecDLP.Incident.isHidingNotAllowed | Boolean | Indicates if incident hiding is not allowed for the incident. | 
| SymantecDLP.Incident.incidentStatusName | String | The status of the incident. | 
| SymantecDLP.Incident.dataOwnerEmail | String | The email of the data owner. | 
| SymantecDLP.Incident.dataOwnerName | String | The name of the data owner. | 
| SymantecDLP.Incident.severity | Number | The severity of the incident. | 
| SymantecDLP.Incident.incidentStatusId | Number | The status ID of the incident. | 
| SymantecDLP.Incident.isHidden | Boolean | The hidden state of the incident. | 
| SymantecDLP.Incident.preventOrProtectStatusId | Number | The remediation status ID. | 
| SymantecDLP.Incident.CustomAttribute.Name | String | The name of the custom attribute. | 
| SymantecDLP.Incident.CustomAttribute.Value | String | The value of the custom attribute. | 
| SymantecDLP.Incident.CustomAttribute.Index | Number | The index of the custom attribute. | 
| SymantecDLP.Incident.fileCreateDate | Date | The date and time the file was created. | 
| SymantecDLP.Incident.discoverServer | String | The name of the file share, server, or SQL database that was scanned. | 
| SymantecDLP.Incident.fileAccessDate | Date | The date and time the file was last accessed. | 
| SymantecDLP.Incident.discoverTargetName | String | The name of the Discover scan target. | 
| SymantecDLP.Incident.discoverRepositoryLocation | String | The location, file location, or other path to the resource which generated the incident. | 
| SymantecDLP.Incident.discoverScanId | Number | The ID of the Discover scan. | 
| SymantecDLP.Incident.discoverContentRootPath | String | The full path on the file share, server, or SQL database that was scanned. | 
| SymantecDLP.Incident.discoverMillisSinceFirstSeen | Number | The time from the first incident generated, by the same policy on the same file, or resource using Discover detection, up to the detection time of the current incident. | 
| SymantecDLP.Incident.isBlockedStatusSuperseded | Boolean | Specifies whether the incident response was superseded by another response. | 
| SymantecDLP.Incident.messageAclEntries.principal | String | The principal of the entry. | 
| SymantecDLP.Incident.messageAclEntries.aclType | String | The type of resource the access control list applies to. | 
| SymantecDLP.Incident.messageAclEntries.permission | String | The permission of the entry. | 
| SymantecDLP.Incident.messageAclEntries.grantDeny | String | Whether access is allowed or not. | 
| SymantecDLP.Incident.discoverTargetId | Number | The ID of the Discover scan target. | 
| SymantecDLP.Incident.discoverScanStartDate | Date | The date and time that the Discover scan started. | 
| SymantecDLP.Incident.discoverName | String | The name of the file or resource that caused the incident. | 
| SymantecDLP.Incident.fileOwner | String | The owner of the file at the time the incident was created. | 
| SymantecDLP.Incident.discoverUrl | String | The URL of the resource scanned. | 
| SymantecDLP.Incident.endpointFilePath | String | The file system path of the file that violated the policy. | 
| SymantecDLP.Incident.endpointApplicationPath | String | The path to the application that caused the incident. | 
| SymantecDLP.Incident.endpointVolumeName | String | The name of the local drive where the incident occurred. | 
| SymantecDLP.Incident.domainUserName | String | The domain and user name associated with the incident. | 
| SymantecDLP.Incident.fileCreatedBy | String | The name of the user who created the file. | 
| SymantecDLP.Incident.fileModifiedBy | String | The name of the user who last modified the file. | 
| SymantecDLP.Incident.endpointDeviceInstanceId | String | The ID to specifically identify an endpoint computer. | 
| SymantecDLP.Incident.endpointFileName | String | The name of the file that violated the policy. | 
| SymantecDLP.Incident.endpointConnectionStatus | String | The location of the endpoint computer, on or off the corporate network. | 
| SymantecDLP.Incident.endpointMachineIpAddress | String | The IP address of the computer on which the incident occurred, if the computer is in the corporate network. | 
| SymantecDLP.Incident.endpointMachineName | String | The name of the computer on which the incident occurred. | 
| SymantecDLP.Incident.endpointApplicationName | String | The name of the application that caused the incident. | 

#### Command example
```!symantec-dlp-get-incident-details incident_id=1 custom_attributes="custom attribute group name" custom_data="att group2"```
#### Context Example
```json
{
    "SymantecDLP": {
        "Incident": {
            "ID": 1,
            "attachmentInfo": [
                {
                    "componentType": 3,
                    "documentFormat": "unknown",
                    "messageComponentId": 5,
                    "messageComponentName": "token",
                    "mimeType": "application/octet-stream",
                    "originalSize": 0,
                    "wasCracked": false
                }
            ],
            "creationDate": "2021-12-20T13:25:46.103",
            "customAttributeGroup": [
                {
                    "customAttribute": [
                        {
                            "index": 4,
                            "name": "kjv",
                            "value": "test"
                        }
                    ],
                    "name": "att group2"
                }
            ],
            "dataOwnerEmail": "testing@gmail.com",
            "dataOwnerName": "test123",
            "detectionDate": "2021-12-20T13:25:27.56",
            "detectionServerId": 1,
            "detectionServerName": "Detection - Network monitor",
            "endpointMachineIpAddress": "1.31.25.150",
            "incidentStatusId": 1,
            "incidentStatusName": "incident.status.New",
            "isBlockedStatusSuperseded": false,
            "isHidden": false,
            "isHidingNotAllowed": false,
            "matchCount": 1,
            "messageDate": "2021-12-20T13:25:27.623",
            "messageId": 2,
            "messageOriginatorID": 2,
            "messageSource": "NETWORK",
            "messageSubject": "HTTP incident",
            "messageType": "HTTP",
            "messageTypeId": 3,
            "networkSenderIdentifier": "1.31.25.150",
            "networkSenderPort": 51108,
            "policyGroupId": 1,
            "policyGroupName": "policy_group.default.name",
            "policyId": 2,
            "policyName": "Network Test policy",
            "policyVersion": 1,
            "preventOrProtectStatusId": 0,
            "recipientInfo": [
                {
                    "recipientDomain": "1.254.1.254",
                    "recipientIPAddress": "1.254.1.254",
                    "recipientIdentifier": "http://1.254.1.254/latest/api/token",
                    "recipientPort": 80,
                    "recipientType": 1,
                    "recipientUrl": "http://1.254.1.254/latest/api/token"
                }
            ],
            "senderIPAddress": "1.31.25.150",
            "severity": "Medium"
        }
    }
}
```

#### Human Readable Output

>### Symantec DLP incident 1 details
>|Status|Creation Date|Detection Date|Incident Type|Policy Name|Policy Group Name|Detection Server Name|Message Type|Message Source|Data Owner Name|Data Owner Email|Custom Attributes|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 2021-12-20T13:25:46.103 | 2021-12-20T13:25:27.56 | NETWORK | Network Test policy | policy_group.default.name | Detection - Network monitor | HTTP | NETWORK | test123 | testing@gmail.com | **-**	***name***: att group2<br/>	**customAttribute**:<br/>		**-**	***name***: kjv<br/>			***value***: test |


### symantec-dlp-update-incident
***
Updates the details of a specific incident.


#### Base Command

`symantec-dlp-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | The incident IDs to update. | Required | 
| data_owner_email | The data owner email. | Optional | 
| data_owner_name | The data owner name. | Optional | 
| note | The note to be added. | Optional | 
| incident_status_id | The status ID to update. Run the `symantec-dlp-list-incident-status` command to get the status ID. | Optional | 
| remediation_status_name | The remediation status name of an incident. | Optional | 
| remediation_location | The remediation location of the incident. Values can be user-defined. | Optional | 
| severity | The severity level of the incident. Possible values are: Info, Low, Medium, High. | Optional | 
| custom_attributes | The custom attributes to update. To get the custom attribute details, run the `symantec-dlp-get-incident-details` command with the `custom_attributes=all` command.<br/>Format:<br/>{columnIndex}:{newValue}<br/>For example, 1:update, 4:att. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-dlp-update-incident incident_ids=1,2 severity=Medium data_owner_email=testing@gmail.com custom_attributes=4:test```
#### Human Readable Output

>Symantec DLP incidents: ['1', '2'] were updated

### symantec-dlp-list-incident-status
***
Returns a list of the custom status values defined in the Symantec DLP deployment.


#### Base Command

`symantec-dlp-list-incident-status`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.IncidentStatus.id | Number | The ID of the status. | 
| SymantecDLP.IncidentStatus.name | String | The name of the status. | 

#### Command example
```!symantec-dlp-list-incident-status```
#### Context Example
```json
{
    "SymantecDLP": {
        "IncidentStatus": [
            {
                "id": 1,
                "name": "incident.status.New"
            },
            {
                "id": 42,
                "name": "Escalated"
            },
            {
                "id": 21,
                "name": "In Process"
            },
            {
                "id": 43,
                "name": "False Positive"
            },
            {
                "id": 44,
                "name": "Configuration Error"
            },
            {
                "id": 45,
                "name": "Resolved"
            },
            {
                "id": 61,
                "name": "Custom status"
            }
        ]
    }
}
```

#### Human Readable Output

>### Symantec DLP incidents status
>|Id|Name|
>|---|---|
>| 1 | incident.status.New |
>| 42 | Escalated |
>| 21 | In Process |
>| 43 | False Positive |
>| 44 | Configuration Error |
>| 45 | Resolved |
>| 61 | Custom status |


### symantec-dlp-get-incident-history
***
Returns the history of the specified incident.


#### Base Command

`symantec-dlp-get-incident-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The limit of the incident history list per page. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.IncidentHistory.incidentHistoryDate | String | The date of the incident history. | 
| SymantecDLP.IncidentHistory.dlpUserName | String | The name of the user. | 
| SymantecDLP.IncidentHistory.incidentHistoryAction | String | The action of the incident history. | 
| SymantecDLP.IncidentHistory.incidentHistoryDetail | String | The incident history detail. | 
| SymantecDLP.IncidentHistory.policyGroupId | Number | The ID of the policy group. | 
| SymantecDLP.IncidentHistory.detectionServerName | String | The name of the detection server that created the incident. | 
| SymantecDLP.IncidentHistory.incidentHistoryId | Number | The ID of the incident history. | 
| SymantecDLP.IncidentHistory.messageSource | String | The localized label that corresponds to the Symantec DLP product that generated the incident. | 
| SymantecDLP.IncidentHistory.messageDate | String | The date of the message. | 
| SymantecDLP.IncidentHistory.ID | Number | The ID of the incident. | 

#### Command example
```!symantec-dlp-get-incident-history limit=6 incident_id=2```
#### Context Example
```json
{
    "SymantecDLP": {
        "IncidentHistory": {
            "ID": 2,
            "incidentHistory": [
                {
                    "detectionServerName": "Detection - Network monitor",
                    "dlpUserName": "Administrator",
                    "incidentHistoryAction": "SET_STATUS",
                    "incidentHistoryDate": "2021-12-20T13:25:46.197",
                    "incidentHistoryDetail": "incident.status.New",
                    "messageDate": "2021-12-20T13:25:27.623",
                    "messageSource": "NETWORK",
                    "policyGroupId": 1
                },
                {
                    "detectionServerName": "Detection - Network monitor",
                    "dlpUserName": "Administrator",
                    "incidentHistoryAction": "MESSAGE_NOT_RETAINED",
                    "incidentHistoryDate": "2021-12-20T13:25:27.576",
                    "messageDate": "2021-12-20T13:25:27.623",
                    "messageSource": "NETWORK",
                    "policyGroupId": 1
                },
                {
                    "detectionServerName": "Detection - Network monitor",
                    "dlpUserName": "Administrator",
                    "incidentHistoryAction": "SET_SEVERITY",
                    "incidentHistoryDate": "2021-12-20T13:25:27.576",
                    "incidentHistoryDetail": "incident.severity.High",
                    "messageDate": "2021-12-20T13:25:27.623",
                    "messageSource": "NETWORK",
                    "policyGroupId": 1
                },
                {
                    "detectionServerName": "Detection - Network monitor",
                    "dlpUserName": "Administrator",
                    "incidentHistoryAction": "DETECTED",
                    "incidentHistoryDate": "2021-12-20T13:25:27.576",
                    "messageDate": "2021-12-20T13:25:27.623",
                    "messageSource": "NETWORK",
                    "policyGroupId": 1
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Symantec DLP Incident 2 history results
>|DLP User Name|History Date|Incident History Action|
>|---|---|---|
>| Administrator | 2021-12-20T13:25:46.197 | SET_STATUS |
>| Administrator | 2021-12-20T13:25:27.576 | MESSAGE_NOT_RETAINED |
>| Administrator | 2021-12-20T13:25:27.576 | SET_SEVERITY |
>| Administrator | 2021-12-20T13:25:27.576 | DETECTED |


### symantec-dlp-list-remediation-status
***
Returns a list of the remediation status values defined in the Symantec DLP deployment.


#### Base Command

`symantec-dlp-list-remediation-status`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.IncidentRemediationStatus.id | Number | The ID of the remediation status. | 
| SymantecDLP.IncidentRemediationStatus.name | String | The name of the remediation status. | 

#### Command example
```!symantec-dlp-list-remediation-status```
#### Context Example
```json
{
    "SymantecDLP": {
        "IncidentRemediationStatus": [
            {
                "id": 0,
                "name": "PASSED"
            },
            {
                "id": 1,
                "name": "BLOCKED"
            },
            {
                "id": 2,
                "name": "MESSAGE_MODIFIED"
            },
            {
                "id": 3,
                "name": "PROTECT_FILE_COPIED"
            },
            {
                "id": 4,
                "name": "PROTECT_FILE_QUARANTINED"
            },
            {
                "id": 5,
                "name": "PROTECT_FILE_DELETED"
            },
            {
                "id": 6,
                "name": "PROTECT_REMEDIATION_ERROR"
            },
            {
                "id": 8,
                "name": "CONTENT_REMOVED"
            },
            {
                "id": 9,
                "name": "ENDPOINT_BLOCK"
            },
            {
                "id": 10,
                "name": "ENDPOINT_NOTIFY"
            },
            {
                "id": 11,
                "name": "FLEX_RESPONSE_EXECUTED"
            },
            {
                "id": 12,
                "name": "FLEX_RESPONSE_ERROR"
            },
            {
                "id": 13,
                "name": "FLEX_RESPONSE_REQUESTED"
            },
            {
                "id": 14,
                "name": "ENDPOINT_NOTIFY_CANCEL_ALLOW"
            },
            {
                "id": 15,
                "name": "ENDPOINT_NOTIFY_CANCEL_BLOCK"
            },
            {
                "id": 16,
                "name": "ENDPOINT_NOTIFY_CANCEL_TIMEOUT_ALLOW"
            },
            {
                "id": 17,
                "name": "ENDPOINT_NOTIFY_CANCEL_TIMEOUT_BLOCK"
            },
            {
                "id": 18,
                "name": "ENDPOINT_FILE_QUARANTINE_FAILED"
            },
            {
                "id": 19,
                "name": "ENDPOINT_FILE_QUARANTINED"
            },
            {
                "id": 20,
                "name": "UNKNOWN"
            },
            {
                "id": 21,
                "name": "EMAIL_QUARANTINED"
            },
            {
                "id": 22,
                "name": "EMAIL_APPROVED"
            },
            {
                "id": 23,
                "name": "EMAIL_BLOCKED"
            },
            {
                "id": 24,
                "name": "CUSTOM_ACTION_ON_EMAIL"
            },
            {
                "id": 25,
                "name": "EMAIL_MESSAGE_EXPUNGED"
            },
            {
                "id": 26,
                "name": "TRANSPORT_HEADERS_ADDED"
            },
            {
                "id": 27,
                "name": "VISUAL_TAG_ADDED"
            },
            {
                "id": 28,
                "name": "VISUAL_TAG_ADDITION_FAILED"
            },
            {
                "id": 29,
                "name": "QUARANTINE_FAILED"
            },
            {
                "id": 30,
                "name": "REST_ENCRYPTED"
            },
            {
                "id": 31,
                "name": "REST_PERFORMED_DRM"
            },
            {
                "id": 32,
                "name": "REST_PERFORMED_BREAK_LINKS"
            },
            {
                "id": 33,
                "name": "REST_PERFORMED_CUSTOM_ACTION"
            },
            {
                "id": 34,
                "name": "ENCRYPTED"
            },
            {
                "id": 35,
                "name": "ENCRYPT_FAILED"
            },
            {
                "id": 36,
                "name": "ENDPOINT_USER_ENCRYPT_CANCEL_ENCRYPT"
            },
            {
                "id": 37,
                "name": "ENDPOINT_USER_ENCRYPT_CANCEL_PREVENT"
            },
            {
                "id": 38,
                "name": "ENDPOINT_USER_ENCRYPT_CANCEL_TIMEOUT_ENCRYPT"
            },
            {
                "id": 39,
                "name": "ENDPOINT_USER_ENCRYPT_CANCEL_TIMEOUT_PREVENT"
            },
            {
                "id": 40,
                "name": "PROTECT_FILE_ENCRYPTED"
            },
            {
                "id": 41,
                "name": "REST_ACTION_REQUESTED"
            },
            {
                "id": 42,
                "name": "REST_ACTION_SUCCESS"
            },
            {
                "id": 43,
                "name": "REST_ACTION_FAILURE"
            },
            {
                "id": 44,
                "name": "REST_ACTION_WARNING"
            },
            {
                "id": 45,
                "name": "REST_USER_REMEDIATED"
            },
            {
                "id": 46,
                "name": "MANUAL_ACTION_REQUESTED"
            },
            {
                "id": 47,
                "name": "REST_RESTRICTED_FILE_AUTHORIZATION"
            },
            {
                "id": 48,
                "name": "REST_PREVENTED_PHYSICAL_ACCESS"
            },
            {
                "id": 49,
                "name": "REST_ADDITIONAL_ACCESS_PROTECTION"
            },
            {
                "id": 50,
                "name": "ENDPOINT_ENCRYPT"
            },
            {
                "id": 51,
                "name": "ENDPOINT_ENCRYPT_PREVENT_ENFORCED"
            },
            {
                "id": 52,
                "name": "ENDPOINT_ICT_TAGGING_SUCCESS"
            },
            {
                "id": 53,
                "name": "ENDPOINT_ICT_TAGGING_FAILURE"
            },
            {
                "id": 54,
                "name": "ENDPOINT_ICT_TAGGING_NOT_SUPPORTED"
            },
            {
                "id": 55,
                "name": "ENDPOINT_ICD_SUCCESS"
            },
            {
                "id": 56,
                "name": "ENDPOINT_ICD_FAILURE"
            },
            {
                "id": 57,
                "name": "PROTECT_FILE_TAGGED"
            },
            {
                "id": 58,
                "name": "PROTECT_FILE_TAGGING_FAILED"
            },
            {
                "id": 59,
                "name": "PROTECT_FILE_TAGGING_NOT_SUPPORTED"
            },
            {
                "id": 60,
                "name": "PROTECT_REMEDIATION_FAILED_CORRUPTION"
            },
            {
                "id": 61,
                "name": "REMEDIATION_PENDING"
            },
            {
                "id": 62,
                "name": "REMEDIATION_OVERRIDEN"
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents remediation status results
>|Id|Name|
>|---|---|
>| 0 | PASSED |
>| 1 | BLOCKED |
>| 2 | MESSAGE_MODIFIED |
>| 3 | PROTECT_FILE_COPIED |
>| 4 | PROTECT_FILE_QUARANTINED |
>| 5 | PROTECT_FILE_DELETED |
>| 6 | PROTECT_REMEDIATION_ERROR |
>| 8 | CONTENT_REMOVED |
>| 9 | ENDPOINT_BLOCK |
>| 10 | ENDPOINT_NOTIFY |
>| 11 | FLEX_RESPONSE_EXECUTED |
>| 12 | FLEX_RESPONSE_ERROR |
>| 13 | FLEX_RESPONSE_REQUESTED |
>| 14 | ENDPOINT_NOTIFY_CANCEL_ALLOW |
>| 15 | ENDPOINT_NOTIFY_CANCEL_BLOCK |
>| 16 | ENDPOINT_NOTIFY_CANCEL_TIMEOUT_ALLOW |
>| 17 | ENDPOINT_NOTIFY_CANCEL_TIMEOUT_BLOCK |
>| 18 | ENDPOINT_FILE_QUARANTINE_FAILED |
>| 19 | ENDPOINT_FILE_QUARANTINED |
>| 20 | UNKNOWN |
>| 21 | EMAIL_QUARANTINED |
>| 22 | EMAIL_APPROVED |
>| 23 | EMAIL_BLOCKED |
>| 24 | CUSTOM_ACTION_ON_EMAIL |
>| 25 | EMAIL_MESSAGE_EXPUNGED |
>| 26 | TRANSPORT_HEADERS_ADDED |
>| 27 | VISUAL_TAG_ADDED |
>| 28 | VISUAL_TAG_ADDITION_FAILED |
>| 29 | QUARANTINE_FAILED |
>| 30 | REST_ENCRYPTED |
>| 31 | REST_PERFORMED_DRM |
>| 32 | REST_PERFORMED_BREAK_LINKS |
>| 33 | REST_PERFORMED_CUSTOM_ACTION |
>| 34 | ENCRYPTED |
>| 35 | ENCRYPT_FAILED |
>| 36 | ENDPOINT_USER_ENCRYPT_CANCEL_ENCRYPT |
>| 37 | ENDPOINT_USER_ENCRYPT_CANCEL_PREVENT |
>| 38 | ENDPOINT_USER_ENCRYPT_CANCEL_TIMEOUT_ENCRYPT |
>| 39 | ENDPOINT_USER_ENCRYPT_CANCEL_TIMEOUT_PREVENT |
>| 40 | PROTECT_FILE_ENCRYPTED |
>| 41 | REST_ACTION_REQUESTED |
>| 42 | REST_ACTION_SUCCESS |
>| 43 | REST_ACTION_FAILURE |
>| 44 | REST_ACTION_WARNING |
>| 45 | REST_USER_REMEDIATED |
>| 46 | MANUAL_ACTION_REQUESTED |
>| 47 | REST_RESTRICTED_FILE_AUTHORIZATION |
>| 48 | REST_PREVENTED_PHYSICAL_ACCESS |
>| 49 | REST_ADDITIONAL_ACCESS_PROTECTION |
>| 50 | ENDPOINT_ENCRYPT |
>| 51 | ENDPOINT_ENCRYPT_PREVENT_ENFORCED |
>| 52 | ENDPOINT_ICT_TAGGING_SUCCESS |
>| 53 | ENDPOINT_ICT_TAGGING_FAILURE |
>| 54 | ENDPOINT_ICT_TAGGING_NOT_SUPPORTED |
>| 55 | ENDPOINT_ICD_SUCCESS |
>| 56 | ENDPOINT_ICD_FAILURE |
>| 57 | PROTECT_FILE_TAGGED |
>| 58 | PROTECT_FILE_TAGGING_FAILED |
>| 59 | PROTECT_FILE_TAGGING_NOT_SUPPORTED |
>| 60 | PROTECT_REMEDIATION_FAILED_CORRUPTION |
>| 61 | REMEDIATION_PENDING |
>| 62 | REMEDIATION_OVERRIDEN |


### symantec-dlp-get-incident-original-message

***
Fetches the original message from an incident. Requires SDLP 15.8.

#### Base Command

`symantec-dlp-get-incident-original-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The EntryID of the original message file. | 
| InfoFile.Extension | String | The extension of the original message file. | 
| InfoFile.Name | String | The name of the original message file. | 
| InfoFile.Info | String | The info of the original message file. | 
| InfoFile.Size | Number | The size of the original message file. | 
| InfoFile.Type | String | The type of the original message file. | 

#### Command example
```!symantec-dlp-get-incident-original-message incident_id=1```
#### Context Example
```json
{
    "File": {
        "EntryID": "2442@1a367091-9d9f-4851-8e71-bfbbb66563a6",
        "Info": "text/plain",
        "MD5": "cb79735bc7c9de30eb3a63110c6febd9",
        "Name": "unknown",
        "SHA1": "30dcc9ed8a7b1f44de4c4cdcde055708f96487d5",
        "SHA256": "d085bf376b122a38064ef32ede13b0ff64b7dc085079e1cfd57ae664bf76d78b",
        "SHA512": "3db852235a9d84dccacc04e805c5a3d843d0cd90c71833e2b8c68c17f77f04aadd88f8f72216a9f23417336e689c342a25588390002edd51605067a78bfabfa4",
        "SSDeep": "3:ZwRRrPD+sGMw2Bu:+7Dy324",
        "Size": 37,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output


### symantec-dlp-get-report-filters

***
Retrieves the filter criteria for a saved search in the Enforce console by report ID. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-get-report-filters`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID for which to retrieve filters. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.ReportFilter | Unknown | The filter criteria for a saved search in the Enforce console. | 

#### Command example
```!symantec-dlp-get-report-filters report_id=1```
#### Context Example
```json
{
    "SymantecDLP": {
        "ReportFilter": {
            "filter": {
                "booleanOperator": "AND",
                "filterType": "booleanLogic",
                "filters": [
                    {
                        "filterType": "string",
                        "operandOne": {
                            "name": "messageSource"
                        },
                        "operandTwoValues": [
                            "NETWORK"
                        ],
                        "operator": "EQ"
                    },
                    {
                        "booleanOperator": "AND",
                        "filterType": "booleanLogic",
                        "filters": [
                            {
                                "filterType": "localDateTime",
                                "operandOne": {
                                    "name": "messageDate"
                                },
                                "operandTwoValues": [
                                    "2022-01-01T00:00:00"
                                ],
                                "operator": "GTE"
                            },
                            {
                                "filterType": "localDateTime",
                                "operandOne": {
                                    "name": "messageDate"
                                },
                                "operandTwoValues": [
                                    "2022-12-31T23:59:59"
                                ],
                                "operator": "LTE"
                            },
                            {
                                "filterType": "string",
                                "operandOne": {
                                    "function": "UPPER",
                                    "name": "networkSenderIdentifier"
                                },
                                "operandTwoValues": [
                                    "example_email@demisto.com"
                                ],
                                "operator": "IN"
                            }
                        ]
                    }
                ]
            },
            "filterString": "{\"select\": [{\"id\": 173, \"name\": \"messageDate\"}, {\"id\": 174, \"name\": \"incidentId\"}, {\"id\": 175, \"name\": \"networkSenderIdentifier\"}, {\"id\": 176, \"name\": \"messageSubject\"}, {\"id\": 177, \"name\": \"recipientIdentifier\"}, {\"id\": 178, \"name\": \"policyName\"}, {\"id\": 179, \"name\": \"matchCount\"}, {\"id\": 180, \"name\": \"incidentStatusName\"}], \"filter\": {\"filterType\": \"booleanLogic\", \"booleanOperator\": \"AND\", \"filters\": [{\"filterType\": \"string\", \"operandOne\": {\"name\": \"messageSource\"}, \"operator\": \"EQ\", \"operandTwoValues\": [\"NETWORK\"]}, {\"filterType\": \"booleanLogic\", \"booleanOperator\": \"AND\", \"filters\": [{\"filterType\": \"localDateTime\", \"operandOne\": {\"name\": \"messageDate\"}, \"operator\": \"GTE\", \"operandTwoValues\": [\"2022-01-01T00:00:00\"]}, {\"filterType\": \"localDateTime\", \"operandOne\": {\"name\": \"messageDate\"}, \"operator\": \"LTE\", \"operandTwoValues\": [\"2022-12-31T23:59:59\"]}, {\"filterType\": \"string\", \"operandOne\": {\"name\": \"networkSenderIdentifier\", \"function\": \"UPPER\"}, \"operator\": \"IN\", \"operandTwoValues\": [\"example_email@demisto.com\"]}]}]}, \"orderBy\": [{\"field\": {\"name\": \"messageDate\"}, \"order\": \"DESC\"}]}",
            "orderBy": [
                {
                    "field": {
                        "name": "messageDate"
                    },
                    "order": "DESC"
                }
            ],
            "select": [
                {
                    "id": 173,
                    "name": "messageDate"
                },
                {
                    "id": 174,
                    "name": "incidentId"
                },
                {
                    "id": 175,
                    "name": "networkSenderIdentifier"
                },
                {
                    "id": 176,
                    "name": "messageSubject"
                },
                {
                    "id": 177,
                    "name": "recipientIdentifier"
                },
                {
                    "id": 178,
                    "name": "policyName"
                },
                {
                    "id": 179,
                    "name": "matchCount"
                },
                {
                    "id": 180,
                    "name": "incidentStatusName"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>Returned results for report id 1
### symantec-dlp-list-users

***
Returns details for all SDLP users from the Enforce console. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.Users | Unknown | List of SDLP users and details. | 

#### Command example
```!symantec-dlp-list-users```
#### Context Example
```json
{
    "SymantecDLP": {
        "Users": {
            "accountDisabled": "no",
            "emailAddress": "test@gmail.com",
            "roles": [
                "API Web"
            ],
            "userId": 1,
            "userName": "User1"
        }
    }
}
```

#### Human Readable Output

>### Symantec DLP Users
>|Accountdisabled|Emailaddress|Roles|Userid|Username|
>|---|---|---|---|---|
>| no | test@gmail.com | API Web | 1 | User1 |

### symantec-dlp-get-sender-recipient-pattern

***
Returns a sender/recipient pattern. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-get-sender-recipient-pattern`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | Pattern ID for which to retrieve pattern details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.SenderRecipientPattern | Unknown | Sender/recipient pattern returned from the Enforce console. | 

#### Command example
```!symantec-dlp-get-sender-recipient-pattern pattern_id=1```
#### Context Example
```json
{
    "SymantecDLP": {
        "SenderRecipientPattern": {
            "description": "demo",
            "id": 1,
            "ipAddresses": [
                "1.1.1.1",
                "2.2.2.2"
            ],
            "modifiedBy": {
                "id": 343,
                "name": "AdminUsername "
            },
            "modifiedDate": "05/16/23 12:20 PM",
            "name": "XSOAR Sender Block Example",
            "ruleType": 4,
            "userPatterns": [
                "domain-jsmith",
                "domain-jdoe"
            ]
        }
    }
}
```

#### Human Readable Output

>### XSOAR Sender Block Example
>|description|id|ipAddresses|modifiedBy|modifiedDate|name|ruleType|userPatterns|
>|---|---|---|---|---|---|---|---|
>| demo | 1 | 1.1.1.1,<br/>2.2.2.2 | id: 343<br/>name: AdminUsername  | 05/16/23 12:20 PM | XSOAR Sender Block Example | 4 | domain-jsmith,<br/>domain-jdoe |

### symantec-dlp-list-sender-recipient-patterns

***
Returns a list of all sender/recipient patterns from the Enforce console. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-list-sender-recipient-patterns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.Patterns | Unknown |  The list of all sender/recipient patterns returned from the Enforce console. | 

#### Command example
```!symantec-dlp-list-sender-recipient-patterns```
#### Context Example
```json
{
    "SymantecDLP": {
        "Patterns": {
            "description": "demo",
            "id": 1,
            "ipAddresses": [
                "1.1.1.1",
                "2.2.2.2"
            ],
            "modifiedBy": {
                "id": 343,
                "name": "AdminUsername "
            },
            "modifiedDate": "05/16/23 12:20 PM",
            "name": "XSOAR Sender Block Example",
            "ruleType": 4,
            "userPatterns": [
                "domain-jsmith",
                "domain-jdoe"
            ]
        }
    }
}
```

#### Human Readable Output

>### Sender/Recipient Patterns
>|description|id|ipAddresses|modifiedBy|modifiedDate|name|ruleType|userPatterns|
>|---|---|---|---|---|---|---|---|
>| demo | 1 | 1.1.1.1,<br/>2.2.2.2 | id: 343<br/>name: AdminUsername  | 05/16/23 12:20 PM | XSOAR Sender Block Example | 4 | domain-jsmith,<br/>domain-jdoe |

### symantec-dlp-update-sender-pattern

***
Updates a sender pattern in the Enforce console. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-update-sender-pattern`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | ID number of the pattern to update. | Required | 
| ips | Comma-separated list of IP addresses for the pattern. Note: These IP values will replace the existing values in the pattern. | Optional | 
| users | Comma-separated list of emails, Windows names, or screen names for the pattern. Note: These user values will replace the existing values in the pattern. | Optional | 
| name | Name of the sender pattern. Note: This value will change the name of the pattern if different from the existing name. | Required | 
| description | Description of the sender pattern. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.SenderUpdate | Unknown | Results of updating the sender pattern from the Enforce Console. | 

#### Command example
```!symantec-dlp-update-sender-pattern pattern_id=1 name="XSOAR Sender Block Example" description="demo"```
#### Context Example
```json
{
    "SymantecDLP": {
        "SenderUpdate": {
            "description": "demo",
            "id": 1,
            "ipAddresses": [
                "1.1.1.1",
                "2.2.2.2"
            ],
            "modifiedBy": {
                "id": 343,
                "name": "AdminUsername "
            },
            "modifiedDate": "05/16/23 12:20 PM",
            "name": "XSOAR Sender Block Example",
            "ruleType": 4,
            "userPatterns": [
                "domain-jsmith",
                "domain-jdoe"
            ]
        }
    }
}
```

#### Human Readable Output

>### Sender Pattern Update Results
>|description|id|ipAddresses|modifiedBy|modifiedDate|name|ruleType|userPatterns|
>|---|---|---|---|---|---|---|---|
>| demo | 1 | 1.1.1.1,<br/>2.2.2.2 | id: 343<br/>name: AdminUsername  | 05/16/23 12:20 PM | XSOAR Sender Block Example | 4 | domain-jsmith,<br/>domain-jdoe |

### symantec-dlp-update-recipient-pattern

***
Updates a recipient pattern in the Enforce console. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-update-recipient-pattern`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | ID number of the pattern to update. | Required | 
| ips | Comma-separated list of IP addresses for the pattern. Note: These IP values will replace the existing values in the pattern. | Optional | 
| emails | Comma-separated list of emails for the pattern. Note: These email values will replace the existing values in the pattern. | Optional | 
| domains | Comma-separated list of domains for the pattern. Note: These domain values will replace the existing values in the pattern. | Optional | 
| name | Name of the sender pattern. Note: This value will change the name of the pattern if different from the existing name. | Required | 
| description | Description of the sender pattern. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.RecipientUpdate | Unknown | Results of updating the recipient pattern from the Enforce Console. | 

#### Command example
```!symantec-dlp-update-recipient-pattern pattern_id=1 name="XSOAR Recipient Edit Test" description="updated from XSOAR for demo"```
#### Context Example
```json
{
    "SymantecDLP": {
        "RecipientUpdate": {
            "description": "updated from XSOAR for demo",
            "emailAddresses": [
                "test1@gmail.com",
                "test2@gmail.com"
            ],
            "id": 1,
            "ipAddresses": [
                "1.1.1.1",
                "2.2.2.2"
            ],
            "modifiedBy": {
                "id": 343,
                "name": "AdminUsername"
            },
            "modifiedDate": "05/16/23 12:18 PM",
            "name": "XSOAR Recipient Edit Test",
            "ruleType": 2,
            "urlDomains": [
                "example.com",
                "external.com"
            ]
        }
    }
}
```

#### Human Readable Output

>### Sender Pattern Update Results
>|description|emailAddresses|id|ipAddresses|modifiedBy|modifiedDate|name|ruleType|urlDomains|
>|---|---|---|---|---|---|---|---|---|
>| updated from XSOAR for demo | test1@gmail.com,<br/>test2@gmail.com | 1 | 1.1.1.1,<br/>2.2.2.2 | id: 343<br/>name: AdminUsername | 05/16/23 12:18 PM | XSOAR Recipient Edit Test | 2 | example.com,<br/>external.com |

### symantec-dlp-get-message-body

***
Returns the message body from the Enforce console by incident ID. Requires SDLP 16.0.

#### Base Command

`symantec-dlp-get-message-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.MessageBody | Unknown | Message body for the incident returned by the Enforce console. | 

#### Command example
```!symantec-dlp-get-message-body incident_id=1```
#### Context Example
```json
{
    "SymantecDLP": {
        "MessageBody": {
            "IncidentID": "1",
            "MessageBody": "message body for incident 1"
        }
    }
}
```

#### Human Readable Output

>Message body for incident 1 written to context data

## Breaking changes from the previous version of this integration - Symantec Data Loss Prevention v2

### Commands
#### The following commands were removed in this version:
- ***symantec-dlp-incident-binaries***
- ***symantec-dlp-incident-violations***
- ***symantec-dlp-list-custom-attributes***

### Arguments
#### The following arguments were removed in this version:

In the ***symantec-dlp-update-incident*** command:
* *incident_id* - this argument was replaced by *incident_ids*.
* *note_time*
* *status*
* *custom_attribute_name* - this argument was replaced by *custom_attributes*.
* *custom_attribute_value* - this argument was replaced by *custom_attributes*.
* *remediation_status* - this argument was replaced by *remediation_status_name*.

#### The behavior of the following arguments was changed:

In the ***symantec-dlp-update-incident*** command:
  *custom_attribute_name* and *custom_attribute_value* are now used in *custom_attributes*.
  *incident_id* argument are now called *incident_ids* and can get a list of incident IDs to update.
  
### Outputs
#### The following outputs were removed in this version:

In the ***symantec-dlp-get-incident-details*** command:

- *SymantecDLP.Incident.LongID*
- *SymantecDLP.Incident.StatusCode* - this output was replaced by *SymantecDLP.Incident.incidentStatusId*.
- *SymantecDLP.Incident.CreationDate* - this output was replaced by *SymantecDLP.Incident.creationDate*.
- *SymantecDLP.Incident.DetectionDate* - this output was replaced by *SymantecDLP.Incident.detectionDate*.
- *SymantecDLP.Incident.Severity* - this output was replaced by *SymantecDLP.Incident.severity*.
- *SymantecDLP.Incident.MessageSource* - this output was replaced by *SymantecDLP.Incident.messageSource*.
- *SymantecDLP.Incident.MessageSourceType* - this output was replaced by *SymantecDLP.Incident.messageType*.
- *SymantecDLP.Incident.MessageType* - this output was replaced by *SymantecDLP.Incident.messageType*.
- *SymantecDLP.Incident.MessageTypeID - this output was replaced by *SymantecDLP.Incident.messageTypeId*.*
- *SymantecDLP.Incident.Policy.Name* - this output was replaced by *SymantecDLP.Incident.policyName*.
- *SymantecDLP.Incident.Policy.Version* - this output was replaced by *SymantecDLP.Incident.policyVersion*.
- *SymantecDLP.Incident.Policy.Label*
- *SymantecDLP.Incident.Policy.ID* - this output was replaced by *SymantecDLP.Incident.policyId*.
- *SymantecDLP.Incident.BlockedStatus*
- *SymantecDLP.Incident.MatchCount* - this output was replaced by *SymantecDLP.Incident.matchCount*.
- *SymantecDLP.Incident.RuleViolationCount*
- *SymantecDLP.Incident.DetectionServer* - this output was replaced by *SymantecDLP.Incident.detectionServerName*.
- *SymantecDLP.Incident.DataOwner.Name* - this output was replaced by *SymantecDLP.Incident.dataOwnerName*.
- *SymantecDLP.Incident.DataOwner.Email* - this output was replaced by *SymantecDLP.Incident.dataOwnerEmail*.
- *SymantecDLP.Incident.EventDate*
- *SymantecDLP.Incident.ViolatedPolicyRule.Name*
- *SymantecDLP.Incident.ViolatedPolicyRule.ID*
- *SymantecDLP.Incident.OtherViolatedPolicy.Name*
- *SymantecDLP.Incident.OtherViolatedPolicy.Version*
- *SymantecDLP.Incident.OtherViolatedPolicy.Label*
- *SymantecDLP.Incident.OtherViolatedPolicy.ID*


## Additional Considerations for this version
There is an issue with DLP API where some incidents get a 401 error.
For these incidents, the missing data is returned. From the Network incident layout, in the description field, you can see information about this issue.