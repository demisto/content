Symantec Data Loss Prevention enables you to discover, monitor and protect your sensitive corporate information.
This integration was integrated and tested with version 15.7 RESTful API of Symantec Data Loss Prevention.

[Check Symantec DLP 15.7 API docs](https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/information-security/data-loss-prevention/generated-pdfs/Symantec_DLP_15.7_REST_API_Guide.pdf)
## Configure Symantec Data Loss Prevention v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Data Loss Prevention v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Enforce Server (e.g. https://192.168.0.1) | True |
    | Username | True |
    | Password | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | Fetch limit | False |
    | Incident type | False |
    | Incident Status ID | False |
    | Incident Severity | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.

## Additions and changes between Symantec DLP V1 to Symantec DLP v2
### New commands
- ***symantec-dlp-get-incident-history***
- ***symantec-dlp-list-remediation-status***

### Deprecated commands
- ***symantec-dlp-incident-binaries***
- ***symantec-dlp-incident-violations***

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### symantec-dlp-list-incidents
***
Returns a list of incidents.


#### Base Command

`symantec-dlp-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| creation_date | Get incidents with creation date later than specified. Support ISO (e.g 2021-12-28T00:00:00Z) and free text (e.g. '2 days'). | Optional | 
| status_id | The status ID of the incidents. In order to get status IDs, you should run the command `symantec-dlp-list-incident-status`. | Optional | 
| severity | The severity of the incidents. Can be: "High", "Medium", "Low", and "Info". Possible values are: Info, Low, Medium, High. | Optional | 
| incident_type | The incidents type. Can be: "Network", "Endpoint" and "Discover". Possible values are: Network, Discover, Endpoint. | Optional | 
| limit | The limit of the incidents list per page. Default is 50. Default is 50. | Optional | 
| page | The page of the incidents list. Default is 1. Default is 1. | Optional | 


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
| SymantecDLP.Incident.severityId | Number | The severity ID of the incident. | 
| SymantecDLP.Incident.messageTypeId | Number | The ID of the Message Type. | 
| SymantecDLP.Incident.incidentStatusId | Number | The status ID of the incident. | 

#### Command example
```!symantec-dlp-list-incidents limit=2 severity=High incident_type=Network creation_date="4 days"```
#### Context Example
```json
{
    "SymantecDLP": {
        "Incident": [
            {
                "ID": 3676,
                "creationDate": "2022-03-09T09:23:56.692",
                "detectionDate": "2022-03-09T09:23:41.493",
                "detectionServerId": 1,
                "incidentStatusId": 1,
                "matchCount": 3,
                "messageSource": "NETWORK",
                "messageType": "HTTP",
                "messageTypeId": 3,
                "policyId": 2,
                "policyVersion": 4,
                "severityId": 1
            },
            {
                "ID": 3675,
                "creationDate": "2022-03-09T09:23:56.66",
                "detectionDate": "2022-03-09T09:23:41.493",
                "detectionServerId": 1,
                "incidentStatusId": 1,
                "matchCount": 2,
                "messageSource": "NETWORK",
                "messageType": "HTTP",
                "messageTypeId": 3,
                "policyId": 41,
                "policyVersion": 4,
                "severityId": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Symantec DLP incidents results
>|ID|Severity|Status|Creation Date|Incident Type|Message Type|Policy ID|Match Count|
>|---|---|---|---|---|---|---|---|
>| 3676 | High | 1 | 2022-03-09T09:23:56.692 | NETWORK | HTTP | 2 | 3 |
>| 3675 | High | 1 | 2022-03-09T09:23:56.66 | NETWORK | HTTP | 41 | 2 |


### symantec-dlp-get-incident-details
***
Returns the details of the specified incident.


#### Base Command

`symantec-dlp-get-incident-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID to get details of. | Required | 
| custom_attributes | This argument can get the following values:<br/>all - If all custom attributes are needed <br/>none - If none of the custom attributes are needed<br/>specific attributes - A list of custom attributes names, seperated by comma. For example: ca1,ca2,ca3<br/>custom attribute group name - A list of custom attributes group names, seperated by comma. For example: cag1, cag2, cag3.<br/>This value will retrive all custom attributes in the mentioned group. The value "none" is default. Possible values are: all, none, specific attributes, custom attribute group name. Default is none. | Optional | 
| custom_data | A list of custom attributes names / custom attribute group names. List should be comma seperated. For example: item1,item2,item3. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.Incident.ID | Number | The ID of the incident. | 
| SymantecDLP.Incident.creationDate | Date | The creation date of the incident. | 
| SymantecDLP.Incident.detectionDate | Date | The detection date of the incident. | 
| SymantecDLP.Incident.severityId | Number | The severity ID of the incident. | 
| SymantecDLP.Incident.messageSource | String | The localized label that corresponds to the Symantec DLP product that generated the incident. | 
| SymantecDLP.Incident.messageType | String | Indicates the Symantec DLP product that generated the incident. Can be: "NETWORK", "DISCOVER", "ENDPOINT". | 
| SymantecDLP.Incident.incidentStatusId | Number | The status ID of the incident. | 
| SymantecDLP.Incident.senderIPAddress | String | The sender IP address. | 
| SymantecDLP.Incident.policyName | String | The name of the policy. | 
| SymantecDLP.Incident.policyId | Number | The ID of the policy. | 
| SymantecDLP.Incident.endpointMachineIpAddress | String | The IP address of the endpoint machine. | 
| SymantecDLP.Incident.CustomAttribute.Name | String | The custom attribute name. | 
| SymantecDLP.Incident.CustomAttribute.Value | String | The custom attribute value. | 
| SymantecDLP.Incident.CustomAttribute.Index | Number | The custom attribute index. | 
| SymantecDLP.Incident.policyVersion | String | The version of the policy. | 
| SymantecDLP.Incident.detectionServerName | String | The name of the detection server that created the incident. | 
| SymantecDLP.Incident.policyGroupName | String | The policy group name. | 
| SymantecDLP.Incident.dataOwnerEmail | String | The email of the data owner. | 
| SymantecDLP.Incident.dataOwnerName | String | The name of the data owner. | 

#### Command example
```!symantec-dlp-get-incident-details incident_id=1 custom_attributes="custom attribute group name" custom_data="att group2"```
#### Context Example
```json
{
    "SymantecDLP": {
        "Incident": {
            "ID": 1,
            "creationDate": "2021-12-20T13:25:46.103",
            "customAttributeGroup": [
                {
                    "customAttribute": [
                        {
                            "index": 4,
                            "name": "kjv",
                            "value": "test1"
                        }
                    ],
                    "name": "att group2"
                }
            ],
            "dataOwnerEmail": "testing@gmail.com",
            "dataOwnerName": "test123",
            "detectionDate": "2021-12-20T13:25:27.56",
            "detectionServerName": "Detection - Network monitor",
            "endpointMachineIpAddress": "1.1.1.150",
            "incidentStatusId": 1,
            "matchCount": 1,
            "messageSource": "NETWORK",
            "messageType": "HTTP",
            "policyGroupName": "policy_group.default.name",
            "policyId": 2,
            "policyName": "Network Test policy",
            "policyVersion": 1,
            "senderIPAddress": "1.1.1.150",
            "severityId": "High"
        }
    }
}
```

#### Human Readable Output

>### Symantec DLP incident 1 details
>|Status|Creation Date|Detection Date|Incident Type|Policy Name|Policy Group Name|Detection Server Name|Message Type|Message Source|Data Owner Name|Data Owner Email|Custom Attributes|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 2021-12-20T13:25:46.103 | 2021-12-20T13:25:27.56 | NETWORK | Network Test policy | policy_group.default.name | Detection - Network monitor | HTTP | NETWORK | test123 | testing@gmail.com | **-**	***name***: att group2<br/>	**customAttribute**:<br/>		**-**	***name***: kjv<br/>			***value***: test1 |


### symantec-dlp-update-incident
***
Updates the details of a specific incident.


#### Base Command

`symantec-dlp-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID to update. | Required | 
| data_owner_email | The data owner email. | Optional | 
| data_owner_name | The data owner name. | Optional | 
| note | The note to be added. | Optional | 
| incident_status_id | The status ID to update to. Run `symantec-dlp-list-incident-status` to get the status ID. | Optional | 
| remediation_status_name | Represents the remediation status name of an incident. | Optional | 
| remediation_location | Represents the remediation location of the incident. Values can be user-defined. | Optional | 
| severity | Represents the severity level of the incident. Can be: "High", "Medium", "Low", and "Info". Possible values are: Info, Low, Medium, High. | Optional | 
| custom_attributes | The custom attributes to update. In order to get the custom attributes details, run `symantec-dlp-get-incident-details` command with `custom_attributes=all`<br/>Format:<br/>{columnIndex}:{newValue}<br/>E.g: 1:update, 4:att. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-dlp-update-incident incident_id=1 severity=Medium data_owner_email=testing@gmail.com custom_attributes=4:test```
#### Human Readable Output

>Symantec DLP incident 1 was updated

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
| limit | The limit of the incident history list per page. Default is 50. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.IncidentHistory.incidentHistoryDate | String | The date of the incident history. | 
| SymantecDLP.IncidentHistory.dlpUserName | String | The user name. | 
| SymantecDLP.IncidentHistory.incidentHistoryAction | String | The action of the incident history. | 
| SymantecDLP.IncidentHistory.incidentHistoryDetail | String | The incident history detail. | 
| SymantecDLP.IncidentHistory.policyGroupId | Number | The policy group ID. | 
| SymantecDLP.IncidentHistory.detectionServerName | String | The name of the detection server that created the incident. | 
| SymantecDLP.IncidentHistory.incidentHistoryId | Number | The incident history ID. | 
| SymantecDLP.IncidentHistory.messageSource | String | The localized label that corresponds to the Symantec DLP product that generated the incident. | 
| SymantecDLP.IncidentHistory.messageDate | String | The date of the message. | 
| SymantecDLP.IncidentHistory.ID | Number | The ID of the incident | 

#### Command example
```!symantec-dlp-get-incident-history limit=6 incident_id=2```
#### Context Example
```json
{
    "SymantecDLP": {
        "IncidentHistory": {
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
            ],
            "incidentId": "2"
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
| SymantecDLP.IncidentRemediationStatus.id | Number | The remediation status ID. | 
| SymantecDLP.IncidentRemediationStatus.name | String | The remediation status name. | 

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

## Known Limitations
There is an issue with DLP API where some incidents get 401 error.
For these incidents we will return missing data and in the network layout 
you will be able to see the description field that indicates about this issue.