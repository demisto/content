Symantec Data Loss Prevention enables you to discover, monitor and protect your sensitive corporate information.
This integration was integrated and tested with version 15.7 RESTful API of Symantec Data Loss Prevention.

[Check Symantec DLP 15.7 API docs](https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/information-security/data-loss-prevention/generated-pdfs/Symantec_DLP_15.7_REST_API_Guide.pdf)

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-symantec-data-loss-prevention-v2).

## Configure Symantec Data Loss Prevention v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Data Loss Prevention v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Enforce Server (For example, `https://192.168.0.1`) | True |
    | Username | True |
    | Password | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | Fetch limit | False |
    | Fetch incidents from type | False |
    | Incident Status ID | False |
    | Incident Severity | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.

## Fetch Incidents
The integration fetches incidents ordered by the creation date of the incidents.
Notice that due to creation time differences, some incidents may not be displayed in a sorted way.


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
| creation_date | The earliest time from which to get incidents. Supports ISO (For example, 2021-12-28T00:00:00Z) and free text (For example, '2 days'). | Optional | 
| status_id | The status ID of the incidents. To get status IDs, you should run the command `symantec-dlp-list-incident-status`. | Optional | 
| severity | The severity of the incidents. Can be: "High", "Medium", "Low", and "Info". Possible values are: Info, Low, Medium, High. | Optional | 
| incident_type | The incident type. Can be: "Network", "Endpoint" and "Discover". Possible values are: Network, Discover, Endpoint. | Optional | 
| limit | The limit of the incidents list per page. Default is 50. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is 1. | Optional | 
| page_size | Number of results per page to display. | Optional | 


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
Returns the details of the specified incident.


#### Base Command

`symantec-dlp-get-incident-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID for which to retrieve details. | Required | 
| custom_attributes | This argument can get the following values:<br/>all - All custom attributes are needed <br/>none - None of the custom attributes are needed<br/>specific attributes - A comma separated list of custom attributes names. For example: ca1,ca2,ca3<br/>custom attribute group name - A comma separated list of custom attributes group names. For example: cag1, cag2, cag3.<br/>This value retrieves all custom attributes in the mentioned group. The value "none" is default. Possible values are: all, none, specific attributes, custom attribute group name. Default is none. | Optional | 
| custom_data | A comma separated list of custom attributes names or custom attribute group names. For example: item1,item2,item3. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecDLP.Incident.ID | Number | The ID of the incident. | 
| SymantecDLP.Incident.creationDate | Date | The creation date of the incident. | 
| SymantecDLP.Incident.detectionDate | Date | The detection date of the incident. | 
| SymantecDLP.Incident.severity | String | The severity of the incident. | 
| SymantecDLP.Incident.messageSource | String | The localized label that corresponds to the Symantec DLP product that generated the incident. | 
| SymantecDLP.Incident.messageType | String | Indicates the Symantec DLP product that generated the incident. Can be: "NETWORK", "DISCOVER", "ENDPOINT". | 
| SymantecDLP.Incident.incidentStatusId | Number | The status ID of the incident. | 
| SymantecDLP.Incident.senderIPAddress | String | The IP address of the sender. | 
| SymantecDLP.Incident.policyName | String | The name of the policy. | 
| SymantecDLP.Incident.policyId | Number | The ID of the policy. | 
| SymantecDLP.Incident.endpointMachineIpAddress | String | The IP address of the endpoint machine. | 
| SymantecDLP.Incident.CustomAttribute.Name | String | The name of the custom attribute. | 
| SymantecDLP.Incident.CustomAttribute.Value | String | The value of the custom attribute. | 
| SymantecDLP.Incident.CustomAttribute.Index | Number | The index of the custom attribute. | 
| SymantecDLP.Incident.policyVersion | String | The version of the policy. | 
| SymantecDLP.Incident.detectionServerName | String | The name of the detection server that created the incident. | 
| SymantecDLP.Incident.policyGroupName | String | The name of the policy group. | 
| SymantecDLP.Incident.dataOwnerEmail | String | The email of the data owner. | 
| SymantecDLP.Incident.dataOwnerName | String | The name of the data owner. | 
| SymantecDLP.Incident.preventOrProtectStatusId | Number | The remediation status ID. | 
| SymantecDLP.Incident.matchCount | Number | The total number of policy violation matches produced by policies for this incident. | 

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
                            "value": "test"
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
            "preventOrProtectStatusId": 0,
            "senderIPAddress": "1.1.1.150",
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
| incident_status_id | The status ID for which to update. Run the `symantec-dlp-list-incident-status` command to get the status ID. | Optional | 
| remediation_status_name | Represents the remediation status name of an incident. | Optional | 
| remediation_location | Represents the remediation location of the incident. Values can be user-defined. | Optional | 
| severity | Represents the severity level of the incident. Can be: "High", "Medium", "Low", and "Info". Possible values are: Info, Low, Medium, High. | Optional | 
| custom_attributes | The custom attributes to update. To get the custom attributes details, run the `symantec-dlp-get-incident-details` command with the `custom_attributes=all` command.<br/>Format:<br/>{columnIndex}:{newValue}<br/>For example, 1:update, 4:att. | Optional | 


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
| limit | The limit of the incident history list per page. Default is 50. Default is 50. | Optional | 


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


## Breaking changes from the previous version of this integration - Symantec Data Loss Prevention v2

### Commands
#### The following commands were removed in this version:
* *symantec-dlp-incident-binaries*
* *symantec-dlp-incident-violations*
* *symantec-dlp-list-custom-attributes*

### Arguments
#### The following arguments were removed in this version:

In the *symantec-dlp-update-incident* command:
* *incident_id* - this argument was replaced by *incident_ids*.
* *note_time*
* *status*
* *custom_attribute_name* - this argument was replaced by *custom_attributes*.
* *custom_attribute_value* - this argument was replaced by *custom_attributes*.
* *remediation_status* - this argument was replaced by *remediation_status_name*.

#### The behavior of the following arguments was changed:

In the *symantec-dlp-update-incident* command:
  *custom_attribute_name* and *custom_attribute_value* are now used in *custom_attributes*.
  *incident_id* argument are now called *incident_ids* and can get a list of incident IDs to update.
  
### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:

*SymantecDLP.Incident.LongID*
*SymantecDLP.Incident.StatusCode* - this output was replaced by *SymantecDLP.Incident.incidentStatusIde*.
*SymantecDLP.Incident.CreationDate* - this output was replaced by *SymantecDLP.Incident.creationDate*.
*SymantecDLP.Incident.DetectionDate* - this output was replaced by *SymantecDLP.Incident.detectionDate*.
*SymantecDLP.Incident.Severity* - this output was replaced by *SymantecDLP.Incident.severity*.
*SymantecDLP.Incident.MessageSource* - this output was replaced by *SymantecDLP.Incident.messageSource*.
*SymantecDLP.Incident.MessageSourceType*
*SymantecDLP.Incident.MessageType* - this output was replaced by *SymantecDLP.Incident.messageType*.
*SymantecDLP.Incident.MessageTypeID*
*SymantecDLP.Incident.Policy.Name* - this output was replaced by *SymantecDLP.Incident.policyName*.
*SymantecDLP.Incident.Policy.Version* - this output was replaced by *SymantecDLP.Incident.policyVersion*.
*SymantecDLP.Incident.Policy.Label*
*SymantecDLP.Incident.Policy.ID* - this output was replaced by *SymantecDLP.Incident.policyId*.
*SymantecDLP.Incident.BlockedStatus*
*SymantecDLP.Incident.MatchCount* - this output was replaced by *SymantecDLP.Incident.matchCount*.
*SymantecDLP.Incident.RuleViolationCount*
*SymantecDLP.Incident.DetectionServer* - this output was replaced by *SymantecDLP.Incident.detectionServerName*.
*SymantecDLP.Incident.DataOwner.Name* - this output was replaced by *SymantecDLP.Incident.dataOwnerName*.
*SymantecDLP.Incident.DataOwner.Email* - this output was replaced by *SymantecDLP.Incident.dataOwnerEmail*.
*SymantecDLP.Incident.EventDate*
*SymantecDLP.Incident.ViolatedPolicyRule.Name*
*SymantecDLP.Incident.ViolatedPolicyRule.ID*
*SymantecDLP.Incident.OtherViolatedPolicy.Name*
*SymantecDLP.Incident.OtherViolatedPolicy.Version*
*SymantecDLP.Incident.OtherViolatedPolicy.Label*
*SymantecDLP.Incident.OtherViolatedPolicy.ID*


## Additional Considerations for this version
There is an issue with DLP API where some incidents get a 401 error.
For these incidents, the missing data is returned. From the Network incident layout, in the description field you can see information about this issue.
