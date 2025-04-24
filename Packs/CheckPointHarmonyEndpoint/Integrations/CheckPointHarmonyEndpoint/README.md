Checkpoint Harmony Endpoint provides a complete endpoint security solution built to protect organizations and the remote workforce from today's complex threat landscape.
This integration was integrated and tested with version 1 of CheckPointHarmonyEndpoint.

## Configure Check Point Harmony Endpoint in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base URL | True |
| Client ID | True |
| Secret Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### harmony-ep-job-status-get

***
Retrieves the status and result (if any) of a given asynchronous operation. A job is a way to monitor the progress of an asynchronous operation while avoiding issues that may manifest during long synchronous waits.

#### Base Command

`harmony-ep-job-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the operation to query the status of. Job ID will returned from most of the commands in this integration. It can be found in the context path. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.Job.data | String | The job data. | 
| HarmonyEP.Job.status | String | The job status. | 

#### Command example
```!harmony-ep-job-status-get23```
#### Context Example
```json
{
    "HarmonyEP": {
        "Job": {
            "data": {
                "data": [
                    {
                        "machine": {
                            "id": "1",
                            "name": "DESKTOP-1"
                        },
                        "operation": {
                            "response": null,
                            "status": "DA_NOT_INSTALLED"
                        }
                    },
                    {
                        "machine": {
                            "id": "2",
                            "name": "DESKTOP-2"
                        },
                        "operation": {
                            "response": null,
                            "status": "DA_NOT_INSTALLED"
                        }
                    }
                ],
                "metadata": {
                    "count": 2,
                    "from": 0,
                    "to": 100
                }
            },
            "status": "DONE",
            "statusCode": 200,
            "statusType": 2
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|status|statusCode|statusType|
>|---|---|---|---|
>| data: {'machine': {'id': '1', 'name': 'DESKTOP-1'}, 'operation': {'response': None, 'status': 'DA_NOT_INSTALLED'}},<br/>{'machine': {'id': '2', 'name': 'DESKTOP-2'}, 'operation': {'response': None, 'status': 'DA_NOT_INSTALLED'}}<br/>metadata: {"from": 0, "to": 100, "count": 2} | DONE | 200 | 2 |


### harmony-ep-ioc-list

***
Gets a list of all Indicators of Compromise. Use the filter parameters to fetch specific IOCs.

#### Base Command

`harmony-ep-ioc-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The indicator value or comment to search for. The filter is case-insensitive. For example, filter 'efg will match IoCs 'abcdEFG', 'efGGG', and 'yEfG'. | Optional | 
| field | The Indicator of Compromise field to search by. Possible values are: iocValue, iocComment. Default is iocValue. | Optional | 
| sort_direction | The way to sort the results. Possible values are: ASC, DESC. Default is DESC. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.IOC.comment | String | The IOC comment. | 
| HarmonyEP.IOC.modifiedOn | Number | The time the IOC was modified. | 
| HarmonyEP.IOC.value | String | The IOC value. | 
| HarmonyEP.IOC.type | String | The IOC type. | 
| HarmonyEP.IOC.id | String | The IOC ID. | 

#### Command example
```!harmony-ep-ioc-list```
#### Context Example
```json
{
    "HarmonyEP": {
        "IOC": [
            {
                "comment": "test",
                "id": "3",
                "modifiedOn": "2024-04-03T09:15:04.182Z",
                "type": "Domain",
                "value": "test2.com"
            },
            {
                "comment": "comment",
                "id": "4",
                "modifiedOn": "2024-05-20T13:14:28.290Z",
                "type": "Domain",
                "value": "test1.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### IOC List:
>Showing page 1.
>Current page size: 50.
>|Id|Type|Value|Comment|Modifiedon|
>|---|---|---|---|---|
>| 3 | Domain | test2.com | test | 2024-04-03T09:15:04.182Z |
>| 4 | Domain | test1.com | comment | 2024-05-20T13:14:28.290Z |


### harmony-ep-ioc-update

***
Updates the given Indicators of Compromise with the given parameters.

#### Base Command

`harmony-ep-ioc-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to update. Use harmony-ep-ioc-list command to get all IOC IDs. | Required | 
| comment | The IOC comment to update. | Required | 
| value | The IOC value to update. | Required | 
| type | The IOC type to update. Possible values are: Domain, IP, URL, MD5, SHA1. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.IOC.comment | String | The IOC comment. | 
| HarmonyEP.IOC.modifiedOn | Number | The time the IOC was modified. | 
| HarmonyEP.IOC.value | String | The IOC value. | 
| HarmonyEP.IOC.type | String | The IOC type. | 
| HarmonyEP.IOC.id | String | The IOC ID. | 

#### Command example
```!harmony-ep-ioc-update ioc_id=8 comment=test value=8.8.8.8 type=IP```
#### Context Example
```json
{
    "HarmonyEP": {
        "IOC": {
            "comment": "test",
            "id": "8",
            "modifiedOn": "2024-06-24T06:44:49.214Z",
            "type": "IP",
            "value": "8.8.8.8"
        }
    }
}
```

#### Human Readable Output

>### IOC 8 was updated successfully.
>|Id|Type|Value|Comment|Modifiedon|
>|---|---|---|---|---|
>| 8 | IP | 8.8.8.8 | test | 2024-06-24T06:44:49.214Z |


### harmony-ep-ioc-create

***
Creates new Indicators of Compromise using the given parameters.

#### Base Command

`harmony-ep-ioc-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | The IOC comment. | Required | 
| value | The IOC value. For example, 8.8.8.8 for IP or example.com for Domain. | Required | 
| type | The IOC type. Possible values are: Domain, IP, URL, MD5, SHA1. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!harmony-ep-ioc-create comment=test value=1.1.1.2 type=IP```
#### Human Readable Output

>IOC was created successfully.

### harmony-ep-ioc-delete

***
Deletes the given Indicators of Compromise by their ID.

#### Base Command

`harmony-ep-ioc-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A A comma-separated list of list of IOC IDs to delete. Use harmony-ep-ioc-list command to get all IOC IDs. | Optional | 
| delete_all | Whether to delete all IOCs. This action permanently deletes all Indicators of Compromise and cannot be undone. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!harmony-ep-ioc-delete ids=7```
#### Human Readable Output

>IOCs 7 was deleted successfully.

### harmony-ep-policy-rule-assignments-get

***
Gets all entities directly assigned to the given rule.

#### Base Command

`harmony-ep-policy-rule-assignments-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule to get the assignments. Use harmony-ep-rule-metadata-list command to get all rule IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.Rule.Assignments.type | String | The rule assignment type. | 
| HarmonyEP.Rule.Assignments.name | String | The rule assignment name. | 
| HarmonyEP.Rule.Assignments.id | String | The rule assignment ID. | 

#### Command example
```!harmony-ep-policy-rule-assignments-get rule_id=1a2b ```
#### Context Example
```json
{
    "HarmonyEP": {
        "Rule": {
            "assignments": [
                {
                    "id": "456",
                    "name": "ChromeOsLaptops",
                    "type": "VIRTUAL_GROUP"
                }
            ],
            "id": "1a2b"
        }
    }
}
```

#### Human Readable Output

>### Rule 1a2b assignments:
>|Id|Name|Type|
>|---|---|---|
>| 456 | ChromeOsLaptops | VIRTUAL_GROUP |


### harmony-ep-policy-rule-assignments-add

***
Assigns the specified entities to the given rule. Specified IDs that are already assigned to the rule are ignored.

#### Base Command

`harmony-ep-policy-rule-assignments-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule to add assignments to. Use harmony-ep-rule-metadata-list command to get all rule IDs. | Required | 
| entities_ids | The entity IDs to assign. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!harmony-ep-policy-rule-assignments-add rule_id=1a2b entities_ids=000```
#### Human Readable Output

>Entities ['000'] were assigned to rule 1a2b successfully.

### harmony-ep-policy-rule-assignments-remove

***
Removes the specified entities from the given rule's assignments. Specified IDs that are not assigned to the rule are ignored.

#### Base Command

`harmony-ep-policy-rule-assignments-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule to remove assignments from. Use harmony-ep-rule-metadata-list command to get all rule IDs. | Required | 
| entities_ids | The entity IDs to remove. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!harmony-ep-policy-rule-assignments-remove rule_id=1a2b entities_ids=000```
#### Human Readable Output

>Entities ['000'] were removed from rule 1a2b successfully.

### harmony-ep-policy-rule-install

***
Installs all policies.

#### Base Command

`harmony-ep-policy-rule-install`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.PolicyRuleInstall.job_id | String | The job ID of the policy installation. | 

#### Command example
```!harmony-ep-policy-rule-install job_id=976```
#### Context Example
```json
{
    "HarmonyEP": {
        "PolicyRuleInstall": {
            "job_id": "976"
        }
    }
}
```

#### Human Readable Output

>### Policy was installed successfully.
>Job ID: 976
>**No entries.**


### harmony-ep-policy-rule-modifications-get

***
Gets information on modifications to a given rule. (Modifications are the additions or removal of assignments on a rule since it was last installed).

#### Base Command

`harmony-ep-policy-rule-modifications-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule to get the modifications of. Use harmony-ep-rule-metadata-list command to get all rule IDs. | Required | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.Rule.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.Rule.order | Number | Rule order. | 
| HarmonyEP.Rule.isDefaultRule | Boolean | Whether or not the rule is the default. | 
| HarmonyEP.Rule.family | String | A family in the rule-base \(legacy and unified\). | 
| HarmonyEP.Rule.connectionState | String | Rule connection state. | 
| HarmonyEP.Rule.comment | String | Rule comment. | 
| HarmonyEP.Rule.assignments.type | String | Rule assignments type. | 
| HarmonyEP.Rule.assignments.name | String | Rule assignments name. | 
| HarmonyEP.Rule.assignments.id | String | Rule assignments ID. | 
| HarmonyEP.Rule.name | String | Rule name. | 
| HarmonyEP.Rule.id | String | Rule ID. | 
| HarmonyEP.Rule.orientation | String | Rule policy orientation. | 

#### Command example
```!harmony-ep-policy-rule-modifications-get rule_id=1a2b job_id=999```
#### Context Example
```json
{
    "HarmonyEP": {
        "Rule": {
            "connectionState": "CONNECTED",
            "family": "Access",
            "id": "1a2b",
            "job_id": "999",
            "lastModifiedBy": "talg",
            "lastModifiedOn": {
                "iso-8601": "2024-06-24T09:04:43.000Z",
                "posix": 1719219883000
            },
            "modified": {
                "assignments": {
                    "modified": false
                },
                "order": {
                    "modified": false
                },
                "settings": {
                    "modified": true
                }
            },
            "name": "New Rule 1"
        }
    }
}
```

#### Human Readable Output

>### Rule 1a2b modification:
>Job ID: 999
>|Id|Name|Family|Connectionstate|Lastmodifiedby|Job Id|
>|---|---|---|---|---|---|
>| 1a2b | New Rule 1 | Access | CONNECTED | talg | 999 |


### harmony-ep-policy-rule-metadata-list

***
Gets the metadata of all rules or the given rule's metadata. (Metadata refers to all information relating to the rule except it's actual settings).

#### Base Command

`harmony-ep-policy-rule-metadata-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule to get the metadata. | Optional | 
| rule_family | An optional 'Rule Family' filter. Used to filter the results to only the selected rule family (e.g., only 'Threat Prevention'). Possible values are: General Settings, Threat Prevention, Data Protection, OneCheck, Deployment, Remote Access VPN, Capsule Docs, Access, Agent Settings. | Optional | 
| connection_state | An optional 'Connection State' filter. Used to filter the results to only the selected Connection State (e.g., only rules pertaining to policies for connected clients). Possible values are: CONNECTED, DISCONNECTED, RESTRICTED. | Optional | 
| limit | The maximum number of IP lists to return. Default is 50. | Optional | 
| all_results | Whether to return all of the results or not. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.Rule.order | Number | Rule order. | 
| HarmonyEP.Rule.isDefaultRule | Boolean | Whether or not the rule is the default. | 
| HarmonyEP.Rule.family | String | A family in the rule-base \(legacy and unified\). | 
| HarmonyEP.Rule.connectionState | String | Rule connection state. | 
| HarmonyEP.Rule.comment | String | Rule comment. | 
| HarmonyEP.Rule.assignments.type | String | Rule assignments type. | 
| HarmonyEP.Rule.assignments.name | String | Rule assignments name. | 
| HarmonyEP.Rule.assignments.id | String | Rule assignments ID. | 
| HarmonyEP.Rule.name | String | Rule name. | 
| HarmonyEP.Rule.id | String | Rule ID. | 
| HarmonyEP.Rule.orientation | String | Rule policy orientation. | 

#### Command example
```!harmony-ep-policy-rule-metadata-list rule_id=1a2b```
#### Context Example
```json
{
    "HarmonyEP": {
        "Rule": {
            "assignments": [
                {
                    "id": "000",
                    "name": "Entire Organization",
                    "type": "ORGANIZATION_ROOT"
                },
                {
                    "id": "456",
                    "name": "ChromeOsLaptops",
                    "type": "VIRTUAL_GROUP"
                }
            ],
            "comment": "",
            "connectionState": "CONNECTED",
            "family": "Threat Prevention",
            "id": "1a2b",
            "isDefaultRule": true,
            "name": "TalTest",
            "order": 2,
            "orientation": "DEVICE"
        }
    }
}
```

#### Human Readable Output

>### Rule 1a2b metadata:
>|Id|Name|Family|Comment|Orientation|Connectionstate|Assignments|
>|---|---|---|---|---|---|---|
>| 1a2b | TalTest | Threat Prevention |  | DEVICE | CONNECTED | {'id': '000', 'name': 'Entire Organization', 'type': 'ORGANIZATION_ROOT'},<br/>{'id': '456', 'name': 'ChromeOsLaptops', 'type': 'VIRTUAL_GROUP'} |


### harmony-ep-push-operation-status-list

***
Gets the current statuses of all remediation operations or if a specific ID is specified, retrieve the current status of the given remediation operation.

#### Base Command

`harmony-ep-push-operation-status-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remediation_operation_id | Remediation operations ID. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.PushOperation.adminName | String | The name of the administrator who initiated the operation. | 
| HarmonyEP.PushOperation.aborted | Boolean | Indicated whether the operation was aborted by an administrator. | 
| HarmonyEP.PushOperation.remainingTimeoutSeconds | Number | The amount of time, in seconds, the operation will remain active. When elapsed, no more entities will be affected. | 
| HarmonyEP.PushOperation.createdOn | Date | The date and time the operation was created. | 
| HarmonyEP.PushOperation.type | String | Remediation operation type. | 
| HarmonyEP.PushOperation.comment | String | A comment that was provided during the operation's creation. | 
| HarmonyEP.PushOperation.id | String | The operation's ID. | 
| HarmonyEP.PushOperation.overallStatus | String | Remediation operation status. | 
| HarmonyEP.PushOperation.numberOfAffectedEntities | Number | The total number of entities affected by the operation. | 

#### Command example
```!harmony-ep-push-operation-status-list remediation_operation_id=4d```
#### Context Example
```json
{
    "HarmonyEP": {
        "PushOperation": {
            "aborted": true,
            "adminName": "talg",
            "createdOn": "2024-06-20T10:58:19.407Z",
            "id": "d45",
            "job_id": "3",
            "numberOfAffectedEntities": 6,
            "operationParameters": {
                "allowPostpone": false,
                "informUser": true,
                "originalTimeoutSeconds": 86400,
                "schedulingType": "IMMEDIATE"
            },
            "overallStatus": "ABORTED",
            "remainingTimeoutSeconds": 0,
            "type": "AM_SCAN"
        }
    }
}
```

#### Human Readable Output

>### Push operations status list:
>Job ID: 3
>|Id|Type|Createdon|Overallstatus|
>|---|---|---|---|
>| d45 | AM_SCAN | 2024-06-20T10:58:19.407Z | ABORTED |


### harmony-ep-push-operation-get

***
Gets the results of a given Remediation Operation. Remediation Operations may produce results such a Forensics Report or yield status updates such as an anti-malware scan progress.

#### Base Command

`harmony-ep-push-operation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remediation_operation_id | Remediation operation ID. Use the harmony-ep-remediation-status-list command to get all remediation operation IDs. | Required | 
| filter_text | Optional free text search in any of the potential response fields excluding "id". Can be used to search for specific results, devices or IPs, for example. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-push-operation-get remediation_operation_id=4d```
#### Context Example
```json
{
    "HarmonyEP": {
        "PushOperation": [
            {
                "job_id": "6",
                "machine": {
                    "id": "5s",
                    "name": "DESKTOP-M4OAKII"
                },
                "operation": {
                    "id": null,
                    "response": null,
                    "status": "DA_NOT_INSTALLED"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Push operations:
>Job ID: 6
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 5s | DESKTOP-M4OAKII | DA_NOT_INSTALLED |


### harmony-ep-push-operation-abort

***
Aborts the given remediation operation. Aborting an operation prevents it from being sent to further Harmony Endpoint Clients. Clients that have already received the operation are not affected.

#### Base Command

`harmony-ep-push-operation-abort`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remediation_operation_id | Remediation operation ID. Use the harmony-ep-remediation-status-list command to get all remediation operation IDs. | Required | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.PushOperationAbort.job_id | String | The job ID of the remediation operation. | 

#### Command example
```!harmony-ep-push-operation-abort remediation_operation_id=93 job_id=976```
#### Context Example
```json
{
    "HarmonyEP": {
        "PushOperationAbort": {
            "job_id": "976"
        }
    }
}
```

#### Human Readable Output

>### Remediation operation abort was added to the push operation list successfully.
>Job ID: 976
>**No entries.**


### harmony-ep-anti-malware-scan

***
Performs an anti-malware scan on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-anti-malware-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.AntiMalwareScan.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.AntiMalwareScan.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.AntiMalwareScan.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.AntiMalwareScan.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.AntiMalwareScan.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.AntiMalwareScan.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.AntiMalwareScan.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.AntiMalwareScan.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-anti-malware-scan computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "AntiMalwareScan": {
            "PushOperation": [
                {
                    "job_id": "13",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Anti-Malware scan was added to the push operation list successfully.
>Job ID: 13
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-anti-malware-update

***
Updates the anti-malware Signature Database on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-anti-malware-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| update_from_ep_server | Determines whether to update from the EP server. Possible values are: true, false. Default is false. | Optional | 
| update_from_cp_server | Determines whether to update from the CP server. Possible values are: true, false. Default is false. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.AntiMalwareUpdate.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.AntiMalwareUpdate.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-anti-malware-update computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "AntiMalwareUpdate": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Anti-Malware Signature Database update was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-anti-malware-restore

***
Restores a file that was previously quarantined by the Harmony Endpoint Client's anti-malware capability. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-anti-malware-restore`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| files | A list of file paths to restore. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.AntiMalwareRestore.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.AntiMalwareRestore.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-anti-malware-restore files=test computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "AntiMalwareRestore": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### File restore was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-forensics-indicator-analyze

***
Collects forensics data whenever a computer that matches the given query accesses or executes the given IP, URL, filename, MD5 or path. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-forensics-indicator-analyze`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indictor type to analyze. Possible values are: IP, URL, File, MD5, Path. | Required | 
| indicator_value | A URL, IP, Path, File or MD5 that when accessed or executed will trigger a forensics report. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| generate_activity_logs | Determines whether to generate detailed activity logs. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.IndicatorAnalyze.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.IndicatorAnalyze.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-forensics-indicator-analyze indicator_type=IP indicator_value=8.8.8.8 computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "IndicatorAnalyze": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### IOC analyze was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-forensics-file-quarantine

***
Quarantines files given by path or MD5 or detections relating to a forensic incident. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-forensics-file-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_type | The forensics quarantine item type. Possible values are: PATH, INCIDENT_ID, MD5. | Required | 
| file_value | The forensics quarantine item value. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.FileQuarantine.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.FileQuarantine.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.FileQuarantine.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.FileQuarantine.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.FileQuarantine.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.FileQuarantine.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.FileQuarantine.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.FileQuarantine.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-forensics-file-quarantine file_type=PATH file_value=test computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "FileQuarantine": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### File quarantine was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-forensics-file-restore

***
Restores previously quarantined files given by path or MD5 or detections relating to a forensic incident. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-forensics-file-restore`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_type | The forensics quarantine item type. Possible values are: PATH, INCIDENT_ID, MD5. | Required | 
| file_value | The forensics quarantine item value. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.FileRestore.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.FileRestore.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.FileRestore.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.FileRestore.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.FileRestore.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.FileRestore.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.FileRestore.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.FileRestore.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-forensics-file-restore file_type=PATH file_value=test computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "FileRestore": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### File restore was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-remediation-computer-isolate

***
Isolates the computers matching the given query. Isolation is the act of denying all network access from a given computer. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-remediation-computer-isolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ComputerIsolate.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ComputerIsolate.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ComputerIsolate.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ComputerIsolate.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ComputerIsolate.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ComputerIsolate.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ComputerIsolate.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ComputerIsolate.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-remediation-computer-isolate computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ComputerIsolate": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Remediation isolate was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-remediation-computer-deisolate

***
De-Isolates the computers matching the given query. De-isolating a computer restores its access to network resources. Affects only isolated computers. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-remediation-computer-deisolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ComputerDeisolate.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ComputerDeisolate.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ComputerDeisolate.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ComputerDeisolate.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ComputerDeisolate.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ComputerDeisolate.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ComputerDeisolate.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ComputerDeisolate.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-remediation-computer-deisolate computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ComputerDeisolate": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Remediation de-isolate was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-computer-restart

***
Restarts computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-computer-restart`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| force_apps_shutdown | Determines whether to force applications shutdown. Possible values are: true, false. Default is false. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ComputerRestart.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ComputerRestart.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ComputerRestart.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ComputerRestart.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ComputerRestart.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ComputerRestart.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ComputerRestart.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ComputerRestart.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-computer-restart computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ComputerReset": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Computer reset restore was added to the push operation list successfully.
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-computer-shutdown

***
Shuts-down computers match the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-computer-shutdown`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| force_apps_shutdown | Determines whether to force applications shutdown. Possible values are: true, false. Default is false. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ComputerShutdown.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ComputerShutdown.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ComputerShutdown.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ComputerShutdown.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ComputerShutdown.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ComputerShutdown.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ComputerShutdown.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ComputerShutdown.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-computer-shutdown computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ComputerShutdown": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Computer shutdown was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-computer-repair

***
Repairs the Harmony Endpoint Client installation on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-computer-repair`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ComputerRepair.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ComputerRepair.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ComputerRepair.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ComputerRepair.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ComputerRepair.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ComputerRepair.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ComputerRepair.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ComputerRepair.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-computer-repair computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ComputerRepair": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Computer repair was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-computer-list

***
Gets a list of computers matching the given filters. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-computer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.Computer.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.Computer.CapabilitiesInstalled | String | A list of all installed capabilities. | 
| HarmonyEP.Computer.InstalledAndRunning | String | A list of installed and running capabilities. | 
| HarmonyEP.Computer.ClientVersion | String | The computer client version. | 
| HarmonyEP.Computer.DeployTime | String | The computer deploy time. | 
| HarmonyEP.Computer.Groups | String | The computer groups. | 
| HarmonyEP.Computer.type | String | The computer type. | 
| HarmonyEP.Computer.userName | String | The computer user name. | 
| HarmonyEP.Computer.domainName | String | The computer domain name. | 
| HarmonyEP.Computer.isolationStatus | String | The computer isolation status. | 
| HarmonyEP.Computer.ClientVersion | String | The computer client veraion. | 
| HarmonyEP.Computer.LastLoggedInUser | String | The computer last login user. | 
| HarmonyEP.Computer.osName | String | The computer operating system name. | 
| HarmonyEP.Computer.osVersion | String | The computer operating system version. | 
| HarmonyEP.Computer.ip | String | The computer IP address. | 
| HarmonyEP.Computer.DeploymentStatus | String | The computer deployment status. | 
| HarmonyEP.Computer.name | String | The computer name. | 
| HarmonyEP.Computer.id | String | The computer's unique ID. | 

#### Command example
```!harmony-ep-computer-list computer_ids=1 job_id=845```
#### Context Example
```json
{
    "HarmonyEP": {
        "Computer": {
            "Computer": [
                {
                    "client_version": "87.62.2002",
                    "deployment_status": "Completed",
                    "domain_name": ".WORKGROUP",
                    "groups": [
                        {
                            "id": "666",
                            "name": "Desktops"
                        },
                        {
                            "id": "222",
                            "name": "WinDesktops"
                        }
                    ],
                    "id": "888",
                    "ip": "1.1.1.1",
                    "isolation_status": "Not Isolated",
                    "last_logged_in_user": "ntlocal",
                    "name": "DESKTOP-E7V07D5",
                    "os_name": "Microsoft Windows 10 Pro",
                    "os_version": "10.0-19045-SP0.0-SMP",
                    "type": "Desktop",
                    "user_name": "ntlocal"
                }
            ],
            "job_id": "845"
        }
    }
}
```

#### Human Readable Output

>### Computer list:
>Job ID: 845
>
>Showing page 1.
>Current page size: 50.
>|Id|Name|Ip|Type|Groups|User Name|Client Version|
>|---|---|---|---|---|---|---|
>| 888 | DESKTOP-E7V07D5 | 1.1.1.1 | Desktop | {'id': '666', 'name': 'Desktops'},<br/>{'id': '222', 'name': 'WinDesktops'} | ntlocal | 87.62.2002 |


### harmony-ep-agent-process-information-get

***
Collects information about processes on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-process-information-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_name | The name of the process to collect information on. If not provided, all running processes will be collected. | Optional | 
| additional_fields | Additional process properties to collect. If not provided, only the process's name and ID will be collected. Possible values are: SI, Handles, VM, WS, PM, NPM, Path, CPU, ExitCode, ExitTime, Handle, HandleCount, HasExited, Id, MachineName, MainModule, MainWindowHandle, MainWindowTitle, MaxWorkingSet, MinWorkingSet, Modules, NonpagedSystemMemorySize, NonpagedSystemMemorySize64, PagedMemorySize, PagedMemorySize64, PagedSystemMemorySize, PagedSystemMemorySize64, PeakPagedMemorySize, PeakPagedMemorySize64, PeakVirtualMemorySize, PeakVirtualMemorySize64, PeakWorkingSet, PeakWorkingSet64, PriorityBoostEnabled, PriorityClass, PrivateMemorySize, PrivateMemorySize64, PrivilegedProcessorTime, ProcessName, ProcessorAffinity, Responding, SafeHandle, SessionId, StandardError, StandardInput, StandardOutput, StartInfo, StartTime, SynchronizingObject, Threads, TotalProcessorTime, UserProcessorTime, VirtualMemorySize, VirtualMemorySize64, WorkingSet, WorkingSet64. | Optional | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ProcessInformation.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ProcessInformation.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ProcessInformation.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ProcessInformation.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ProcessInformation.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ProcessInformation.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ProcessInformation.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ProcessInformation.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-process-information-get computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ProcessInformation": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Process information fetch was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-process-terminate

***
Terminates the given process on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-process-terminate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| terminate_all_instances | Indicates whether to terminate all processes matching the given name. If set to true while a non-zero PID is given, only a single process with the given name AND PID may be matched. If set to false or not provided, will terminate only the first matching process. Possible values are: true, false. Default is false. | Optional | 
| name | The name of the process to terminate. | Required | 
| pid | The ID (PID) of the process to terminate. When used in conjunction with the name field, the PID must match the named process. If both name and PID are provided but the process matching the PID does not match the provided name, the operation will be ignored by the agent. If set to 0 or not provided, the agent will seek to terminate the process or processes as indicated by the name field. | Optional | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.ProcessTerminate.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.ProcessTerminate.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.ProcessTerminate.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.ProcessTerminate.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.ProcessTerminate.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.ProcessTerminate.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.ProcessTerminate.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.ProcessTerminate.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-process-terminate name=test computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "ProcessTerminate": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Process terminate was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-registry-key-add

***
Adds a given registry key and/or value to the registry of computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-registry-key-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| is_redirected | Determines if the key should reside under WOW6432Node. Keys intended for 64bit versions of Windows may target 32bit versions by setting this value to 'true, thus specifying that the registry key/value be added under the WOW6432Node. Possible values are: true, false. | Optional | 
| value_data | The actual value to be added the the specified registry key. | Required | 
| value_type | A registry value's type. Possible values are: DWORD (REG_DWORD), STRING (REG_GZ). | Required | 
| value_name | The name of the value to be added to the specified registry key. | Required | 
| key | The full path path of the key to create or add a value to. For example, 'SOFTWARE\Node.js\Components'. | Required | 
| hive | Defines known Windows Registry Hives. For more information, see https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys. Possible values are: HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.RegistryKeyAdd.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.RegistryKeyAdd.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-registry-key-add value_data=test value_type="STRING (REG_GZ)" value_name=test key=test hive=HKEY_USERS computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "RegistryKeyAdd": {
            "PushOperation": {
                "job_id": "54",
                "machine": {
                    "id": "1",
                    "name": "DESKTOP-1"
                },
                "operation": {
                    "id": "88",
                    "response": null,
                    "status": "DA_NOT_INSTALLED"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Registry key add was added to the push operation list successfully..
>Job ID: 54
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |

### harmony-ep-agent-registry-key-delete

***
Removes the given registry key or value to the registry of computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-registry-key-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| is_redirected | Determines if the key should be removed from under WOW6432Node. Keys intended for 64bit versions of Windows may target 32bit versions by setting this value to 'true', thus specifying that the registry key/value be removed under the WOW6432Node. Possible values are: true, false. | Optional | 
| value_name | The value to remove from the key. If not provided, the entire key will be deleted. | Optional | 
| key | The full path path of the key to delete or remove a value from. For example, 'SOFTWARE\Node.js\Components'. | Required | 
| hive | Defines known Windows Registry Hives. For more information, see https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys. Possible values are: HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.RegistryKeyDelete.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.RegistryKeyDelete.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-registry-key-delete value_name='test' key='test' hive=HKEY_USERS computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "RegistryKeyDelete": {
            "PushOperation": {
                "job_id": "54",
                "machine": {
                    "id": "1",
                    "name": "DESKTOP-1"
                },
                "operation": {
                    "id": "88",
                    "response": null,
                    "status": "DA_NOT_INSTALLED"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Registry key delete was added to the push operation list successfully..
>Job ID: 54
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |


### harmony-ep-agent-file-copy

***
Copies the given file from the given source to the given destination on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-file-copy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_absolute_path | The absolute, full destination path. The provided path must include the target file's name (e.g., c:\backup\backup1.txt). | Required | 
| source_absolute_path | The absolute, full source path (e.g., c:\backup\backup1.txt). | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.FileCopy.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.FileCopy.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.FileCopy.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.FileCopy.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.FileCopy.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.FileCopy.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.FileCopy.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.FileCopy.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-file-copy destination_absolute_path='test.txt' source_absolute_path='test.txt' computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "FileCopy": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### File copy was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-file-move

***
Moves the given file from the given source to the given destination on computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-file-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_absolute_path | The absolute, full destination path. The provided path must include the target file's name (e.g., c:\backup\backup1.txt). | Required | 
| source_absolute_path | The absolute, full source path (e.g., c:\backup\backup1.txt). | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.FileMove.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.FileMove.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.FileMove.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.FileMove.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.FileMove.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.FileMove.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.FileMove.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.FileMove.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-file-move destination_absolute_path='test.txt' source_absolute_path='test.txt' computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "FileMove": [
            {
                "job_id": "16",
                "machine": {
                    "id": "1",
                    "name": "DESKTOP-1"
                },
                "operation": {
                    "id": null,
                    "response": null,
                    "status": "DA_NOT_INSTALLED"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### File move was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-file-delete

***
Deletes the given file from the given source on computers matching the given query. This operation is risky! Use with caution as it allows you to change Harmony Endpoint protected files or registry entries that are in use by your operating system. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_absolute_path | The absolute, full path of the file to remove. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.FileDelete.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.FileDelete.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.FileDelete.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.FileDelete.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.FileDelete.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.FileDelete.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.FileDelete.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.FileDelete.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-file-delete target_absolute_path='test.txt' computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "FileDelete": {
            "PushOperation": [
                {
                    "job_id": "16",
                    "machine": {
                        "id": "1",
                        "name": "DESKTOP-1"
                    },
                    "operation": {
                        "id": null,
                        "response": null,
                        "status": "DA_NOT_INSTALLED"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### File delete was added to the push operation list successfully..
>Job ID: 16
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-vpn-site-add

***
 Adds the given VPN site's configuration to computers matching the given query. Adding a VPN site allows Harmony Endpoint Clients to connect to it. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-vpn-site-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remote_access_gateway_name | The remote gateway's name. | Required | 
| fingerprint | The remote gateway's certificate fingerprint. Fingerprints are used to verify the authenticity of the gateway. | Required | 
| authentication_method | Authentication methods used in conjunction with VPN site standard login. Possible values are: CERTIFICATE, P12_CERTIFICATE, USERNAME_PASSWORD, SECURID_KEY_FOB, SECURID_PIN_PAD, SOFTID, CHALLENGE_RESPONSE. | Required | 
| display_name | The VPN site's display name. | Optional | 
| host | The target site's host name or IP address. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.VPNsiteConfigurationAdd.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-vpn-site-add remote_access_gateway_name='test' fingerprint='test' authentication_method=CERTIFICATE host='test' computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "VPNsiteConfigurationAdd": {
            "PushOperation": {
                "job_id": "67",
                "machine": {
                    "id": "1",
                    "name": "DESKTOP-1"
                },
                "operation": {
                    "id": "23",
                    "response": null,
                    "status": "DA_NOT_INSTALLED"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### VPN site configuration remove was added to the push operation list successfully..
>Job ID: 67
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |



### harmony-ep-agent-vpn-site-remove

***
Removes the given VPN site's configuration to computers matching the given query. Note that you must specify at least one of the following filter arguments: computer_ids, computer_names, computer_ips, computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter. 

#### Base Command

`harmony-ep-agent-vpn-site-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The display name of the VPN site to remove. If a display name was not provided during the site's creation, the host name/IP should be used instead. | Required | 
| comment | Operation comment. | Optional | 
| scheduling_date_time | Start the operation on a given date and time. If not specified, defaults to 'Now' (i.e. immediate execution). For example, “2024-04-12 03:59”. | Optional | 
| expiration_seconds | The amount of time, in seconds, the operation will be valid for. When the specified time has elapsed, the operation will expire and will not be pushed to any more clients. If not specified, defaults to 86400 seconds (24 hours). Minimum value is 1. | Optional | 
| computer_ids | A comma-separated list of computer IDs to include in the operation. | Optional | 
| computer_names | A comma-separated list of computer names to include in the operation. | Optional | 
| computer_ips | A comma-separated list of computer IPs to include in the operation. | Optional | 
| computer_types | A comma-separated list of computer types to include in the operation. Possible values are: Desktop, Laptop, N/A, Domain Controller, Server. | Optional | 
| computer_deployment_statuses | A comma-separated list of computer deployment statuses to include in the operation. Possible values are: Retrying, Error, Scheduled, Downloading, Deploying, Completed, Failed, Uninstalling, Not Scheduled, Not Installed, N/A. | Optional | 
| computer_last_connection | Computer last connection range time (start time, end time) to include in the operation. For example, "2024-01-01 07:58, 2024-04-02 02:00”. | Optional | 
| filter | A comma-separated list of list of search filters according to the following template: "column_name operator 'values_list' ".  For example, the query "computerId Contains '1,2,3,4' , computerIP Exact '1.1.1.1' " will refer to computers contains '1', '2', '3', and '4'  in their ID and that their IP is '1.1.1.1'. For more optional 'column_name' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/ComputerColumnNames. For more optional 'operator' values, see https://app.swaggerhub.com/apis/Check-Point/web-mgmt-external-api-production/1.9.179#/FilterType . | Optional | 
| groups_ids_to_exclude | A comma-separated list of group IDs to exclude from the operation. | Optional | 
| computers_ids_to_exclude | A comma-separated list of computer IDs to exclude from the operation. | Optional | 
| computers_ids_to_include | A comma-separated list of computer IDs to include in the operation. | Optional | 
| inform_user | Determines whether to inform the user, via a UserCheck (popup) message, that the operation is taking place. Possible values are: true, false. Default is true. | Optional | 
| allow_postpone | Determines whether to allow the user to postpone the operation. Possible values are: true, false. Default is true. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional | 
| page_size | The number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| interval | The interval between each poll in seconds. Minimum value is `10`. Default is 30. | Optional | 
| timeout | The timeout for the polling in seconds. Default is 600. | Optional | 
| job_id | The job ID to fetch data for. Hidden argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.job_id | String | The job ID of the remediation operation. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.id | String | The remediation operation ID. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.status | String | Describes possible states in which a push operation may be in regards to a specific device. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.response.status | String | Push operation response status. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.response.output | String | Push operation response output. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.machine.ipAddress | String | The client device's IPv4 address. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.machine.name | String | The client device's name. | 
| HarmonyEP.VPNsiteConfigurationRemove.PushOperation.machine.id | String | The client device's unique ID. | 

#### Command example
```!harmony-ep-agent-vpn-site-remove display_name='test' computer_ids=1```
#### Context Example
```json
{
    "HarmonyEP": {
        "VPNsiteConfigurationRemove": {
            "PushOperation": {
                "job_id": "67",
                "machine": {
                    "id": "1",
                    "name": "DESKTOP-1"
                },
                "operation": {
                    "id": "23",
                    "response": null,
                    "status": "DA_NOT_INSTALLED"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### VPN site configuration remove was added to the push operation list successfully..
>Job ID: 67
>
>Showing page 1.
>Current page size: 50.
>|Machine Id|Machine Name|Operation Status|
>|---|---|---|
>| 1 | DESKTOP-1 | DA_NOT_INSTALLED |
