Centrally orchestrate ransomware response and recovery via API integrations and automated playbooks. This content pack will empower you to get back to normal faster after security incidents such as insider threats and ransomware attacks.

This integration was integrated and tested with Public APIs available on Druva Public Cloud documented at https://developer.druva.com/

## Configure Druva Ransomware Response on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Druva Ransomware Response.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Druva API URL | True |
| clientId | Client ID | True |
| secretKey | Secret Key | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### druva-find-device
***
Finds Device ID for specific hostname


#### Base Command

`druva-find-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_string | Prefix Search String for data source name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.Resource.resourceID | number | Resource ID. | 
| Druva.Resource.resourceName | string | Resource Name | 
| Druva.Resource.resourceType | unknown | Resource Type | 
| Druva.Resource.resourceParent | string | Resource Server or User | 


#### Command Example
```!druva-find-device search_string=sah```

#### Context Example
```
{
    "Druva": {
        "Resource": {
            "orgID": -1,
            "resourceID": 4497505,
            "resourceName": "SahilG-MBP",
            "resourceParent": "Druva Integrations",
            "resourceStatus": "enabled",
            "resourceType": "Endpoint"
        }
    }
}
```

#### Human Readable Output

>### Found Druva Devices
>|orgID|resourceID|resourceName|resourceParent|resourceStatus|resourceType|
>|---|---|---|---|---|---|
>| -1 | 4497505 | SahilG-MBP | Druva Integrations | enabled | Endpoint |


### druva-list-quarantine-ranges
***
Lists all quarantine ranges in your environment


#### Base Command

`druva-list-quarantine-ranges`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.activeQuarantineRanges.resourceID | number | Resource ID. | 
| Druva.activeQuarantineRanges.resourceName | string | Resource Name | 
| Druva.activeQuarantineRanges.resourceParent | string | Resource User Or Server | 
| Druva.activeQuarantineRanges.resourceType | string | Resource Type | 
| Druva.activeQuarantineRanges.fromDate | string | Quarantine Start Date | 
| Druva.activeQuarantineRanges.toDate | string | Quarantine End Date | 
| Druva.activeQuarantineRanges.rangeID | unknown | Quarantine Range ID | 


#### Command Example
```!druva-list-quarantine-ranges```

#### Context Example
```
{
    "Druva": {
        "activeQuarantineRanges": {
            "fromDate": "2020-07-13",
            "orgID": -1,
            "rangeID": 415,
            "recoveryStatus": "None",
            "resourceID": 4497505,
            "resourceName": "SahilG-MBP",
            "resourceParent": "Druva Integrations",
            "resourcePlatform": "darwin",
            "resourceType": "Endpoint",
            "toDate": "2020-07-15",
            "workload": "endpoints"
        }
    }
}
```

#### Human Readable Output

>### Active quarantined Ranges
>|fromDate|orgID|rangeID|recoveryStatus|resourceID|resourceName|resourceParent|resourcePlatform|resourceType|toDate|workload|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-07-13 | -1 | 415 | None | 4497505 | SahilG-MBP | Druva Integrations | darwin | Endpoint | 2020-07-15 | endpoints |


### druva-quarantine-resource
***
Quarantine a resource


#### Base Command

`druva-quarantine-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | resource id for which you would like to list resources | Required | 
| resource_type | type or resource : Endpoint or  File Server or NAS | Required | 
| from_date | Date from which a quarantine range should start. If not provided then it is considered as open ended. example: 2020-10-25 | Optional | 
| to_date | Date from which a quarantine range should end. If not provided then it is considered as open ended. example: 2020-10-25 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.QuarantinedRangeID | string | RangeID of the Quarantined Resource | 


#### Command Example
```!druva-quarantine-resource resource_id=4497505 resource_type=Endpoint from_date=2020-03-01 to_date=2020-03-10```

#### Context Example
```
{
    "Druva": {
        "QuarantinedRangeID": "445",
        "activeQuarantineRanges": [
            {
                "fromDate": "2020-03-01",
                "orgID": -1,
                "rangeID": 445,
                "recoveryStatus": "None",
                "resourceID": 4497505,
                "resourceName": "SahilG-MBP",
                "resourceParent": "Druva Integrations",
                "resourcePlatform": "darwin",
                "resourceType": "Endpoint",
                "toDate": "2020-03-10",
                "workload": "endpoints"
            },
            {
                "fromDate": "2020-07-13",
                "orgID": -1,
                "rangeID": 415,
                "recoveryStatus": "None",
                "resourceID": 4497505,
                "resourceName": "SahilG-MBP",
                "resourceParent": "Druva Integrations",
                "resourcePlatform": "darwin",
                "resourceType": "Endpoint",
                "toDate": "2020-07-15",
                "workload": "endpoints"
            }
        ]
    }
}
```

#### Human Readable Output

>### Resource quarantined successfully
>|RangeID|
>|---|
>| 445 |
>### Active quarantined Ranges
>|fromDate|orgID|rangeID|recoveryStatus|resourceID|resourceName|resourceParent|resourcePlatform|resourceType|toDate|workload|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-03-01 | -1 | 445 | None | 4497505 | SahilG-MBP | Druva Integrations | darwin | Endpoint | 2020-03-10 | endpoints |
>| 2020-07-13 | -1 | 415 | None | 4497505 | SahilG-MBP | Druva Integrations | darwin | Endpoint | 2020-07-15 | endpoints |


### druva-delete-quarantine-range
***
Delete a quarantine range


#### Base Command

`druva-delete-quarantine-range`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | ID of range to be deleted | Required | 
| resource_id | resource id for which you would like to delete the range | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!druva-delete-quarantine-range range_id=354 resource_id=3335062```

#### Context Example
```
{
    "Druva": {
        "deletedQuarantineRange": "354"
    }
}
```

#### Human Readable Output

>### Quarantine Range Deleted Successfully
>|RangeID|
>|---|
>| 354 |


### druva-view-quarantine-range
***
View Quarantine Range Details


#### Base Command

`druva-view-quarantine-range`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | ID of range to be viewed | Required | 
| resource_id | resource id for which you would like to view the range | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!druva-view-quarantine-range range_id=415 resource_id=4497505```

#### Context Example
```
{
    "Druva": {
        "viewedQuarantineRange": {
            "addedTime": "2020-07-13T07:58:46Z",
            "fromDate": "2020-07-13",
            "orgID": -1,
            "rangeID": 415,
            "recoveryStatus": "None",
            "resourceID": 4497505,
            "resourceName": "SahilG-MBP",
            "resourceParent": "Druva Integrations",
            "resourcePlatform": "darwin",
            "resourceType": "Endpoint",
            "toDate": "2020-07-15",
            "workload": "endpoints"
        }
    }
}
```

#### Human Readable Output

>### Range Details
>|addedTime|fromDate|orgID|rangeID|recoveryStatus|resourceID|resourceName|resourceParent|resourcePlatform|resourceType|toDate|workload|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-07-13T07:58:46Z | 2020-07-13 | -1 | 415 | None | 4497505 | SahilG-MBP | Druva Integrations | darwin | Endpoint | 2020-07-15 | endpoints |


### druva-update-quarantine-range
***
Updates an existing Quarantine Range


#### Base Command

`druva-update-quarantine-range`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | ID of resource to be updated | Required | 
| range_id | ID of range to be updated | Required | 
| resource_type | type or resource to be updated : Endpoint or  File Server or NAS  | Required | 
| from_date | Update Date from which a quarantine range should start. If not provided then it is considered as open ended. example: 2020-10-25 | Optional | 
| to_date | Updated Date from which a quarantine range should end. If not provided then it is considered as open ended. example: 2020-10-25 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.updatedQuarantineRange | string | Range ID of the Updated Quarantined Range | 


#### Command Example
```!druva-update-quarantine-range range_id=415 resource_id=4497505 from_date=2020-07-13 to_date=2020-07-15 resource_type=Endpoint```

#### Context Example
```
{
    "Druva": {
        "activeQuarantineRanges": [
            {
                "fromDate": "2020-07-13",
                "orgID": -1,
                "rangeID": 415,
                "recoveryStatus": "None",
                "resourceID": 4497505,
                "resourceName": "SahilG-MBP",
                "resourceParent": "Druva Integrations",
                "resourcePlatform": "darwin",
                "resourceType": "Endpoint",
                "toDate": "2020-07-15",
                "workload": "endpoints"
            },
            {
                "fromDate": "2020-03-01",
                "orgID": -1,
                "rangeID": 445,
                "recoveryStatus": "None",
                "resourceID": 4497505,
                "resourceName": "SahilG-MBP",
                "resourceParent": "Druva Integrations",
                "resourcePlatform": "darwin",
                "resourceType": "Endpoint",
                "toDate": "2020-03-10",
                "workload": "endpoints"
            }
        ],
        "updatedQuarantineRange": "415"
    }
}
```

#### Human Readable Output

>### Range updated successfully
>|RangeID|
>|---|
>| 415 |
>### Active quarantined Ranges
>|fromDate|orgID|rangeID|recoveryStatus|resourceID|resourceName|resourceParent|resourcePlatform|resourceType|toDate|workload|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-07-13 | -1 | 415 | None | 4497505 | SahilG-MBP | Druva Integrations | darwin | Endpoint | 2020-07-15 | endpoints |
>| 2020-03-01 | -1 | 445 | None | 4497505 | SahilG-MBP | Druva Integrations | darwin | Endpoint | 2020-03-10 | endpoints |


### druva-list-quarantine-snapshots
***
List all quarantine Snapshots for a quarantine range


#### Base Command

`druva-list-quarantine-snapshots`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | resource id for which you would like to view the quarantined snapshots | Required | 
| range_id | ID of range for which quarantined snapshots are to be viewed | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.quarantinedSnapshots.snapshotID | string | ID of the quarantined snapshot | 
| Druva.quarantinedSnapshots.name | string | Name of the quarantined snapshot | 


#### Command Example
```!druva-list-quarantine-snapshots range_id=415 resource_id=4497505```

#### Context Example
```
{
    "Druva": {
        "quarantinedSnapshots": [
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 15 2020, 14:15",
                "snapshotID": "MTMyNzQtV2VkIEp1bCAxNSAxNDoxNTo0OCAyMDIw",
                "snapshotName": "Jul 15 2020, 14:15",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 15 2020, 13:15",
                "snapshotID": "MTMyNzQtV2VkIEp1bCAxNSAxMzoxNToyNiAyMDIw",
                "snapshotName": "Jul 15 2020, 13:15",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 15 2020, 11:38",
                "snapshotID": "MTMyNzQtV2VkIEp1bCAxNSAxMTozODoyMCAyMDIw",
                "snapshotName": "Jul 15 2020, 11:38",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 15 2020, 10:38",
                "snapshotID": "MTMyNzQtV2VkIEp1bCAxNSAxMDozODowNiAyMDIw",
                "snapshotName": "Jul 15 2020, 10:38",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 15 2020, 06:51",
                "snapshotID": "MTMyNzQtV2VkIEp1bCAxNSAwNjo1MTo0NSAyMDIw",
                "snapshotName": "Jul 15 2020, 06:51",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 15 2020, 00:02",
                "snapshotID": "MTMyNzQtV2VkIEp1bCAxNSAwMDowMjo0NyAyMDIw",
                "snapshotName": "Jul 15 2020, 00:02",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 23:02",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAyMzowMjozNSAyMDIw",
                "snapshotName": "Jul 14 2020, 23:02",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 22:02",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAyMjowMjoyMSAyMDIw",
                "snapshotName": "Jul 14 2020, 22:02",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 21:02",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAyMTowMjowNyAyMDIw",
                "snapshotName": "Jul 14 2020, 21:02",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 20:01",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAyMDowMTo1MCAyMDIw",
                "snapshotName": "Jul 14 2020, 20:01",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 19:01",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxOTowMTozNiAyMDIw",
                "snapshotName": "Jul 14 2020, 19:01",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 18:01",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxODowMToyNCAyMDIw",
                "snapshotName": "Jul 14 2020, 18:01",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 17:01",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxNzowMToxMCAyMDIw",
                "snapshotName": "Jul 14 2020, 17:01",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 16:00",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxNjowMDo1NSAyMDIw",
                "snapshotName": "Jul 14 2020, 16:00",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 15:00",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxNTowMDo0MSAyMDIw",
                "snapshotName": "Jul 14 2020, 15:00",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 14:00",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxNDowMDoyOCAyMDIw",
                "snapshotName": "Jul 14 2020, 14:00",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 13:00",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxMzowMDoxMyAyMDIw",
                "snapshotName": "Jul 14 2020, 13:00",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 11:59",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxMTo1OTo1NiAyMDIw",
                "snapshotName": "Jul 14 2020, 11:59",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 10:55",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAxMDo1NTo0MiAyMDIw",
                "snapshotName": "Jul 14 2020, 10:55",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 09:55",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAwOTo1NToxOSAyMDIw",
                "snapshotName": "Jul 14 2020, 09:55",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 0,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 14 2020, 08:55",
                "snapshotID": "MTMyNzQtVHVlIEp1bCAxNCAwODo1NTowNCAyMDIw",
                "snapshotName": "Jul 14 2020, 08:55",
                "snapshotSize": 105355564,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 0,
                "updatedFiles": 0
            },
            {
                "alertTypes": [],
                "createdFiles": 67,
                "deletedFiles": 0,
                "encryptedFiles": 0,
                "name": "Jul 13 2020, 01:02",
                "snapshotID": "MTMyNzQtTW9uIEp1bCAxMyAwMTowMjoyNSAyMDIw",
                "snapshotName": "Jul 13 2020, 01:02",
                "snapshotSize": 228657822,
                "status": "Snapshot Quarantined",
                "totalFilesImpacted": 67,
                "updatedFiles": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Quarantined Snapshots
>|alertTypes|createdFiles|deletedFiles|encryptedFiles|name|snapshotID|snapshotName|snapshotSize|status|totalFilesImpacted|updatedFiles|
>|---|---|---|---|---|---|---|---|---|---|---|
>|  | 0 | 0 | 0 | Jul 15 2020, 14:15 | MTMyNzQtV2VkIEp1bCAxNSAxNDoxNTo0OCAyMDIw | Jul 15 2020, 14:15 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 15 2020, 13:15 | MTMyNzQtV2VkIEp1bCAxNSAxMzoxNToyNiAyMDIw | Jul 15 2020, 13:15 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 15 2020, 11:38 | MTMyNzQtV2VkIEp1bCAxNSAxMTozODoyMCAyMDIw | Jul 15 2020, 11:38 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 15 2020, 10:38 | MTMyNzQtV2VkIEp1bCAxNSAxMDozODowNiAyMDIw | Jul 15 2020, 10:38 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 15 2020, 06:51 | MTMyNzQtV2VkIEp1bCAxNSAwNjo1MTo0NSAyMDIw | Jul 15 2020, 06:51 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 15 2020, 00:02 | MTMyNzQtV2VkIEp1bCAxNSAwMDowMjo0NyAyMDIw | Jul 15 2020, 00:02 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 23:02 | MTMyNzQtVHVlIEp1bCAxNCAyMzowMjozNSAyMDIw | Jul 14 2020, 23:02 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 22:02 | MTMyNzQtVHVlIEp1bCAxNCAyMjowMjoyMSAyMDIw | Jul 14 2020, 22:02 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 21:02 | MTMyNzQtVHVlIEp1bCAxNCAyMTowMjowNyAyMDIw | Jul 14 2020, 21:02 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 20:01 | MTMyNzQtVHVlIEp1bCAxNCAyMDowMTo1MCAyMDIw | Jul 14 2020, 20:01 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 19:01 | MTMyNzQtVHVlIEp1bCAxNCAxOTowMTozNiAyMDIw | Jul 14 2020, 19:01 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 18:01 | MTMyNzQtVHVlIEp1bCAxNCAxODowMToyNCAyMDIw | Jul 14 2020, 18:01 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 17:01 | MTMyNzQtVHVlIEp1bCAxNCAxNzowMToxMCAyMDIw | Jul 14 2020, 17:01 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 16:00 | MTMyNzQtVHVlIEp1bCAxNCAxNjowMDo1NSAyMDIw | Jul 14 2020, 16:00 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 15:00 | MTMyNzQtVHVlIEp1bCAxNCAxNTowMDo0MSAyMDIw | Jul 14 2020, 15:00 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 14:00 | MTMyNzQtVHVlIEp1bCAxNCAxNDowMDoyOCAyMDIw | Jul 14 2020, 14:00 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 13:00 | MTMyNzQtVHVlIEp1bCAxNCAxMzowMDoxMyAyMDIw | Jul 14 2020, 13:00 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 11:59 | MTMyNzQtVHVlIEp1bCAxNCAxMTo1OTo1NiAyMDIw | Jul 14 2020, 11:59 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 10:55 | MTMyNzQtVHVlIEp1bCAxNCAxMDo1NTo0MiAyMDIw | Jul 14 2020, 10:55 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 09:55 | MTMyNzQtVHVlIEp1bCAxNCAwOTo1NToxOSAyMDIw | Jul 14 2020, 09:55 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 0 | 0 | 0 | Jul 14 2020, 08:55 | MTMyNzQtVHVlIEp1bCAxNCAwODo1NTowNCAyMDIw | Jul 14 2020, 08:55 | 105355564 | Snapshot Quarantined | 0 | 0 |
>|  | 67 | 0 | 0 | Jul 13 2020, 01:02 | MTMyNzQtTW9uIEp1bCAxMyAwMTowMjoyNSAyMDIw | Jul 13 2020, 01:02 | 228657822 | Snapshot Quarantined | 67 | 0 |


### druva-delete-quarantined-snapshot
***
Delete a quarantined Snapshot. Warning: Snapshots once deleted can not be recovered.


#### Base Command

`druva-delete-quarantined-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | resource id for which you would like to delete a quarantined snapshots | Required | 
| snapshot_id | ID of snapshot you would like to delete | Required | 
| range_id | Range id for which you would like to delete a quarantined snapshots | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.quarantinedSnapshots.snapshotID | string | ID of the quarantined snapshot | 


#### Command Example
```!druva-delete-quarantined-snapshot range_id=415 resource_id=4497505 snapshot_id=MTMyNzQtV2VkIEp1bCAxNSAxMTozODoyMCAyMDIw```

#### Context Example
```
{}
```

#### Human Readable Output

>### Snapshot Deleted successfully
>|Snapshot ID|
>|---|
>| MTMyNzQtV2VkIEp1bCAxNSAxMTozODoyMCAyMDIw |


### druva-endpoint-search-file-hash
***
Search a file use SHA1 checksum


#### Base Command

`druva-endpoint-search-file-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1_checksum | checksum of the file to be searched | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.searchEndpointsFileHashResults.deviceID | string | Device ID of device the input hash | 
| Druva.searchEndpointsFileHashResults.fileName | string | Name of the file on the Endpoint | 
| Druva.searchEndpointsFileHashResults.objectID | string | Object ID | 
| Druva.searchEndpointsFileHashResults.userID | string | User ID of the Endpoint | 


#### Command Example
```!druva-endpoint-search-file-hash sha1_checksum=cec8ad914b1e9db83626b98e8d98512616975fdf```

#### Context Example
```
{
    "Druva": {
        "searchEndpointsFileHashResults": [
            {
                "creationTime": "2020-05-11T23:49:17Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Documents\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MCwiZnNldGRpciI6IkM6XFxVc2Vyc1xcc2FoaWxcXERvY3VtZW50cyIsInVuaXF1ZV9ubyI6IjBAMDAwMDEwMDAwMFxcIiwic3BhdGgiOiJ7e015IERvY3VtZW50c319L3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeE1EQXdNREJjIiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ==",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            },
            {
                "creationTime": "2020-05-11T23:49:17Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Documents\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsXFxEb2N1bWVudHMiLCJ1bmlxdWVfbm8iOiIwQDAwMDAxQDAwMDEwIiwic3BhdGgiOiJEb2N1bWVudHMxL3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeFFEQXdNREV3Iiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ==",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            },
            {
                "creationTime": "2020-05-11T23:49:20Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Desktop\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsXFxEZXNrdG9wIiwidW5pcXVlX25vIjoiMEAwMDAwMVAwMDAxWCIsInNwYXRoIjoiRGVza3RvcDEvemlwXzEwTUIvemlwXzEwTUIiLCJkb2NpZCI6InZqMHpBRGtoUkFBd1FEQXdNREF4VURBd01ERlkiLCJzaWQiOjEzMjc0LCJkaWQiOjQ0NjQ5NTN9",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            },
            {
                "creationTime": "2020-05-11T23:49:20Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Desktop\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MCwiZnNldGRpciI6IkM6XFxVc2Vyc1xcc2FoaWxcXERlc2t0b3AiLCJ1bmlxdWVfbm8iOiIwQDAwMDAxYDAwMDBgIiwic3BhdGgiOiJ7e0Rlc2t0b3B9fS96aXBfMTBNQi96aXBfMTBNQiIsImRvY2lkIjoidmowekFEa2hSQUF3UURBd01EQXhZREF3TURCZyIsInNpZCI6MTMyNzQsImRpZCI6NDQ2NDk1M30=",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            },
            {
                "creationTime": "2020-05-11T23:49:20Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Desktop\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsIiwidW5pcXVlX25vIjoiMEAwMDAwMjAwMDNsbCIsInNwYXRoIjoic2FoaWwvRGVza3RvcC96aXBfMTBNQi96aXBfMTBNQiIsImRvY2lkIjoidmowekFEa2hSQUF3UURBd01EQXlNREF3TTJ4cyIsInNpZCI6MTMyNzQsImRpZCI6NDQ2NDk1M30=",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            },
            {
                "creationTime": "2020-05-11T23:49:17Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Documents\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsIiwidW5pcXVlX25vIjoiMEAwMDAwMjAwMDNuNCIsInNwYXRoIjoic2FoaWwvRG9jdW1lbnRzL3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeU1EQXdNMjQwIiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ==",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            },
            {
                "creationTime": "2017-08-12T06:22:30Z",
                "dataSource": "Devices",
                "deviceID": 4464953,
                "fileName": "file-example_PDF_1MB.pdf",
                "fileSize": 1042157,
                "folderPath": "C:\\Users\\sahil\\Downloads\\zip_10MB\\zip_10MB",
                "modificationTime": "2020-05-11T23:49:10Z",
                "objectID": "eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsIiwidW5pcXVlX25vIjoiMEAwMDAwMjAwMDNvTCIsInNwYXRoIjoic2FoaWwvRG93bmxvYWRzL3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeU1EQXdNMjlNIiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ==",
                "sha1Checksum": "cec8ad914b1e9db83626b98e8d98512616975fdf",
                "storageID": 13274,
                "userID": 3358142
            }
        ]
    }
}
```

#### Human Readable Output

>### Search Results
>|creationTime|dataSource|deviceID|fileName|fileSize|folderPath|modificationTime|objectID|sha1Checksum|storageID|userID|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-05-11T23:49:17Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Documents\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MCwiZnNldGRpciI6IkM6XFxVc2Vyc1xcc2FoaWxcXERvY3VtZW50cyIsInVuaXF1ZV9ubyI6IjBAMDAwMDEwMDAwMFxcIiwic3BhdGgiOiJ7e015IERvY3VtZW50c319L3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeE1EQXdNREJjIiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ== | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |
>| 2020-05-11T23:49:17Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Documents\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsXFxEb2N1bWVudHMiLCJ1bmlxdWVfbm8iOiIwQDAwMDAxQDAwMDEwIiwic3BhdGgiOiJEb2N1bWVudHMxL3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeFFEQXdNREV3Iiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ== | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |
>| 2020-05-11T23:49:20Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Desktop\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsXFxEZXNrdG9wIiwidW5pcXVlX25vIjoiMEAwMDAwMVAwMDAxWCIsInNwYXRoIjoiRGVza3RvcDEvemlwXzEwTUIvemlwXzEwTUIiLCJkb2NpZCI6InZqMHpBRGtoUkFBd1FEQXdNREF4VURBd01ERlkiLCJzaWQiOjEzMjc0LCJkaWQiOjQ0NjQ5NTN9 | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |
>| 2020-05-11T23:49:20Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Desktop\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MCwiZnNldGRpciI6IkM6XFxVc2Vyc1xcc2FoaWxcXERlc2t0b3AiLCJ1bmlxdWVfbm8iOiIwQDAwMDAxYDAwMDBgIiwic3BhdGgiOiJ7e0Rlc2t0b3B9fS96aXBfMTBNQi96aXBfMTBNQiIsImRvY2lkIjoidmowekFEa2hSQUF3UURBd01EQXhZREF3TURCZyIsInNpZCI6MTMyNzQsImRpZCI6NDQ2NDk1M30= | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |
>| 2020-05-11T23:49:20Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Desktop\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsIiwidW5pcXVlX25vIjoiMEAwMDAwMjAwMDNsbCIsInNwYXRoIjoic2FoaWwvRGVza3RvcC96aXBfMTBNQi96aXBfMTBNQiIsImRvY2lkIjoidmowekFEa2hSQUF3UURBd01EQXlNREF3TTJ4cyIsInNpZCI6MTMyNzQsImRpZCI6NDQ2NDk1M30= | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |
>| 2020-05-11T23:49:17Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Documents\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsIiwidW5pcXVlX25vIjoiMEAwMDAwMjAwMDNuNCIsInNwYXRoIjoic2FoaWwvRG9jdW1lbnRzL3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeU1EQXdNMjQwIiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ== | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |
>| 2017-08-12T06:22:30Z | Devices | 4464953 | file-example_PDF_1MB.pdf | 1042157 | C:\Users\sahil\Downloads\zip_10MB\zip_10MB | 2020-05-11T23:49:10Z | eyJ2ZXJzaW9uIjoxNiwiZHZlciI6MTcsImZzZXRkaXIiOiJDOlxcVXNlcnNcXHNhaGlsIiwidW5pcXVlX25vIjoiMEAwMDAwMjAwMDNvTCIsInNwYXRoIjoic2FoaWwvRG93bmxvYWRzL3ppcF8xME1CL3ppcF8xME1CIiwiZG9jaWQiOiJ2ajB6QURraFJBQXdRREF3TURBeU1EQXdNMjlNIiwic2lkIjoxMzI3NCwiZGlkIjo0NDY0OTUzfQ== | cec8ad914b1e9db83626b98e8d98512616975fdf | 13274 | 3358142 |


### druva-endpoint-initiate-restore
***
Restore Data to a replacement device. Delete a quarantined Snapshot. Warning: This command will restore your endpoint data from a prior day snapshot. Any changes since the snapshot date may be lost.


#### Base Command

`druva-endpoint-initiate-restore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_resourceid | Select resource id to restore from  | Required | 
| target_resourceid | Select resource id to restore to  | Required | 
| restore_location | Select Target Restore Location: 1) Desktop - If you want to restore the data to the desktop on the target device. 2) Original - If you want to restore data to the same location from which it was backed up. 3) If you want to restore the data at a custom location, specify absolute path of the location. Example - /Users/username/Desktop | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### druva-endpoint-check-restore-status
***
Check Restore Job Status


#### Base Command

`druva-endpoint-check-restore-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restore_id | Job ID of Restore | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### druva-endpoint-decommission
***
Remote Wipe Infected Endpoint Resource. Delete a quarantined Snapshot. Warning: This command will remote wipe data from the end point. This action can not be undone.


#### Base Command

`druva-endpoint-decommission`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | ID of endpoint resource to be decommissioned | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


