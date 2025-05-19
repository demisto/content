Druva Ransomware Response Integration provides ransomware protection for endpoints, SaaS applications and data center workloads for Druva Ransomware Recovery customers.

## Configure Druva Ransomware Response in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Druva API URL |  | True |
| Client ID |  | True |
| Secret Key |  | True |
| Fetch indicators |  | False |
| Indicator Verdict | Indicators from this integration instance will be marked with this verdict | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### druva-find-device

***
Finds device information for a specific hostname.

#### Base Command

`druva-find-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_string | The full string or prefix from the data resource name to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.Resource.resourceID | number | The ID of the Resource. | 
| Druva.Resource.resourceName | string | The name of the Resource. | 
| Druva.Resource.resourceType | unknown | The type of the Resource. | 
| Druva.Resource.resourceParent | string | The name of the resource user for a device or server. | 
| Druva.Resource.orgID | unknown | The Organisation ID of device  | 

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
Lists all quarantine ranges in your environment.

#### Base Command

`druva-list-quarantine-ranges`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.activeQuarantineRanges.resourceID | number | The ID of the resource. | 
| Druva.activeQuarantineRanges.resourceName | string | The name of the resource. | 
| Druva.activeQuarantineRanges.resourceParent | string | The name of the resource user for a device or server. | 
| Druva.activeQuarantineRanges.resourceType | string | The type of the resource. | 
| Druva.activeQuarantineRanges.fromDate | string | The start date of the quarantine. | 
| Druva.activeQuarantineRanges.toDate | string | The end date of the quarantine. | 
| Druva.activeQuarantineRanges.rangeID | unknown | The range ID of the quarantined resource. | 

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
Quarantines a resource.

#### Base Command

`druva-quarantine-resource`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource to quarantine. | Required | 
| resource_type | The resource type to quarantine. Can be: "Endpoint", "File Server", or "NAS". | Required | 
| org_id | Specify your org id for NAS and File server for End points set org_id to -1. | Optional | 
| from_date | Date from which a quarantine range should start. If not provided, it is considered open ended. For example, 2020-10-25. | Optional | 
| to_date | Date from which a quarantine range should end. If not provided, it is considered open ended. For example, 2020-10-25. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.QuarantinedRangeID | string | The range ID of the Quarantined Resource. | 
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
Deletes a quarantine range.

#### Base Command

`druva-delete-quarantine-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | ID of the range to be deleted. | Required | 
| resource_id | The resource ID for which the quarantine range is to be deleted. | Required | 

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
View details of the quarantine range.

#### Base Command

`druva-view-quarantine-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | The ID of the range to be viewed. | Required | 
| resource_id | The resource ID for which you would like to view the range. | Required | 

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
Updates an existing quarantine range of a resource.

#### Base Command

`druva-update-quarantine-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource to be updated. | Required | 
| range_id | The ID of range to be updated. | Required | 
| resource_type | The resource type to be updated. Can be: "Endpoint", "File Server", or "NAS". | Required | 
| from_date | The date from which a quarantine range should start. If not provided, it is open-ended. For example, 2020-10-25. | Optional | 
| to_date | The date from which a quarantine range should end. If not provided, it is open-ended. For example, 2020-10-25. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.updatedQuarantineRange | string | The range ID of the updated quarantined range. | 
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
List all quarantine snapshots for a quarantine range.

#### Base Command

`druva-list-quarantine-snapshots`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The resource ID of the quarantined snapshots to view. | Required | 
| range_id | The range ID of the quarantined snapshots to view. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.quarantinedSnapshots.snapshotID | string | ID of the quarantined snapshot. | 
| Druva.quarantinedSnapshots.name | string | Name of the quarantined snapshot. | 
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
Deletes a quarantined Snapshot. Snapshots that are deleted cannot be recovered.

#### Base Command

`druva-delete-quarantined-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The resource ID to delete a quarantined snapshot. | Required | 
| snapshot_id | The ID of the snapshot to delete. | Required | 
| range_id | The range ID to delete a quarantined snapshot. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.quarantinedSnapshots.snapshotID | string | ID of the quarantined snapshot. | 
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
Searches a file using the SHA1 checksum.

#### Base Command

`druva-endpoint-search-file-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1_checksum | SHA1 checksum of the file to be searched. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.searchEndpointsFileHashResults.deviceID | string | The device ID on the Endpoint. | 
| Druva.searchEndpointsFileHashResults.fileName | string | Name of the file on the Endpoint. | 
| Druva.searchEndpointsFileHashResults.objectID | string | The object ID on the Endpoint. | 
| Druva.searchEndpointsFileHashResults.userID | string | The user ID of the Endpoint. | 

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
Restores data to a replacement device and deletes a quarantined Snapshot. This command restores your endpoint data from a day prior to the snapshot. Any changes made after the snapshot date may be lost.

#### Base Command

`druva-endpoint-initiate-restore`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_resourceid | Select a Resource ID in which to restore. . | Required | 
| target_resourceid | Select a Resource ID in which to restore. | Required | 
| restore_location | Specify the target Restore Location. Can be: "Desktop" - if you want to restore the data to the desktop on the target device, "Original" - if you want to restore data to the same location from which it was backed up, or to restore the data to a custom location, specify the absolute path of the location. For example,  /Users/username/Desktop. | Required | 

#### Context Output

There is no context output for this command.
### druva-endpoint-check-restore-status

***
Checks the restore job status of the endpoint.

#### Base Command

`druva-endpoint-check-restore-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restore_id | The restore ID of the job. | Required | 

#### Context Output

There is no context output for this command.
### druva-endpoint-decommission

***
Wipes remotely an infected Endpoint Resource and deletes a quarantined Snapshot. This command remote wipes data from the endpoint. This action cannot be undone.

#### Base Command

`druva-endpoint-decommission`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | ID of endpoint resource to be decommissioned. | Required | 

#### Context Output

There is no context output for this command.
### druva-find-user

***
Finds user information for a specific username.

#### Base Command

`druva-find-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_string | Complete user name or p. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.User.userID | unknown | The full string or prefix from the user name to search. | 

#### Command example
```!druva-find-user user_string=rit1```
#### Context Example
```json
{
    "Druva": {
        "User": [
            {
                "emailID": "test@test.com",
                "userID": 10000135,
                "userName": "test"
            },
            {
                "emailID": "test123@test.com",
                "userID": 10000154,
                "userName": "test123"
            }
        ]
    }
}
```

#### Human Readable Output

>### Found Druva users
>|emailID|userID|userName|
>|---|---|---|
>| test@test.com | 10000135 | test |
>| test123@test.com | 10000154 | test123 |


### druva-find-userDevice

***
Finds device information for a specific user.

#### Base Command

`druva-find-userDevice`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userID | The userID to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.Resource.resourceID | string | The ID of the Resource. | 
| Druva.Resource.resourceType | string | The type of the Resource. | 

#### Command example
```!druva-find-userDevice userID=10000135```
#### Context Example
```json
{
    "Druva": {
        "Resource": [
            {
                "profileID": 183,
                "resourceID": 10000105,
                "resourceName": "DDSPL1571N",
                "resourceStatus": "Enabled",
                "resourceType": "Endpoint",
                "userID": 10000135,
                "userName": "rit1"
            },
            {
                "profileID": 183,
                "resourceID": 10000103,
                "resourceName": "rit1's OneDrive",
                "resourceStatus": "Enabled",
                "resourceType": "OneDrive",
                "userID": 10000135,
                "userName": "rit1"
            },
            {
                "profileID": 183,
                "resourceID": 10000104,
                "resourceName": "rit1's Google Drive",
                "resourceStatus": "Enabled",
                "resourceType": "Google Drive",
                "userID": 10000135,
                "userName": "rit1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Found Druva Devices
>|profileID|resourceID|resourceName|resourceStatus|resourceType|userID|userName|
>|---|---|---|---|---|---|---|
>| 183 | 10000105 | DDSPL1571N | Enabled | Endpoint | 10000135 | rit1 |
>| 183 | 10000103 | rit1's OneDrive | Enabled | OneDrive | 10000135 | rit1 |
>| 183 | 10000104 | rit1's Google Drive | Enabled | Google Drive | 10000135 | rit1 |


### druva-find-sharePointSites

***
Find all share point resources with given user name 

#### Base Command

`druva-find-sharePointSites`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_string | The full string or prefix from the share point url to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.Resource.resourceID | unknown | The ID of the Resource. | 
| Druva.Resource.resourceType | unknown | The type of the Resource. | 

#### Command example
```!druva-find-sharePointSites search_string="auto_restore_XQ9OBZ"```
#### Context Example
```json
{
    "Druva": {
        "Resource": {
            "resourceID": 53,
            "resourceName": "auto_restore_XQ9OBZ",
            "resourceParentName": "https://druvainternal.sharepoint.com/sites/auto_restore_XQ9OBZ",
            "resourceStatus": "Disabled",
            "resourceType": "SharePoint",
            "siteType": "Other Site"
        }
    }
}
```

#### Human Readable Output

>### Found Druva Devices
>|resourceID|resourceName|resourceParentName|resourceStatus|resourceType|siteType|
>|---|---|---|---|---|---|
>| 53 | auto_restore_XQ9OBZ | https:<span>//</span>druvainternal.sharepoint.com/sites/auto_restore_XQ9OBZ | Disabled | SharePoint | Other Site |


### druva-find-sharedDrives

***
Finds shared drives resources specific to share drive name

#### Base Command

`druva-find-sharedDrives`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_string | The full string or prefix from the share drive name to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Druva.Resource.resourceID | unknown | The ID of the Resource. | 
| Druva.Resource.resourceType | unknown | The type of the Resource. | 

#### Command example
```!druva-find-sharedDrives search_string="rahul_drive"```
#### Context Example
```json
{
    "Druva": {
        "Resource": {
            "resourceID": 104,
            "resourceName": "rahul_drive",
            "resourceParentName": "https://drive.google.com/drive/folders/0AIL1ax7fcxDKUk9PVA",
            "resourceStatus": "Enabled",
            "resourceType": "Shared Drive"
        }
    }
}
```

#### Human Readable Output

>### Found Druva Devices
>|resourceID|resourceName|resourceParentName|resourceStatus|resourceType|
>|---|---|---|---|---|
>| 104 | rahul_drive | https:<span>//</span>drive.google.com/drive/folders/0AIL1ax7fcxDKUk9PVA | Enabled | Shared Drive |
