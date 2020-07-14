Druva Ransomware Response Playbook
This integration was integrated and tested with Druva Ransomware Response module on Druva Public Cloud
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
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
        "Resource": [
            {
                "orgID": -1,
                "resourceID": 3335062,
                "resourceName": "Sahil\u2019s MacBook Pro",
                "resourceParent": "Sanket Parlikar",
                "resourceStatus": "enabled",
                "resourceType": "Endpoint"
            },
            {
                "orgID": -1,
                "resourceID": 3359444,
                "resourceName": "Sahil\u2019s MacBook Pro",
                "resourceParent": "PM Demo User",
                "resourceStatus": "disabled",
                "resourceType": "Endpoint"
            },
            {
                "orgID": -1,
                "resourceID": 3996977,
                "resourceName": "SahilG-MBP",
                "resourceParent": "PM Demo User",
                "resourceStatus": "enabled",
                "resourceType": "Endpoint"
            }
        ]
    }
}
```

#### Human Readable Output

>### Found Druva Devices
>|orgID|resourceID|resourceName|resourceParent|resourceStatus|resourceType|
>|---|---|---|---|---|---|
>| -1 | 3335062 | Sahil’s MacBook Pro | Sanket Parlikar | enabled | Endpoint |
>| -1 | 3359444 | Sahil’s MacBook Pro | PM Demo User | disabled | Endpoint |
>| -1 | 3996977 | SahilG-MBP | PM Demo User | enabled | Endpoint |


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
        "activeQuarantineRanges": [
            {
                "fromDate": "2020-06-01",
                "orgID": -1,
                "rangeID": 353,
                "recoveryStatus": "None",
                "resourceID": 3673398,
                "resourceName": "ElizabethS-MBA",
                "resourceParent": "PM Demo User",
                "resourcePlatform": "darwin",
                "resourceType": "Endpoint",
                "toDate": "NA"
            },
            {
                "fromDate": "2020-06-22",
                "orgID": -1,
                "rangeID": 321,
                "recoveryStatus": "None",
                "resourceID": 877976,
                "resourceName": "DDSPL1251",
                "resourceParent": "Pronoy Sd",
                "resourcePlatform": "win32",
                "resourceType": "Endpoint",
                "toDate": "2020-06-24"
            },
            {
                "fromDate": "2020-06-15",
                "orgID": -1,
                "rangeID": 290,
                "recoveryStatus": "None",
                "resourceID": 4312962,
                "resourceName": "SGOYAL-WIN10VM",
                "resourceParent": "PM Demo User",
                "resourcePlatform": "win32",
                "resourceType": "Endpoint",
                "toDate": "2020-06-15"
            },
            {
                "fromDate": "2020-04-01",
                "orgID": -1,
                "rangeID": 273,
                "recoveryStatus": "None",
                "resourceID": 3673398,
                "resourceName": "ElizabethS-MBA",
                "resourceParent": "PM Demo User",
                "resourcePlatform": "darwin",
                "resourceType": "Endpoint",
                "toDate": "2020-05-29"
            },
            {
                "fromDate": "2020-05-01",
                "orgID": 3,
                "rangeID": 281,
                "recoveryStatus": "None",
                "resourceID": 81,
                "resourceName": "WIN-CL87GB0P0H2#bset81",
                "resourceParent": "WIN-CL87GB0P0H2",
                "resourcePlatform": "NA",
                "resourceType": "File Server",
                "toDate": "NA"
            },
            {
                "fromDate": "2020-04-01",
                "orgID": 4133,
                "rangeID": 233,
                "recoveryStatus": "None",
                "resourceID": 28604,
                "resourceName": "Downloads",
                "resourceParent": "winnode1",
                "resourcePlatform": "NA",
                "resourceType": "File Server",
                "toDate": "NA"
            }
        ]
    }
}
```

#### Human Readable Output

>### Active quarantined Ranges
>|fromDate|orgID|rangeID|recoveryStatus|resourceID|resourceName|resourceParent|resourcePlatform|resourceType|toDate|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-06-01 | -1 | 353 | None | 3673398 | ElizabethS-MBA | PM Demo User | darwin | Endpoint | NA |
>| 2020-06-22 | -1 | 321 | None | 877976 | DDSPL1251 | Pronoy Sd | win32 | Endpoint | 2020-06-24 |
>| 2020-06-15 | -1 | 290 | None | 4312962 | SGOYAL-WIN10VM | PM Demo User | win32 | Endpoint | 2020-06-15 |
>| 2020-04-01 | -1 | 273 | None | 3673398 | ElizabethS-MBA | PM Demo User | darwin | Endpoint | 2020-05-29 |
>| 2020-05-01 | 3 | 281 | None | 81 | WIN-CL87GB0P0H2#bset81 | WIN-CL87GB0P0H2 | NA | File Server | NA |
>| 2020-04-01 | 4133 | 233 | None | 28604 | Downloads | winnode1 | NA | File Server | NA |


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
```!druva-quarantine-resource resource_id=3335062 resource_type=Endpoint from_date=2020-03-01 to_date=2020-03-10```

#### Context Example
```
{
    "Druva": {
        "QuarantinedRangeID": "354"
    }
}
```

#### Human Readable Output

>### Resource quarantined successfully
>|RangeID|
>|---|
>| 354 |


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
```!druva-view-quarantine-range range_id=354 resource_id=3335062```

#### Context Example
```
{
    "Druva": {
        "viewedQuarantineRange": {
            "addedTime": "2020-06-26T12:38:39Z",
            "fromDate": "2020-03-01",
            "orgID": -1,
            "rangeID": 354,
            "recoveryStatus": "None",
            "resourceID": 3335062,
            "resourceName": "Sahil\u2019s MacBook Pro",
            "resourceParent": "Sanket Parlikar",
            "resourcePlatform": "darwin",
            "resourceType": "Endpoint",
            "toDate": "2020-03-10"
        }
    }
}
```

#### Human Readable Output

>### Range Details
>|addedTime|fromDate|orgID|rangeID|recoveryStatus|resourceID|resourceName|resourceParent|resourcePlatform|resourceType|toDate|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-06-26T12:38:39Z | 2020-03-01 | -1 | 354 | None | 3335062 | Sahil’s MacBook Pro | Sanket Parlikar | darwin | Endpoint | 2020-03-10 |


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
```!druva-update-quarantine-range range_id=354 resource_id=3335062 from_date=2020-02-01 to_date=2020-02-10 resource_type=Endpoint```

#### Context Example
```
{
    "Druva": {
        "updatedQuarantineRange": "354"
    }
}
```

#### Human Readable Output

>### Range updated successfully
>|RangeID|
>|---|
>| 354 |


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
``` ```

#### Human Readable Output



### druva-delete-quarantined-snapshot
***
Delete a quarantined Snapshot


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
``` ```

#### Human Readable Output



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
```!druva-endpoint-search-file-hash sha1_checksum=ea00a57fc80d1e288f625ad365cc69061bbcb6dc```

#### Context Example
```
{
    "Druva": {
        "searchEndpointsFileHashResults": {
            "creationTime": "2014-09-30T19:16:28Z",
            "dataSource": "Devices",
            "deviceID": 3335062,
            "fileName": "basic-test.js",
            "fileSize": 1347,
            "folderPath": "/Users/sahilgoyal/Desktop/wdc/webdataconnector/node_modules/colors/tests",
            "modificationTime": "2014-09-30T19:16:28Z",
            "objectID": "eyJ2ZXJzaW9uIjoyMCwiZHZlciI6MCwiZnNldGRpciI6Ii9Vc2Vycy9zYWhpbGdveWFsL0Rlc2t0b3Avd2RjIiwidW5pcXVlX25vIjoiMEAwMDAwMkAwMDBMOCIsInNwYXRoIjoid2RjL3dlYmRhdGFjb25uZWN0b3Ivbm9kZV9tb2R1bGVzL2NvbG9ycy90ZXN0cyIsImRvY2lkIjoiblBJUUFKYmpNZ0F3UURBd01EQXlRREF3TUV3NCIsInNpZCI6ODMxLCJkaWQiOjMzMzUwNjJ9",
            "sha1Checksum": "ea00a57fc80d1e288f625ad365cc69061bbcb6dc",
            "storageID": 831,
            "userID": 1110684
        }
    }
}
```

#### Human Readable Output

>### Search Results
>|creationTime|dataSource|deviceID|fileName|fileSize|folderPath|modificationTime|objectID|sha1Checksum|storageID|userID|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2014-09-30T19:16:28Z | Devices | 3335062 | basic-test.js | 1347 | /Users/sahilgoyal/Desktop/wdc/webdataconnector/node_modules/colors/tests | 2014-09-30T19:16:28Z | eyJ2ZXJzaW9uIjoyMCwiZHZlciI6MCwiZnNldGRpciI6Ii9Vc2Vycy9zYWhpbGdveWFsL0Rlc2t0b3Avd2RjIiwidW5pcXVlX25vIjoiMEAwMDAwMkAwMDBMOCIsInNwYXRoIjoid2RjL3dlYmRhdGFjb25uZWN0b3Ivbm9kZV9tb2R1bGVzL2NvbG9ycy90ZXN0cyIsImRvY2lkIjoiblBJUUFKYmpNZ0F3UURBd01EQXlRREF3TUV3NCIsInNpZCI6ODMxLCJkaWQiOjMzMzUwNjJ9 | ea00a57fc80d1e288f625ad365cc69061bbcb6dc | 831 | 1110684 |


### druva-endpoint-initiate-restore
***
Restore Data to a replacement device


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
Remote Wipe Infected Endpoint Resource


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


