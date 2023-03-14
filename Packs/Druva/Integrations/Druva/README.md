Druva Ransomware Response Integration provides ransomware protection for endpoints, SaaS applications and data center workloads for Druva Ransomware Recovery customers.
This integration was integrated and tested with version xx of Druva Ransomware Response

## Configure Druva Ransomware Response on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Druva Ransomware Response.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
