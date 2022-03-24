Use the Automox integration to create device groups, update devices, run policies, and remediate vulnerabilities of devices through the Automox platform.
This integration was integrated and tested as of 2022-03-21 with the Automox API

## Configure Automox on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Automox.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Organization ID | A comma-separated list of organization ids. When specified, data pulled from Automox will only belong to these organizations; otherwise, the default permissions for this API key will be used. | False |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### automox-devices-list
***
List all devices in an Automox instance based on group and organization permissions.


#### Base Command

`automox-devices-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization ID. | Optional |
| group_id | Group ID. | Optional |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.Devices.id | Number | Identifier of device |
| Automox.Devices.server_group_id | Number | Identifier of server group |
| Automox.Devices.organization_id | Number | Identifier of organization |
| Automox.Devices.uuid | String | The Automox UUID of a device |
| Automox.Devices.name | String | The name of a device |
| Automox.Devices.refresh_interval | Number | Frequency of device refreshes in minutes |
| Automox.Devices.last_update_time | String | The last time a device was updated in Automox |
| Automox.Devices.last_refresh_time | String | The last time a device was refreshed in Automox |
| Automox.Devices.uptime | Number | The device uptime in minutes |
| Automox.Devices.needs_reboot | Boolean | Whether a device needs to be rebooted |
| Automox.Devices.timezone | String | The device timezone |
| Automox.Devices.tags | String | List of tags for the device |
| Automox.Devices.deleted | Boolean | Whether a device is deleted |
| Automox.Devices.create_time | Date | The time a device was created in Automox |
| Automox.Devices.os_version | String | The operating system version of a device |
| Automox.Devices.os_name | String | The operating system name of a device |
| Automox.Devices.os_family | String | the operating system family of a device |
| Automox.Devices.ip_addrs | String | List of IP addresses for a device |
| Automox.Devices.ip_addrs_private | String | List of private IP addresses for a device |
| Automox.Devices.patches | Number | The number of patches currently identified for a device |
| Automox.Devices.agent_version | String | The version of the Automox agent on the device |
| Automox.Devices.custom_name | String | The Automox specific custom name for the device |
| Automox.Devices.is_compatible | Boolean | Whether a device is compatible with Automox |
| Automox.Devices.policy_status.id | Number | Identifier of policy |
| Automox.Devices.policy_status.organization_id | Number | Identifier of organization |
| Automox.Devices.policy_status.policy_name | String | Name of the policy |
| Automox.Devices.policy_status.policy_type_name | String | Type of the policy |
| Automox.Devices.policy_status.status | Number | Current status of the policy |
| Automox.Devices.policy_status.result | String | Result of the policy |
| Automox.Devices.policy_status.create_time | Datetime | Policy created datetime |
| Automox.Devices.last_scan_failed | Boolean | Whether the last scan failed on a device |
| Automox.Devices.pending | Boolean | Whether work is pending on a device |
| Automox.Devices.compliant | Boolean | Whether a device is compliant |
| Automox.Devices.display_name | String | The display name of a device |
| Automox.Devices.commands.command_type_name | String | The type of a command previously issued on a device |
| Automox.Devices.commands.args | String | The arguments of a command previously issued on a device |
| Automox.Devices.commands.exec_time | Date | The execution time of a command previously issued on a device |
| Automox.Devices.pending_patches | Number | The number of pending patches for a device |
| Automox.Devices.connected | Boolean | Whether a device is currently connected to Automox |
| Automox.Devices.last_process_time | String | The last time the device was processed |
| Automox.Devices.next_patch_time | String | The next time the device is patched |
| Automox.Devices.notification_count | Number | The number of notifications for the device |
| Automox.Devices.reboot_notification_count | Number | The number of reboot notifications for a device |
| Automox.Devices.patch_deferral_count | Number | The number of patch deferrals for a device |
| Automox.Devices.is_delayed_by_notification | Boolean | Whether a patch is delayed by notifications |
| Automox.Devices.reboot_is_delayed_by_notification | Boolean | Whether a reboot is delayed by notifications |
| Automox.Devices.is_delayed_by_user | Boolean | Whether a patch is delayed by the user |
| Automox.Devices.reboot_is_delayed_by_user | Boolean | Whether a reboot is delayed by the user |
| Automox.Devices.last_disconnect_time | Date | Last time a device disconnected from Automox |
| Automox.Devices.needs_attention | Boolean | Whether a device currently needs attention |
| Automox.Devices.serial_number | String | The device serial number |
| Automox.Devices.status.device_status | String | The status of a device |
| Automox.Devices.status.agent_status | String | The status of a device agent |
| Automox.Devices.status.policy_status | String | The overall status of all policies assigned to a device |
| Automox.Devices.status.policy_statuses.id | Number | The identifier of the policy |
| Automox.Devices.status.policy_statuses.compliant | Boolean | Whether a device is compliant to a given status |
| Automox.Devices.last_logged_in_user | String | The last logged in user of a device |

#### Command Example
```
!automox-devices-list
```

#### Human Readable Output
##### Devices

| agent_version | commands                                                                                           | compliant | connected | create_time          | custom_name | deleted | display_name | id  | ip_addrs | ip_addrs_private | is_compatible | is_delayed_by_notification | is_delayed_by_user | last_disconnect_time | last_logged_in_user | last_process_time | last_refresh_time | last_scan_failed | last_update_time | name   | needs_attention | needs_reboot | next_patch_time | notification_count | organization_id | os_family | os_name | os_version | patch_deferral_count | patches | pending | pending_patches | policy_status.0.create_time | policy_status.0.id | policy_status.0.organization_id | policy_status.0.policy_id | policy_status.0.policy_name | policy_status.0.policy_type_name | policy_status.0.result | policy_status.0.server_id | policy_status.0.status | reboot_is_delayed_by_notification | reboot_is_delayed_by_user | reboot_notification_count | refresh_interval | serial_number | server_group_id | status                                                                                                                          | tags   | timezone | uptime | uuid                                 |
| ------------- | -------------------------------------------------------------------------------------------------- | --------- | --------- | -------------------- | ----------- | ------- | ------------ | --- | -------- | ---------------- | ------------- | -------------------------- | ------------------ | -------------------- | ------------------- | ----------------- | ----------------- | ---------------- | ---------------- | ------ | --------------- | ------------ | --------------- | ------------------ | --------------- | --------- | ------- | ---------- | -------------------- | ------- | ------- | --------------- | --------------------------- | ------------------ | ------------------------------- | ------------------------- | --------------------------- | -------------------------------- | ---------------------- | ------------------------- | ---------------------- | --------------------------------- | ------------------------- | ------------------------- | ---------------- | ------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- | ------ | ------------------------------------ |
| string        | args: KB12345 KB67890,<br>command_type_name: InstallUpdate,<br>exec_time: 2017-06-29T16:39:50.951Z | true      | true      | 2019-08-24T14:15:22Z | string      | true    | string       | 0   | 1.1.1.1  | 1.1.1.1          | true          | true                       | true               | 2019-08-24T14:15:22Z | string              | string            | string            | true             | string           | string | true            | true         | string          | 0                  | 0               | string    | string  | string     | 0                    | 0       | true    | 0               | string                      | 0                  | 0                               | 0                         | string                      | patch                            | string                 | 0                         | 0                      | true                              | true                      | 0                         | 0                | string        | 0               | {"agent_status": "string","device_status": "string","policy_status": "string","policy_statuses": [{"compliant": true,"id": 0}]} | string | string   | 0      | 095be615-a8ad-4c33-8e9c-c7612fbf6c9f |

### automox-organizations-list
***
List all Automox organizations based on user permissions.


#### Base Command

`automox-organizations-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.Organizations.id | Number | Identifier of organization |
| Automox.Organizations.name | String | Name of organization |
| Automox.Organizations.create_time | Date | The datetime when the organization was created |
| Automox.Organizations.server_limit | Number | The organization server limit |
| Automox.Organizations.parent_id | Number | The organization parent id |
| Automox.Organizations.device_limit | Number | The organization device limit |
| Automox.Organizations.device_count | Number | The organization device count |

#### Command Example
```
!automox-organizations-list
```

#### Human Readable Output
##### Organizations
| create_time          | device_count | device_limit | id  | name   | parent_id | server_limit |
| -------------------- | ------------ | ------------ | --- | ------ | --------- | ------------ |
| 2019-08-24T14:15:22Z | 0            | 0            | 0   | string | 0         | 0            |
### automox-organization-users-list
***
List all Automox users within an organization.


#### Base Command

`automox-organization-users-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.Users.id | Number | Identifier of user |
| Automox.Users.firstname | String | The first name of the user |
| Automox.Users.lastname | String | The last name of the user |
| Automox.Users.email | String | The email of the user |
| Automox.Users.orgs.id | Number | Identifier of organization |
| Automox.Users.orgs.name | String | Name of organization |
| Automox.Users.tags | String | User tags |
| Automox.Users.saml_enabled | Boolean | Whether SAML has been enabled for the user |
| Automox.Users.rbac_roles.id | Number | The RBAC role identifier |
| Automox.Users.rbac_roles.name | String | The RBAC role name |
| Automox.Users.rbac_roles.organization_id | Number | Identifier of organization |

#### Command Example
```
!automox-organization-users-list
```

#### Human Readable Output
##### Organization Users
| id  | firstname | lastname | email  | orgs                         | tags   | saml_enabled | rbac_roles                                        |
| --- | --------- | -------- | ------ | ---------------------------- | ------ | ------------ | ------------------------------------------------- |
| 0   | string    | string   | string | [{"id": 0,"name": "string"}] | string | true         | [{"id": 0,"name": "string","organization_id": 0}] |
### automox-vulnerability-sync-batch-action
***
Perform an action on an Automox Vulnerability Sync batch.


#### Base Command

`automox-vulnerability-sync-batch-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| batch_id | Batch identifier. | Required |
| action | Action to perform on the batch specified. Options are "accept" or "reject". Possible values are: accept, reject. | Required |


#### Context Output

There is no context output for this command.
### automox-vulnerability-sync-task-action
***
Perform an action on an Automox task.


#### Base Command

`automox-vulnerability-sync-task-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| batch_id | Batch identifier. | Required |
| action | Action to perform on the batch specified. Options are "accept" or "reject". Possible values are: accept, reject. | Required |


#### Context Output

There is no context output for this command.
### automox-vulnerability-sync-batch-get
***
Get details about a Vulnerability Sync batch.


#### Base Command

`automox-vulnerability-sync-batch-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| batch_id | Batch identifier. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.VulnSyncBatch.id | Number | Identifier of batch |
| Automox.VulnSyncBatch.organization_id | Number | Identifier of organization |
| Automox.VulnSyncBatch.status | String | Status of batch |
| Automox.VulnSyncBatch.source | String | Originating vendor of vulnerability information |
| Automox.VulnSyncBatch.created_by.id | Number | The identifier of the user who created this batch |
| Automox.VulnSyncBatch.created_by.firstname | String | The first name of the user who created this batch |
| Automox.VulnSyncBatch.created_by.lastname | String | The last name of the user who created this batch |
| Automox.VulnSyncBatch.created_by.email | String | The email of the user who created this batch |
| Automox.VulnSyncBatch.updated_by.id | Number | The identifier of the user who last updated this batch |
| Automox.VulnSyncBatch.updated_by.firstname | String | The first name of the user who last updated this batch |
| Automox.VulnSyncBatch.updated_by.lastname | String | The last name of the user who last updated this batch |
| Automox.VulnSyncBatch.updated_by.email | String | The email of the user who last updated this batch |
| Automox.VulnSyncBatch.uploaded_at | Date | Datetime of initial upload |
| Automox.VulnSyncBatch.task_count | Number | Number of tasks related to batch |
| Automox.VulnSyncBatch.unknown_host_count | Number | Number of hosts that are unknown within batch |
| Automox.VulnSyncBatch.impacted_device_count | Number | Number of devices impacted by batch |
| Automox.VulnSyncBatch.issue_count | Number | Number of issues identified with batch |
| Automox.VulnSyncBatch.cve_count | Number | Number of CVEs impacted by batch |


#### Command Example
```
!automox-vulnerability-sync-batch-get
```

#### Human Readable Output
##### Batch
| id  | organization_id | status     | source | created_by                                                      | updated_by                                                      | uploaded_at          | task_count | unknown_host_count | impacted_device_count | issue_count | cve_count |
| --- | --------------- | ---------- | ------ | --------------------------------------------------------------- | --------------------------------------------------------------- | -------------------- | ---------- | ------------------ | --------------------- | ----------- | --------- |
| 0   | 0               | processing | string | id: 0<br>firstname: string<br>lastname: string<br>email: string | id: 0<br>firstname: string<br>lastname: string<br>email: string | 2019-08-24T14:15:22Z | 0          | 0                  | 0                     | 0           | 0         |

### automox-vulnerability-sync-batches-list
***
Get a list of Vulnerability Sync batches.


#### Base Command

`automox-vulnerability-sync-batches-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.VulnSyncBatches.id | Number | Identifier of batch |
| Automox.VulnSyncBatches.organization_id | Number | Identifier of organization |
| Automox.VulnSyncBatches.status | String | Status of batch |
| Automox.VulnSyncBatches.source | String | Source of batch |
| Automox.VulnSyncBatches.created_by.id | Number | Identifier of user who created the batch |
| Automox.VulnSyncBatches.created_by.firstname | String | First name of the user who created the batch |
| Automox.VulnSyncBatches.created_by.lastname | String | Last name of the user who created the batch |
| Automox.VulnSyncBatches.created_by.email | String | Email of the user who created the batch |
| Automox.VulnSyncBatches.updated_by.id | Number | Identifier of the user who last updated the batch |
| Automox.VulnSyncBatches.updated_by.firstname | String | First name of the user who last updated the batch |
| Automox.VulnSyncBatches.updated_by.lastname | String | Last name of the user who last updated the batch |
| Automox.VulnSyncBatches.updated_by.email | String | Email off the user who last updated the batch |
| Automox.VulnSyncBatches.uploaded_at | Date | Datetime the batch was uploaded |
| Automox.VulnSyncBatches.task_count | Number | Number of tasks related to batch |
| Automox.VulnSyncBatches.unknown_host_count | Number | number of hosts that are unknown within batch |
| Automox.VulnSyncBatches.impacted_device_count | Number | Number of devices that are impacted by batch |
| Automox.VulnSyncBatches.issue_count | Number | Number of issues identified with batch |
| Automox.VulnSyncBatches.cve_count | Number | Number of CVEs that are impacted by batch |
#### Command Example
```
!automox-vulnerability-sync-batches-list
```

#### Human Readable Output
##### Batches
| id  | organization_id | status     | source | created_by                                                      | updated_by                                                      | uploaded_at          | task_count | unknown_host_count | impacted_device_count | issue_count | cve_count |
| --- | --------------- | ---------- | ------ | --------------------------------------------------------------- | --------------------------------------------------------------- | -------------------- | ---------- | ------------------ | --------------------- | ----------- | --------- |
| 0   | 0               | processing | string | id: 0<br>firstname: string<br>lastname: string<br>email: string | id: 0<br>firstname: string<br>lastname: string<br>email: string | 2019-08-24T14:15:22Z | 0          | 0                  | 0                     | 0           | 0         |

### automox-vulnerability-sync-tasks-list
***
Get a list of Automox tasks.


#### Base Command

`automox-vulnerability-sync-tasks-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| batch_id | Batch identifier. | Optional |
| status | Filter by status of tasks. Possible values are: pending, in_progress, completed, canceled. | Optional |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.VulnSyncTasks.id | Number | Identifier of task |
| Automox.VulnSyncTasks.organization_id | Number | Identifier of organization |
| Automox.VulnSyncTasks.task_type | String | Type of task |
| Automox.VulnSyncTasks.payload.patch_id | String | Identifier of patch associated with the task |
| Automox.VulnSyncTasks.payload.severity | String | Severity of patch associated with the task |
| Automox.VulnSyncTasks.payload.package_versions.id | String | Identifier of package associated with the task |
| Automox.VulnSyncTasks.payload.package_versions.name | String | Name of the package associated with the task |
| Automox.VulnSyncTasks.payload.package_versions.version | String | Version of the package associated with the task |
| Automox.VulnSyncTasks.payload.package_versions.display_name | String | Display name of the package associated with the task |
| Automox.VulnSyncTasks.payload.package_versions.requires_reboot | Boolean | Whether the package installed by the task will require a reboot |
| Automox.VulnSyncTasks.source | String | Source of task |
| Automox.VulnSyncTasks.notes | String | Notes associated with task |
| Automox.VulnSyncTasks.status | String | Status of task |
| Automox.VulnSyncTasks.created_by_user.id | Number | Identifier of user who created the task |
| Automox.VulnSyncTasks.created_by_user.email | String | Email of user who created the task |
| Automox.VulnSyncTasks.created_by_user.firstname | String | First name of user who created the task |
| Automox.VulnSyncTasks.created_by_user.lastname | String | Last name of user who created the task |
| Automox.VulnSyncTasks.last_updated_by_user.id | Number | Identifier of user who last updated the task |
| Automox.VulnSyncTasks.last_updated_by_user.email | String | Email of user who last updated the task |
| Automox.VulnSyncTasks.last_updated_by_user.firstname | String | First name of user who last updated the task |
| Automox.VulnSyncTasks.last_updated_by_user.lastname | String | Last name of user who last updated the task |
| Automox.VulnSyncTasks.created_at | Date | Datetime the task was created at |
| Automox.VulnSyncTasks.updated_at | Date | Datetime the task was last updated at |
| Automox.VulnSyncTasks.completed_at | Date | Datetime the task was completed |

#### Command Example
```
!automox-vulnerability-sync-tasks-list
```

#### Human Readable Output
##### Tasks
| id  | organization_id | task_type | payload                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | source  | notes | status            | created_by_user                                                           | last_updated_by_user                                                      | created_at               | updated_at               | completed_at | cves |
| --- | --------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----- | ----------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------ | ------------------------ | ------------ | ---- |
| 69  | 10586           | patch-now | {"patch_id": "CVE-2020-16937","severity": "critical","package_versions": [{"id": "226977092","name": "bcdd12d9-e56a-46be-88f6-8a97a9f9ad18","version": "200","display_name": "2020-10 Cumulative Update for .NET Framework 3.5 and 4.8 for Windows 10 Version 1903 for x64 (KB4578974)","requires_reboot": false},{"id": "226977252","name": "bcdd12d9-e56a-46be-88f6-8a97a9f9ad18","version": "200","display_name": "2020-10 Cumulative Update for .NET Framework 3.5 and 4.8 for Windows 10 Version 1903 for x64 (KB4578974)","requires_reboot": false}]} | Automox |       | awaiting_approval | id: 12381<br>email: user@example.com<br>firstname: user<br>lastname: user | id: 12381<br>email: user@example.com<br>firstname: user<br>lastname: user | 2021-09-10T13:51:40+0000 | 2021-09-10T13:51:40+0000 |              |      |
### automox-vulnerability-sync-file-upload
***
Upload a vulnerability report to Automox Vulnerability Sync.


#### Base Command

`automox-vulnerability-sync-file-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| entry_id | Entry ID of the CSV file to upload. | Required |
| csv_file_name | Name for CSV file uploaded and shown within Automox. Default is XSOAR-uploaded-report.csv. | Optional |
| reports_source | The third-party source of the vulnerability report. Default is Generic Report. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.VulnUpload.batch_id | Number | Identifier of batch |

#### Command Example
```
!automox-vulnerability-sync-file-upload
```

#### Human Readable Output
##### Upload
| batch_id |
| -------- |
| 0        |
### automox-policies-list
***
Retrieve a list of Automox policies belonging to an organization.


#### Base Command

`automox-policies-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.Policies.id | Number | Identifier of policy |
| Automox.Policies.organization_id | Number | Identifier of organization |
| Automox.Policies.name | String | Name of policy |
| Automox.Policies.policy_type_name | String | Policy type name |
| Automox.Policies.server_groups | Number | List of identifiers for device groups assigned to the policy |

#### Command Example
```
!automox-policies-list
```

#### Human Readable Output
##### Policies
| id  | organization_id | name   | policy_type_name | notes | server_count | server_groups | create_time |
| --- | --------------- | ------ | ---------------- | ----- | ------------ | ------------- | ----------- |
| 0   | 0               | string | patch            |       | 0            | 0             | string      |
### automox-command-run
***
Run a command on a device in Automox

#### Base Command

`automox-command-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| device_id | Device identifier. | Required |
| patches | List of patches to be installed by name. (Note: this only works with the InstallUpdate command). | Optional |
| command | Command to run on device. Possible values are: GetOS, InstallUpdate, InstallAllUpdates, Reboot. | Required |


#### Context Output
There is no context output for this command.

### automox-device-delete
***
Delete a device from Automox


#### Base Command

`automox-device-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| device_id | Device identifier. | Required |


#### Context Output

There is no context output for this command.
### automox-device-update
***
Update a device's information in Automox


#### Base Command

`automox-device-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| device_id | Device identifier. | Required |
| custom_name | Custom name to set on device. | Optional |
| exception | Exclude the device from reports and statistics. | Required |
| server_group_id | Identifier of server group. | Required |
| tags | List of tags to associate with the device. | Optional |
| ip_addrs | IP address of the device. | Optional |


#### Context Output

There is no context output for this command.
### automox-groups-list
***
List all groups in an Automox instance based on organization permissions.


#### Base Command

`automox-groups-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| limit | The maximum number of results to return per page. Default is 50. | Optional |
| page | The page of results to return. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.Groups.id | Number | Identifier of the created group |
| Automox.Groups.organization_id | Number | Identifier of organization |
| Automox.Groups.name | String | The name of the group |
| Automox.Groups.refresh_interval | Number | Frequency of device refreshes in minutes. |
| Automox.Groups.parent_server_group_id | Number | Identifier of parent group |
| Automox.Groups.ui_color | String | Automox console highlight color for the group |
| Automox.Groups.notes | String | Notes defined for the group |
| Automox.Groups.enable_os_auto_update | Boolean | Enable operating system auto updates |
| Automox.Groups.server_count | Number | Number of devices assigned to group |
| Automox.Groups.policies | Number | List of policies assigned to group |

#### Command Example
```
!automox-groups-list
```

#### Human Readable Output
##### Groups
| id  | organization_id | name   | refresh_interval | parent_server_group_id | ui_color | notes  | enable_os_auto_update | server_count | policies |
| --- | --------------- | ------ | ---------------- | ---------------------- | -------- | ------ | --------------------- | ------------ | -------- |
| 0   | 0               | string | 0                | 0                      | string   | string | true                  | 0            | 0        |
### automox-group-create
***
Create a group in Automox


#### Base Command

`automox-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| name | Name of the group. | Required |
| notes | Define notes for the group. | Optional |
| parent_server_group_id | Identifier of the parent group. Defaults to default group id if omitted. | Optional |
| policies | List of policy identifiers to assign to group. | Optional |
| refresh_interval | Frequency of device refreshes in minutes. (Must be between 360 and 1440). | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.CreatedGroups.id | Number | Identifier of the created group |
| Automox.CreatedGroups.organization_id | Number | Identifier of organization |
| Automox.CreatedGroups.name | String | The name of the group |
| Automox.CreatedGroups.refresh_interval | Number | Frequency of device refreshes in minutes |
| Automox.CreatedGroups.parent_server_group_id | Number | Identifier of parent group |
| Automox.CreatedGroups.ui_color | String | Automox console highlight color for the group |
| Automox.CreatedGroups.notes | String | Notes defined for the group |
| Automox.CreatedGroups.enable_os_auto_update | Boolean | Enable operating system auto updates |
| Automox.CreatedGroups.server_count | Number | Number of devices assigned to group |
| Automox.CreatedGroups.policies | Number | List of policies assigned to group |

#### Command Example
```
!automox-group-create
```

#### Human Readable Output
##### Group
| id  | organization_id | name   | refresh_interval | parent_server_group_id | ui_color | notes  | enable_os_auto_update | server_count | policies |
| --- | --------------- | ------ | ---------------- | ---------------------- | -------- | ------ | --------------------- | ------------ | -------- |
| 0   | 0               | string | 0                | 0                      | string   | string | true                  | 0            | 0        |
### automox-group-update
***
Update a group's information in Automox


#### Base Command

`automox-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| group_id | Group identifier. | Required |
| name | Name of the group. | Optional |
| notes | Define notes for the group. | Optional |
| parent_server_group_id | Identifier of the parent group. Defaults to default group id if omitted. | Optional |
| policies | List of policy identifiers to assign to group. | Optional |
| refresh_interval | Frequency of device refreshes in minutes. | Optional |


#### Context Output

There is no context output for this command.
### automox-group-delete
***
Delete a group from Automox


#### Base Command

`automox-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
| group_id | Group identifier. | Required |


#### Context Output

There is no context output for this command.
