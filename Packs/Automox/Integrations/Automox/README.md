Use the Automox integration to create device groups, update devices, run policies, and remediate vulnerabilities of devices through the Automox platform.
This integration was integrated and tested as of 2022-03-21 with the Automox API

## Configure Automox in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Organization ID | A comma-separated list of organization ids. When specified, data pulled from Automox will only belong to this organization; otherwise, the default permissions for this API key will be used. | False |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### automox-devices-list
***
List all devices in Automox based on group and organization permissions.


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
!automox-devices-list limit=1
```

#### Context Example
```json
{
    "Automox": {
        "Devices": {
            "agent_version": "string",
            "commands": [
                {
                    "command_type_name": "InstallUpdate",
                    "args": "KB12345 KB67890",
                    "exec_time": "2017-06-29T16:39:50.951Z"
                }
            ],
            "compliant": true,
            "connected": true,
            "create_time": "2019-08-24T14:15:22Z",
            "custom_name": "string",
            "deleted": true,
            "display_name": "string",
            "exception": true,
            "id": 0,
            "ip_addrs": [
                "string"
            ],
            "ip_addrs_private": [
                "string"
            ],
            "is_compatible": true,
            "is_delayed_by_notification": true,
            "is_delayed_by_user": true,
            "last_disconnect_time": "2019-08-24T14:15:22Z",
            "last_logged_in_user": "string",
            "last_process_time": "string",
            "last_refresh_time": "string",
            "last_scan_failed": true,
            "last_update_time": "string",
            "name": "string",
            "needs_attention": true,
            "needs_reboot": true,
            "next_patch_time": "string",
            "notification_count": 0,
            "organization_id": 0,
            "os_family": "string",
            "os_name": "string",
            "os_version": "string",
            "patch_deferral_count": 0,
            "patches": 0,
            "pending": true,
            "pending_patches": 0,
            "policy_status": [
                {
                    "id": 0,
                    "organization_id": 0,
                    "policy_id": 0,
                    "server_id": 0,
                    "policy_name": "string",
                    "policy_type_name": "patch",
                    "status": 0,
                    "result": "string",
                    "create_time": "string"
                }
            ],
            "reboot_is_delayed_by_notification": true,
            "reboot_is_delayed_by_user": true,
            "reboot_notification_count": 0,
            "refresh_interval": 0,
            "serial_number": "string",
            "server_group_id": 0,
            "status": {
                "device_status": "string",
                "agent_status": "string",
                "policy_status": "string",
                "policy_statuses": [
                    {
                        "id": 0,
                        "compliant": true
                    }
                ]
            },
            "tags": [
                "string"
            ],
            "timezone": "string",
            "total_count": 0,
            "uptime": 0,
            "uuid": "095be615-a8ad-4c33-8e9c-c7612fbf6c9f"
        }
    }
}
```

#### Human Readable Output
>### Devices
>| agent_version | commands                                                                                                | compliant | connected | create_time          | custom_name | deleted | display_name | exception | id  | ip_addrs | ip_addrs_private | is_compatible | is_delayed_by_notification | is_delayed_by_user | last_disconnect_time | last_logged_in_user | last_process_time | last_refresh_time | last_scan_failed | last_update_time | name   | needs_attention | needs_reboot | next_patch_time | notification_count | organization_id | os_family | os_name | os_version | patch_deferral_count | patches | pending | pending_patches | policy_status                                                                                                                                                           | reboot_is_delayed_by_notification | reboot_is_delayed_by_user | reboot_notification_count | refresh_interval | serial_number | server_group_id | status                                                                                                                          | tags   | timezone | total_count | uptime | uuid                                 |
>| ------------- | ------------------------------------------------------------------------------------------------------- | --------- | --------- | -------------------- | ----------- | ------- | ------------ | --------- | --- | -------- | ---------------- | ------------- | -------------------------- | ------------------ | -------------------- | ------------------- | ----------------- | ----------------- | ---------------- | ---------------- | ------ | --------------- | ------------ | --------------- | ------------------ | --------------- | --------- | ------- | ---------- | -------------------- | ------- | ------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ------------------------- | ------------------------- | ---------------- | ------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- | ----------- | ------ | ------------------------------------ |
>| string        | command_type_name: InstallUpdate<br>args: KB12345 KB67890<br>exec_time: 2017-06-29T16:39:50.951Z | true      | true      | 2019-08-24T14:15:22Z | string      | true    | string       | true      | 0   | 1.1.1.1  | 1.1.1.1          | true          | true                       | true               | 2019-08-24T14:15:22Z | string              | string            | string            | true             | string           | string | true            | true         | string          | 0                  | 0               | string    | string  | string     | 0                    | 0       | true    | 0               | id: 0<br>organization_id: 0<br>policy_id: 0<br>server_id: 0<br>policy_name: string<br>policy_type_name: patch<br>status: 0<br>result: string<br>create_time: string | true                              | true                      | 0                         | 0                | string        | 0               | {"device_status": "string","agent_status": "string","policy_status": "string","policy_statuses": [{"id": 0,"compliant": true}]} | string | string   | 0           | 0      | 095be615-a8ad-4c33-8e9c-c7612fbf6c9f |

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

#### Command example
```!automox-organizations-list limit=1```
#### Context Example
```json
{
    "Automox": {
        "Organizations": {
            "create_time": "2019-08-27T21:59:19+0000",
            "device_count": 26,
            "device_limit": null,
            "id": 9237,
            "name": "string",
            "parent_id": 65,
            "server_limit": 0
        }
    }
}
```

#### Human Readable Output
>### Organizations
>| create_time              | device_count | device_limit | id   | name   | parent_id | server_limit |
>| ------------------------ | ------------ | ------------ | ---- | ------ | --------- | ------------ |
>| 2019-08-27T21:59:19+0000 | 26           |              | 9237 | string | 65        | 0            |
### automox-organization-users-list
***
List all Automox users within an organization.


#### Base Command

`automox-organization-users-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization identifier. | Optional |
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

#### Command example
```!automox-organization-users-list limit=1```
#### Context Example
```json
{
    "Automox": {
        "Users": {
            "email": "string",
            "firstname": "string",
            "id": 1,
            "lastname": "string",
            "orgs": [
                {
                    "id": 1,
                    "name": "string"
                }
            ],
            "rbac_roles": [
                {
                    "id": 0,
                    "name": "string",
                    "organization_id": 1
                }
            ],
            "saml_enabled": true,
            "tags": [
                "string"
            ]
        }
    }
}
```

#### Human Readable Output
##### Organization Users
| id  | firstname | lastname | email  | orgs                         | tags   | saml_enabled | rbac_roles                                        |
| --- | --------- | -------- | ------ | ---------------------------- | ------ | ------------ | ------------------------------------------------- |
| 0   | string    | string   | string | id: 0<br>name: string | string | true         | id: 0<br>name: string<br>organization_id: 0 |
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
!automox-vulnerability-sync-batch-get batch_id=1
```

#### Context Example
```json
{
    "Automox": {
        "Batch": {
            "created_by": {
                "id": 0,
                "firstname": "string",
                "lastname": "string",
                "email": "string"
            },
            "cve_count": 0,
            "id": 1,
            "impacted_device_count": 0,
            "issue_count": 0,
            "organization_id": 1,
            "source": "string",
            "status": "processing",
            "task_count": 0,
            "unknown_host_count": 0,
            "updated_by": {
                "id": 0,
                "firstname": "string",
                "lastname": "string",
                "email": "string"
            },
            "uploaded_at": "2019-08-24T14:15:22Z"
        }
    }
}
```

#### Human Readable Output
>### Batch
>| created_by                                                          | cve_count | id  | impacted_device_count | issue_count | organization_id | source | status     | task_count | unknown_host_count | updated_by                                                          | uploaded_at          |
>| ------------------------------------------------------------------- | --------- | --- | --------------------- | ----------- | --------------- | ------ | ---------- | ---------- | ------------------ | ------------------------------------------------------------------- | -------------------- |
>| id: 0<br>firstname: string<br>lastname: string<br>email: string<br> | 0         | 1   | 0                     | 0           | 1               | string | processing | 0          | 0                  | id: 0<br>firstname: string<br>lastname: string<br>email: string<br> | 2019-08-24T14:15:22Z |

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
#### Command example
```!automox-vulnerability-sync-batches-list limit=1```
#### Context Example
```json
{
    "Automox": {
        "VulnSyncBatches": {
            "created_by": {
                "id": 0,
                "firstname": "string",
                "lastname": "string",
                "email": "string"
            },
            "cve_count": 0,
            "id": 1,
            "impacted_device_count": 0,
            "issue_count": 0,
            "organization_id": 1,
            "source": "string",
            "status": "processing",
            "task_count": 0,
            "unknown_host_count": 0,
            "updated_by": {
                "id": 0,
                "firstname": "string",
                "lastname": "string",
                "email": "string"
            },
            "uploaded_at": "2019-08-24T14:15:22Z"
        }
    }
}
```

#### Human Readable Output
>### Batches
>| created_by                                                          | cve_count | id  | impacted_device_count | issue_count | organization_id | source | status     | task_count | unknown_host_count | updated_by                                                          | uploaded_at          |
>| ------------------------------------------------------------------- | --------- | --- | --------------------- | ----------- | --------------- | ------ | ---------- | ---------- | ------------------ | ------------------------------------------------------------------- | -------------------- |
>| id: 0<br>firstname: string<br>lastname: string<br>email: string<br> | 0         | 1   | 0                     | 0           | 1               | string | processing | 0          | 0                  | id: 0<br>firstname: string<br>lastname: string<br>email: string<br> | 2019-08-24T14:15:22Z |

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

#### Command example
```!automox-vulnerability-sync-tasks-list limit=1```
#### Context Example
```json
{
    "Automox": {
        "VulnSyncTasks": {
            "completed_at": "2022-03-30 20:00:03",
            "created_at": "2022-03-29T19:46:12+0000",
            "created_by_user": {
                "email": "string",
                "firstname": "string",
                "id": 19017,
                "lastname": "string"
            },
            "cves": [],
            "id": 1221,
            "last_updated_by_user": {
                "email": "string",
                "firstname": "string",
                "id": 19017,
                "lastname": "string"
            },
            "notes": "",
            "organization_id": 9237,
            "payload": {
                "package_versions": [
                    {
                        "display_name": "2020-05 Cumulative Update for Windows 10 Version 1809 for x64-based Systems (KB4551853)",
                        "id": "223683225",
                        "name": "3f646594-9a4f-4b7a-bb7b-1932a5b490a6",
                        "requires_reboot": false,
                        "version": "1"
                    },
                ],
                "patch_id": "CVE-2018-0886",
                "severity": "critical"
            },
            "source": "Automox",
            "status": "executed",
            "task_type": "patch-now",
            "updated_at": "2022-03-30T20:00:03+0000"
        }
    }
}
```

#### Human Readable Output
>### Tasks
>|completed_at|created_at|created_by_user|cves|id|last_updated_by_user|notes|organization_id|payload|source|status|task_type|updated_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-03-30 20:00:03 | 2022-03-29T19:46:12+0000 | id: 19017<br/>email: string<br/>firstname: string<br/>lastname: string |  | 1221 | id: 19017<br/>email: string<br/>firstname: string<br/>lastname: string |  | 9237 | patch_id: CVE-2018-0886<br/>severity: critical<br/>package_versions: {'id': '223683225', 'name': '3f646594-9a4f-4b7a-bb7b-1932a5b490a6', 'version': '1', 'display_name': '2020-05 Cumulative Update for Windows 10 Version 1809 for x64-based Systems (KB4551853)', 'requires_reboot': False} | Automox | executed | patch-now | 2022-03-30T20:00:03+0000 |
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
| type | The type of task to create | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Automox.VulnUpload.batch_id | Number | Identifier of batch |

#### Command example
```!automox-vulnerability-sync-file-upload entry_id="1075@1a203850-514b-4ba5-848e-f944bd9ab460"```
#### Context Example
```json
{
    "Automox": {
        "VulnUpload": {
            "batch_id": 1241
        }
    }
}
```

#### Human Readable Output
### Upload
| batch_id |
| -------- |
| 1241     |
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

#### Command example
```!automox-policies-list limit=1```
#### Context Example
```json
{
    "Automox": {
        "Policies": {
            "create_time": "2021-03-03T21:29:09+0000",
            "id": 112411,
            "name": "string",
            "notes": "",
            "organization_id": 9237,
            "policy_type_name": "patch",
            "server_count": 1,
            "server_groups": [
                85579,
                86754
            ]
        }
    }
}
```

#### Human Readable Output
>### Policies
>| create_time              | id     | name             | notes | organization_id | policy_type_name | server_count | server_groups
>| ------------------------ | ------ | ---------------- | ----- | --------------- | ---------------- | ------------ | ---------------
>| 2021-03-03T21:29:09+0000 | 112411 | string |       | 9237            | patch            | 1            | 85579,<br>86754
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
#### Command example
```!automox-command-run command=GetOS device_id=1375363```
#### Human Readable Output

>Command: GetOS successfully sent to Automox device ID: 1375363
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
List all groups in Automox based on organization permissions.


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
| Automox.Groups.deleted | Boolean | Whether a group is deleted |

#### Command example
```!automox-groups-list limit=1```
#### Context Example
```json
{
    "Automox": {
        "Groups": {
            "enable_os_auto_update": true,
            "id": 1,
            "name": "string",
            "notes": "string",
            "organization_id": 1,
            "parent_server_group_id": 0,
            "policies": [
                163746,
                167809,
                172118,
                172076,
                156951,
                147303
            ],
            "refresh_interval": 360,
            "server_count": 5,
            "ui_color": "#059F1D",
            "deleted": false
        }
    }
}
```

#### Human Readable Output
##### Groups
| id  | organization_id | name   | refresh_interval | parent_server_group_id | ui_color | notes  | enable_os_auto_update | server_count | policies | deleted |
| --- | --------------- | ------ | ---------------- | ---------------------- | -------- | ------ | --------------------- | ------------ | -------- | ------- |
| 0   | 0               | string | 0                | 0                      | string   | string | true                  | 0            | 0        | false   |
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
| color | Automox console highlight color for the group. Value should be a valid Hex color code | Optional |


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
| color | Automox console highlight color for the group. Value should be a valid Hex color code | Optional |


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