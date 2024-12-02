Veeam Backup & Replication REST API allows you to query information about Veeam Backup & Replication entities and perform operations with these entities using HTTP requests and standard HTTP methods.
This integration was integrated and tested with version 1.1-rev2 of VBR REST API.

## Configure Veeam Backup & Replication REST API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username |  | True |
| Password |  | True |
| Resource URL |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| First fetch time |  | False |
| Fetch configuration backup events |  | False |
| Days Since Last Configuration Backup | An incident will be created If the last successful configuration backup is older than the specified value. | False |
| Fetch backup repository events |  | False |
| Backup Repository Free Space (GB) | An incident will be created If the backup repository free space is less than the specified value. | False |
| Backup Repository Events Per Request | The maximum number of backup repository events that can be fetched during command execution. | False |
| Fetch malware events |  | False |
| Malware Events Per Request | The maximum number of malware events that can be fetched during command execution. | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### veeam-vbr-create-malware-event

***
Create Malware Event

#### Base Command

`veeam-vbr-create-malware-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectiontimeutc | 'Detection date and time, in UTC.' | Required | 
| machine_fqdn | Machine FQDN. | Optional | 
| machine_ipv4 | Machine IPv4 address. | Optional | 
| machine_ipv6 | Machine IPv6 address. | Optional | 
| machine_uuid | Machine BIOS UUID in the 8-4-4-4-12 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. | Optional | 
| details | 'Event description.' | Required | 
| engine | 'Detection engine.' | Required | 

#### Context Output

There is no context output for this command.

### veeam-vbr-get-all-malware-events

***
Get All Malware Events

#### Base Command

`veeam-vbr-get-malware-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Number of events to skip. | Optional | 
| limit | Maximum number of events to return. Default is 100. | Optional | 
| orderColumn | Sorts events by event meter. | Optional | 
| orderAsc | Sorts events in the ascending order by the `orderColumn` meter. | Optional | 
| typeFilter | Filters events by event type. | Optional | 
| detectedAfterTimeUtcFilter | Returns events created after the specified time, in UTC. | Optional | 
| detectedBeforeTimeUtcFilter | Returns events created before the specified time, in UTC. | Optional | 
| backupObjectIdFilter | Filters events by backup object ID. | Optional | 
| stateFilter | Filters events by state. | Optional | 
| sourceFilter | Filters events by source type. | Optional | 
| severityFilter | Filters events by severity. | Optional | 
| createdByFilter | Filters events by the `createdBy` pattern. To substitute one or more characters, use the asterisk (*) character at the beginning, at the end, or both. | Optional | 
| engineFilter | Filters events by the `engine` pattern. To substitute one or more characters, use the asterisk (*) character at the beginning, at the end, or both. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_malware_events.data.id | String | Event ID. | 
| Veeam.VBR.get_malware_events.data.type | String | Event type. | 
| Veeam.VBR.get_malware_events.data.detectionTimeUtc | String | Detection date and time, in UTC. | 
| Veeam.VBR.get_malware_events.data.state | String | Event state. | 
| Veeam.VBR.get_malware_events.data.details | String | Event description. | 
| Veeam.VBR.get_malware_events.data.source | String | Event source type. | 
| Veeam.VBR.get_malware_events.data.severity | String | Malware status. | 
| Veeam.VBR.get_malware_events.data.createdBy | String | User account created the event. | 
| Veeam.VBR.get_malware_events.data.engine | String | Detection engine. | 

### veeam-vbr-get-all-repository-states

***
Get All Repository States

#### Base Command

`veeam-vbr-get-repository-states`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Number of repository states to skip. | Optional | 
| limit | Maximum number of repository states to return. Default is 100. | Optional | 
| orderColumn | Sorts repository states by state meter. | Optional | 
| orderAsc | Sorts repository states in the ascending order by the `orderColumn` meter. | Optional | 
| idFilter | Filters repository states by repository ID. | Optional | 
| nameFilter | Filters repository states by the `nameFilter` pattern. The pattern can match any repository state meter. To substitute one or more characters, use the asterisk (*) character at the beginning, at the end, or both. | Optional | 
| typeFilter | Filters repository states by repository type. | Optional | 
| capacityFilter | Filters repository states by repository capacity. | Optional | 
| freeSpaceFilter | Filters repository states by repository free space. | Optional | 
| usedSpaceFilter | Filters repository states by repository used space. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_repository_states.data.id | String | Backup repository ID. | 
| Veeam.VBR.get_repository_states.data.name | String | Backup repository name. | 
| Veeam.VBR.get_repository_states.data.type | String | Backup repository type. | 
| Veeam.VBR.get_repository_states.data.description | String | Description of the backup repository. | 
| Veeam.VBR.get_repository_states.data.capacityGB | String | Repository capacity in GB. | 
| Veeam.VBR.get_repository_states.data.freeGB | String | Repository free space in GB. | 
| Veeam.VBR.get_repository_states.data.usedSpaceGB | String | Repository used space in GB. | 
| Veeam.VBR.get_repository_states.data.hostId | String | ID of the server that is used as a backup repository. | 
| Veeam.VBR.get_repository_states.data.hostName | String | Name of the server that is used as a backup repository. | 
| Veeam.VBR.get_repository_states.data.path | String | Path to the folder where backup files are stored. | 

### veeam-vbr-get-all-restore-points

***
Get All Restore Points

#### Base Command

`veeam-vbr-get-restore-points`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Number of restore points to skip. | Optional | 
| limit | Maximum number of restore points to return. Default is 100. | Optional | 
| orderColumn | Sorts restore points by restore point meter. | Optional | 
| orderAsc | Sorts restore points in the ascending order by the `orderColumn` meter. | Optional | 
| createdAfterFilter | Returns restore points created after the specified date and time. | Optional | 
| createdBeforeFilter | Returns restore points created before the specified date and time. | Optional | 
| nameFilter | Filters restore points by the `nameFilter` pattern. The pattern can match any restore point meter. To substitute one or more characters, use the asterisk (*) character at the beginning and/or at the end. | Optional | 
| platformNameFilter | Filters restore points by name of the backup object platform. | Optional | 
| platformIdFilter | Filters restore points by ID of the backup object platform. | Optional | 
| backupIdFilter | Filters restore points by backup ID. | Optional | 
| backupObjectIdFilter | Filters restore points by backup object ID. | Optional | 
| malwareStatusFilter | Filters restore points by malware status. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_restore_points.data.id | String | Restore point ID. | 
| Veeam.VBR.get_restore_points.data.name | String | Object name. | 
| Veeam.VBR.get_restore_points.data.platformId | String | ID of a platform where the object was created. | 
| Veeam.VBR.get_restore_points.data.creationTime | String | Date and time when the restore point was created. | 
| Veeam.VBR.get_restore_points.data.backupId | String | ID of a backup that contains the restore point. | 
| Veeam.VBR.get_restore_points.data.platformName | String | Platform name. | 
| Veeam.VBR.get_restore_points.data.malwareStatus | String | Malware status. | 

### veeam-vbr-get-backup-object

***
Get Backup Object

#### Base Command

`veeam-vbr-get-backup-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | ID of the backup object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.backup_object.objectId | String | ID of the virtual infrastructure object \(mo-ref or ID, depending on the virtualization platform\). | 
| Veeam.VBR.backup_object.viType | String | Type of the VMware vSphere object. | 
| Veeam.VBR.backup_object.path | String | Path to the object. | 
| Veeam.VBR.backup_object.id | String | Object ID. | 
| Veeam.VBR.backup_object.name | String | Object name. | 
| Veeam.VBR.backup_object.type | String | Object type. | 
| Veeam.VBR.backup_object.vcenter_name | string | Name of the vCenter Server. | 

### veeam-vbr-get-configuration-backup

***
Get Configuration Backup

#### Base Command

`veeam-vbr-get-configuration-backup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_configuration_backup.isEnabled | String | If \`true\`, configuration backup is enabled. | 
| Veeam.VBR.get_configuration_backup.backupRepositoryId | String | ID of the backup repository on which the configuration backup is stored. | 
| Veeam.VBR.get_configuration_backup.restorePointsToKeep | number | Number of restore points to keep in the backup repository. | 
| Veeam.VBR.get_configuration_backup.Schedule | Scheduling settings. |  | 
| Veeam.VBR.get_configuration_backup.Encryption | Encryption settings. |  | 
| Veeam.VBR.get_configuration_backup.LastSuccessfulBackup | Last successful backup. |  | 

### veeam-vbr-get-inventory-objects

***
Get Inventory Objects

#### Base Command

`veeam-vbr-get-inventory-objects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resetCache | If `true`, the cache will be reset for this request. Resetting the cache slows down request processing but allows you to get up-to-date data. | Optional | 
| hostname | Server name. | Required | 
| skip | Number of objects to skip. | Optional | 
| limit | Maximum number of objects to return. Default is 100. | Optional | 
| filter | Filter settings. | Optional | 
| sorting | Sorting settings. | Optional | 
| hierarchyType | Hierarchy type. | Optional | 
| objectName | Object name. | Optional | 
| viType | Type of the VMware vSphere object. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_inventory_objects.data.name | String | Name of the VMware vSphere object. | 
| Veeam.VBR.get_inventory_objects.data.type | String | Type of the VMware vSphere object. | 
| Veeam.VBR.get_inventory_objects.data.hostName | String | Name of the VMware vSphere server that hosts the object. | 
| Veeam.VBR.get_inventory_objects.data.objectId | String | ID of the VMware vSphere object. The parameter is required for all VMware vSphere objects except vCenter Servers and standalone ESXi hosts. | 
| Veeam.VBR.get_inventory_objects.data.urn | String | Object URN. | 
| Veeam.VBR.get_inventory_objects.data.platform | String | Platform name. | 
| Veeam.VBR.get_inventory_objects.data.size | String | Object size. | 

### veeam-vbr-get-session

***
Get Session

#### Base Command

`veeam-vbr-get-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | Session ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_session.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.get_session.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.get_session.id | String | Session ID. | 
| Veeam.VBR.get_session.name | String | Session name. | 
| Veeam.VBR.get_session.sessionType | String | Session type. | 
| Veeam.VBR.get_session.state | String | Session state. | 
| Veeam.VBR.get_session.usn | String | Update sequence number. | 
| Veeam.VBR.get_session.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.get_session.progressPercent | String | Progress percentage of the session. | 
| Veeam.VBR.get_session.result | unknown | Session result. | 
| Veeam.VBR.get_session.resourceId | String | Resource ID. | 
| Veeam.VBR.get_session.resourceReference | String | URI of the resource. | 
| Veeam.VBR.get_session.parentSessionId | String | Parent session ID. | 

### veeam-vbr-start-configuration-backup

***
Start Configuration Backup

#### Base Command

`veeam-vbr-start-configuration-backup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.Configurationbackuphasbeenstarted.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.id | String | Session ID. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.name | String | Session name. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.sessionType | String | Session type. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.state | String | Session state. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.usn | String | Update sequence number. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.progressPercent | String | Progress percentage of the session. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.resourceId | String | Resource ID. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.resourceReference | String | URI of the resource. | 
| Veeam.VBR.Configurationbackuphasbeenstarted.parentSessionId | String | Parent session ID. | 

### veeam-vbr-start-instant-recovery-customized

***
Start Customized VM Instant Recovery

#### Base Command

`veeam-vbr-start-instant-recovery-customized`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restorePointId | Restore point ID. | Required | 
| vmTagsRestoreEnabled | If `true`, Veeam Backup &amp; Replication restores tags that were assigned to the original VM, and assign them to the restored VM. | Optional | 
| antivirusScanEnabled | If `true`, Veeam Backup &amp; Replication scans machine data with antivirus software before restoring the machine to the production environment. | Required | 
| virusDetectionAction | Action that Veeam Backup &amp; Replication takes if the antivirus software finds a threat. | Optional | 
| entireVolumeScanEnabled | If `true`, the antivirus continues machine scan after the first malware is found. | Optional | 
| nicsEnabled | If `true`, the restored VM is connected to the network. | Optional | 
| powerUp | If `true`, Veeam Backup &amp; Replication powers on the restored VM on the target host. | Optional | 
| reason | Reason for restoring the VM. | Optional | 
| restoredVmName | Restored VM name. | Optional | 
| vCenterName | Name of the vCenter Server. | Required | 
| hostObjectId | ID of the VMware vSphere object. The parameter is required for all VMware vSphere objects except vCenter Servers and standalone ESXi hosts. | Required | 
| folderObjectId | ID of the VMware vSphere object. The parameter is required for all VMware vSphere objects except vCenter Servers and standalone ESXi hosts. | Required | 
| resObjectId | ID of the VMware vSphere object. The parameter is required for all VMware vSphere objects except vCenter Servers and standalone ESXi hosts. | Optional | 
| platform | Platform name. | Required | 
| biosUuidPolicy | BIOS UUID policy for the restored VM. | Required | 
| redirectEnabled | If `true`, redo logs are redirected to `cacheDatastore`. | Required | 
| overwrite | If `true`, Veeam Backup &amp; Replication overwrites the existing VM that has the same name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_recovery.id | string | Session ID. | 
| Veeam.VBR.start_recovery.name | string | Session name. | 
| Veeam.VBR.start_recovery.jobId | string | ID of the job or job related activity. | 
| Veeam.VBR.start_recovery.sessionType | string | Session type. | 
| Veeam.VBR.start_recovery.creationTime | string | Date and time when the session was created. | 
| Veeam.VBR.start_recovery.state | string | Session state. | 
| Veeam.VBR.start_recovery.endTime | string | Date and time when the session was ended. | 
| Veeam.VBR.start_recovery.usn | string | Update sequence number. | 

### veeam-vbr-start-instant-recovery

***
Start VM Instant Recovery to Original Location

#### Base Command

`veeam-vbr-start-instant-recovery`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restorePointId | Restore point ID. | Required | 
| vmTagsRestoreEnabled | If `true`, Veeam Backup &amp; Replication restores tags that were assigned to the original VM, and assign them to the restored VM. | Optional | 
| antivirusScanEnabled | If `true`, Veeam Backup &amp; Replication scans machine data with antivirus software before restoring the machine to the production environment. | Required | 
| virusDetectionAction | Action that Veeam Backup &amp; Replication takes if the antivirus software finds a threat. | Optional | 
| entireVolumeScanEnabled | If `true`, the antivirus continues machine scan after the first malware is found. | Optional | 
| nicsEnabled | If `true`, the restored VM is connected to the network. | Optional | 
| powerUp | If `true`, Veeam Backup &amp; Replication powers on the restored VM on the target host. | Optional | 
| reason | Reason for restoring the VM. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_recovery.id | string | Session ID. | 
| Veeam.VBR.start_recovery.name | string | Session name. | 
| Veeam.VBR.start_recovery.jobId | string | ID of the job or job related activity. | 
| Veeam.VBR.start_recovery.sessionType | string | Session type. | 
| Veeam.VBR.start_recovery.creationTime | string | Date and time when the session was created. | 
| Veeam.VBR.start_recovery.state | string | Session state. | 
| Veeam.VBR.start_recovery.endTime | string | Date and time when the session was ended. | 
| Veeam.VBR.start_recovery.usn | string | Update sequence number. | 