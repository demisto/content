Veeam Backup & Replication REST API allows you to query information about Veeam Backup & Replication entities and perform operations with these entities using HTTP requests and standard HTTP methods.
This integration was integrated and tested with version 1.2-rev2 of VBR REST API.

## Configure Veeam Backup & Replication REST API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username |  | True |
| Password |  | True |
| Resource URL |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| First Fetch Time |  | False |
| Fetch configuration backup events |  | False |
| Days Since Last Configuration Backup | An incident will be created If the last successful configuration backup is older than the specified value. | False |
| Fetch backup repository events |  | False |
| Backup Repository Free Space (GB) | An incident will be created If the backup repository free space is less than the specified value. | False |
| Backup Repository Events Per Request | The maximum number of backup repository events that can be fetched during command execution. | False |
| Fetch malware events |  | False |
| Malware Events Per Request | The maximum number of malware events that can be fetched during command execution. | False |
| API Request Timeout (Seconds) |  | False |
| Fetch Security &amp; Compliance Analyzer events |  | False |
| Fetch SureBackup job events |  | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |
| API Version | API version and revision used by the Veeam Backup &amp; Replication instance. Supported values for version 12: 1.2-rev0, 1.2-rev1. Supported values for version 13: 1.3-rev0, 1.3-rev1. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### veeam-vbr-create-malware-event

***
Create Malware Event.

#### Base Command

`veeam-vbr-create-malware-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectiontimeutc | Detection date and time, in UTC. | Required | 
| machine_fqdn | Machine FQDN. | Required | 
| machine_ipv4 | Machine IPv4 address. | Required | 
| machine_ipv6 | Machine IPv6 address. | Optional | 
| machine_uuid | Machine BIOS UUID in the 8-4-4-4-12 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. | Optional | 
| details | Event description. | Required | 
| engine | Detection engine. | Required | 

#### Context Output

There is no context output for this command.
### veeam-vbr-get-malware-events

***
Get All Malware Events.

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

### veeam-vbr-get-yara-rules

***
Get All YARA Rules.

#### Base Command

`veeam-vbr-get-yara-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_yara_rules.data.fileName | String | YARA rule file name. | 

### veeam-vbr-get-repository-states

***
Get All Repository States.

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

### veeam-vbr-get-restore-points

***
Get All Restore Points.

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
Get Backup Object.

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
| Veeam.VBR.backup_object.platformName | string | Platform type. | 

### veeam-vbr-get-configuration-backup

***
Get Configuration Backup.

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
| Veeam.VBR.get_configuration_backup.Schedule | unknown | Scheduling settings. | 
| Veeam.VBR.get_configuration_backup.Encryption | unknown | Encryption settings. | 
| Veeam.VBR.get_configuration_backup.LastSuccessfulBackup | unknown | Last successful backup. | 

### veeam-vbr-get-inventory-objects

***
Get Inventory Objects.

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
Get Session.

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

### veeam-vbr-get-session-logs

***
Get Session Logs. Returns log records for the specified session.

#### Base Command

`veeam-vbr-get-session-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | Session ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_session_logs.totalRecords | Number | Total number of log records. | 
| Veeam.VBR.get_session_logs.records.id | Number | ID of the log record. | 
| Veeam.VBR.get_session_logs.records.status | String | Status of the log record. | 
| Veeam.VBR.get_session_logs.records.startTime | String | Date and time when the operation was started. | 
| Veeam.VBR.get_session_logs.records.updateTime | String | Date and time when the log record was updated. | 
| Veeam.VBR.get_session_logs.records.title | String | Title of the log record. | 
| Veeam.VBR.get_session_logs.records.description | String | Description of the log record. | 
| Veeam.VBR.get_session_logs.records.additionalInfo | String | Additional information of the log record. | 

### veeam-vbr-start-configuration-backup

***
Start Configuration Backup.

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
Start Customized VM Instant Recovery.

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
Start VM Instant Recovery to Original Location.

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

### veeam-vbr-start-instant-recovery-hyperv-vm

***
Start Instant Recovery of Microsoft Hyper-V VM to original location.

#### Base Command

`veeam-vbr-start-instant-recovery-hyperv-vm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restorePointId | Restore point ID. | Required | 
| antivirusScanEnabled | If `true`, Veeam Backup &amp; Replication scans machine data with antivirus software before restoring the machine to the production environment. | Required | 
| virusDetectionAction | Action that Veeam Backup &amp; Replication takes if the antivirus software finds a threat. Possible values are: DisableNetwork, AbortRecovery, Ignore. | Optional | 
| entireVolumeScanEnabled | If `true`, the antivirus continues machine scan after the first malware is found. | Optional | 
| powerUp | If `true`, Veeam Backup &amp; Replication powers on the restored VM on the target host. | Optional | 
| reason | Reason for restoring the VM. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_hv_recovery.id | String | Session ID. | 
| Veeam.VBR.start_hv_recovery.name | String | Session name. | 
| Veeam.VBR.start_hv_recovery.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.start_hv_recovery.sessionType | String | Session type. | 
| Veeam.VBR.start_hv_recovery.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.start_hv_recovery.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.start_hv_recovery.state | String | Session state. | 
| Veeam.VBR.start_hv_recovery.progressPercent | Number | Progress percentage of the session. | 
| Veeam.VBR.start_hv_recovery.result | unknown | Session result. | 
| Veeam.VBR.start_hv_recovery.resourceId | String | ID of the resource. | 
| Veeam.VBR.start_hv_recovery.resourceReference | String | URI of the resource. | 
| Veeam.VBR.start_hv_recovery.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.start_hv_recovery.usn | Number | Update sequence number. | 
| Veeam.VBR.start_hv_recovery.platformName | String | Platform type. | 
| Veeam.VBR.start_hv_recovery.platformId | String | ID of the resource platform. | 
| Veeam.VBR.start_hv_recovery.initiatedBy | String | Name of the user who initiated the session. | 
| Veeam.VBR.start_hv_recovery.relatedSessionId | String | ID of the related session. | 

### veeam-vbr-start-instant-recovery-hyperv-vm-customized

***
Start Instant Recovery of Microsoft Hyper-V VM to a customized location.

#### Base Command

`veeam-vbr-start-instant-recovery-hyperv-vm-customized`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restorePointId | Restore point ID. | Required | 
| antivirusScanEnabled | If `true`, Veeam Backup &amp; Replication scans machine data with antivirus software before restoring the machine to the production environment. | Required | 
| virusDetectionAction | Action that Veeam Backup &amp; Replication takes if the antivirus software finds a threat. Possible values are: DisableNetwork, AbortRecovery, Ignore. | Optional | 
| entireVolumeScanEnabled | If `true`, the antivirus continues machine scan after the first malware is found. | Optional | 
| powerUp | If `true`, Veeam Backup &amp; Replication powers on the restored VM on the target host. | Optional | 
| reason | Reason for restoring the VM. | Optional | 
| hostName | Name of the Microsoft Hyper-V host. | Optional | 
| hostObjectId | ID of the Microsoft Hyper-V host object. | Optional | 
| vmName | Name of the restored VM. | Optional | 
| preserveUUID | If `true`, the BIOS UUID of the source VM is used. | Optional | 
| registerAsClusterResource | If `true`, the restored VM is configured as a cluster resource. | Optional | 
| overwriteExistingVm | If `true`, the existing VM with the same name is overwritten. | Optional | 
| overwriteExistingDisks | If `true`, the existing VM disks with the same names are overwritten. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_hv_recovery.id | String | Session ID. | 
| Veeam.VBR.start_hv_recovery.name | String | Session name. | 
| Veeam.VBR.start_hv_recovery.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.start_hv_recovery.sessionType | String | Session type. | 
| Veeam.VBR.start_hv_recovery.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.start_hv_recovery.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.start_hv_recovery.state | String | Session state. | 
| Veeam.VBR.start_hv_recovery.progressPercent | Number | Progress percentage of the session. | 
| Veeam.VBR.start_hv_recovery.result | unknown | Session result. | 
| Veeam.VBR.start_hv_recovery.resourceId | String | ID of the resource. | 
| Veeam.VBR.start_hv_recovery.resourceReference | String | URI of the resource. | 
| Veeam.VBR.start_hv_recovery.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.start_hv_recovery.usn | Number | Update sequence number. | 
| Veeam.VBR.start_hv_recovery.platformName | String | Platform type. | 
| Veeam.VBR.start_hv_recovery.platformId | String | ID of the resource platform. | 
| Veeam.VBR.start_hv_recovery.initiatedBy | String | Name of the user who initiated the session. | 
| Veeam.VBR.start_hv_recovery.relatedSessionId | String | ID of the related session. | 

### veeam-vbr-start-security-analyzer

***
Starts the Security & Compliance Analyzer scan. The command creates a new session and returns its details.

#### Base Command

`veeam-vbr-start-security-analyzer`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_security_analyzer.id | String | ID of the session. | 
| Veeam.VBR.start_security_analyzer.name | String | Name of the session. | 
| Veeam.VBR.start_security_analyzer.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.start_security_analyzer.sessionType | String | Type of the session. | 
| Veeam.VBR.start_security_analyzer.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.start_security_analyzer.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.start_security_analyzer.state | String | State of the session. | 
| Veeam.VBR.start_security_analyzer.progressPercent | Number | Progress percentage of the session. | 
| Veeam.VBR.start_security_analyzer.result | unknown | Session result. | 
| Veeam.VBR.start_security_analyzer.usn | Number | Update sequence number. | 
| Veeam.VBR.start_security_analyzer.initiatedBy | String | Name of the user who initiated the session. | 

### veeam-vbr-get-security-analyzer-best-practices

***
Get Security & Compliance Analyzer Results.

#### Base Command

`veeam-vbr-get-security-analyzer-best-practices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.security_analyzer_best_practices.items.id | string | Best practice ID. | 
| Veeam.VBR.security_analyzer_best_practices.items.status | string | Best practice status. | 
| Veeam.VBR.security_analyzer_best_practices.items.bestPractice | string | Best practice name. | 
| Veeam.VBR.security_analyzer_best_practices.items.note | string | Note that specifies the reason for suppressing the best practice compliance status \(excluding it from the analyzer checklist\). | 

### veeam-vbr-get-security-analyzer-last-run

***
Get Security & Compliance Analyzer last run details.

#### Base Command

`veeam-vbr-get-security-analyzer-last-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.security_analyzer_last_run.id | String | ID of the session. | 
| Veeam.VBR.security_analyzer_last_run.name | String | Name of the session. | 
| Veeam.VBR.security_analyzer_last_run.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.security_analyzer_last_run.sessionType | String | Type of the session. | 
| Veeam.VBR.security_analyzer_last_run.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.security_analyzer_last_run.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.security_analyzer_last_run.state | String | State of the session. | 
| Veeam.VBR.security_analyzer_last_run.progressPercent | Number | Progress percentage of the session. | 
| Veeam.VBR.security_analyzer_last_run.result | unknown | Session result. | 
| Veeam.VBR.security_analyzer_last_run.usn | Number | Update sequence number. | 
| Veeam.VBR.security_analyzer_last_run.initiatedBy | String | Name of the user who initiated the session. | 

### veeam-vbr-get-job-states

***
Get All Job States.

#### Base Command

`veeam-vbr-get-job-states`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Number of job states to skip. | Optional | 
| limit | Maximum number of job states to return. Default is 100. | Optional | 
| orderColumn | Sorts job states by one of the state parameters. | Optional | 
| orderAsc | Sorts job states in the ascending order by the `orderColumn` parameter. | Optional | 
| nameFilter | Filters job states by the job name pattern. To substitute one or more characters, use the asterisk (*) character at the beginning, at the end, or both. | Optional | 
| typeFilter | Filters job states by the job type (e.g., SureBackup). | Optional | 
| statusFilter | Filters job states by the job status. | Optional | 
| lastResultFilter | Filters job states by the last job result. | Optional | 
| idFilter | Filters job states by the job ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_job_states.data.id | String | Job ID. | 
| Veeam.VBR.get_job_states.data.name | String | Name of the job. | 
| Veeam.VBR.get_job_states.data.type | String | Type of the job. | 
| Veeam.VBR.get_job_states.data.status | String | Current status of the job. | 
| Veeam.VBR.get_job_states.data.lastResult | String | Result status. | 
| Veeam.VBR.get_job_states.data.lastRun | String | Date and time of the last run of the job. | 
| Veeam.VBR.get_job_states.data.nextRun | String | Date and time of the next run of the job. | 
| Veeam.VBR.get_job_states.data.description | String | Description of the job. | 
| Veeam.VBR.get_job_states.data.workload | String | Workload which the job must process. | 
| Veeam.VBR.get_job_states.data.objectsCount | String | Number of objects processed by the job. | 
| Veeam.VBR.get_job_states.data.highPriority | String | If true, the resource scheduler prioritized this job higher than other similar jobs and allocated resources to it in the first place. | 
| Veeam.VBR.get_job_states.data.progressPercent | String | Progress percentage of the session. | 
| Veeam.VBR.get_job_states.data.nextRunPolicy | String | Note in case the job is disabled, not scheduled, or configured to run after another job. | 
| Veeam.VBR.get_job_states.data.repositoryId | String | Backup repository ID. | 
| Veeam.VBR.get_job_states.data.repositoryName | String | Name of the backup repository. | 
| Veeam.VBR.get_job_states.data.sessionId | String | ID of the last job session. | 
| Veeam.VBR.get_job_states.data.sessionProgress | String | Details on the progress of the session. | 
| Veeam.VBR.get_job_states.data.runAfterJob | String | Specifies that the job will run after another job. | 
| Veeam.VBR.get_job_states.data.backupCopyMode | String | Copy mode of backup copy job. | 
| Veeam.VBR.get_job_states.data.isStorageSnapshot | String | If true, the target for the job is snapshot storage. | 

### veeam-vbr-start-vsphere-quick-backup

***
Start vSphere Quick Backup.

#### Base Command

`veeam-vbr-start-vsphere-quick-backup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VMware vSphere object. | Required | 
| platform | Platform type. | Required | 
| type | Type of the VMware vSphere object. | Required | 
| hostName | Name of the VMware vSphere server that hosts the object. | Required | 
| objectId | ID of the VMware vSphere object. Required for all VMware vSphere objects except vCenter Servers and standalone ESXi hosts. | Optional | 
| urn | Uniform Resource Name (URN) of the object. | Optional | 
| size | Object size. | Optional | 
| isEnabled | Indicates whether the VMware vSphere object is enabled or disabled. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_vsphere_quick_backup.id | String | ID of the session. | 
| Veeam.VBR.start_vsphere_quick_backup.name | String | Name of the session. | 
| Veeam.VBR.start_vsphere_quick_backup.sessionType | String | Type of the session. | 
| Veeam.VBR.start_vsphere_quick_backup.state | String | State of the session. | 
| Veeam.VBR.start_vsphere_quick_backup.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.start_vsphere_quick_backup.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.start_vsphere_quick_backup.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.start_vsphere_quick_backup.progressPercent | String | Progress percentage of the session. | 
| Veeam.VBR.start_vsphere_quick_backup.usn | String | Update sequence number. | 
| Veeam.VBR.start_vsphere_quick_backup.resourceId | String | ID of the resource. | 
| Veeam.VBR.start_vsphere_quick_backup.resourceReference | String | URI of the resource. | 
| Veeam.VBR.start_vsphere_quick_backup.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.start_vsphere_quick_backup.platformName | String | Platform type. | 
| Veeam.VBR.start_vsphere_quick_backup.platformId | String | ID of the resource platform. | 
| Veeam.VBR.start_vsphere_quick_backup.initiatedBy | String | Name of the user that initiated the session. | 
| Veeam.VBR.start_vsphere_quick_backup.result | unknown | Session result. | 

### veeam-vbr-get-authorization-events

***
Get All Authorization Events.

#### Base Command

`veeam-vbr-get-authorization-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Number of authorization events to skip. | Optional | 
| limit | Maximum number of authorization events to return. Default is 100. | Optional | 
| orderColumn | Sorts authorization events by one of the authorization events parameters. | Optional | 
| orderAsc | If true, sorts authorization events in the ascending order by the `orderColumn` parameter. | Optional | 
| nameFilter | Filters authorization events by the `nameFilter` pattern. To substitute one or more characters, use the asterisk (*) character at the beginning, at the end, or both. | Optional | 
| createdAfterFilter | Returns authorization events that are created after the specified date and time. | Optional | 
| createdBeforeFilter | Returns authorization events that are created before the specified date and time. | Optional | 
| processedAfterFilter | Returns authorization events that are processed after the specified date and time. | Optional | 
| processedBeforeFilter | Returns authorization events that are processed before the specified date and time. | Optional | 
| stateFilter | Filters authorization events by state. | Optional | 
| createdByFilter | Filters authorization events created by the specified user. | Optional | 
| processedByFilter | Filters authorization events processed by the specified user. | Optional | 
| expireBeforeFilter | Returns authorization events that expire before the specified date and time. | Optional | 
| expireAfterFilter | Returns authorization events that expire after the specified date and time. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_authorization_events.data.id | String | Event ID. | 
| Veeam.VBR.get_authorization_events.data.name | String | Event name. | 
| Veeam.VBR.get_authorization_events.data.state | String | Event state. | 
| Veeam.VBR.get_authorization_events.data.creationTime | String | Date and time when the event was created. | 
| Veeam.VBR.get_authorization_events.data.processedTime | String | Date and time when the event was processed. | 
| Veeam.VBR.get_authorization_events.data.expirationTime | String | Date and time when the event expires. | 
| Veeam.VBR.get_authorization_events.data.createdBy | String | User that initiated the event. | 
| Veeam.VBR.get_authorization_events.data.processedBy | String | User that processed the event. | 
| Veeam.VBR.get_authorization_events.data.description | String | Event description. | 

### veeam-vbr-start-malware-backup-scan

***
Starts a Scan Backup session.

#### Base Command

`veeam-vbr-start-malware-backup-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| backupId | ID of the backup. | Required | 
| backupObjectId | ID of the backup object. | Required | 
| scanMode | Backup scan mode. Possible values are: MostRecent, AllInInterval, FirstInInterval. | Required | 
| useAntivirusEngine | If true, the selected backup is scanned with antivirus software. | Required | 
| useYaraRule | If true, the selected backup is scanned with the specified YARA rule. | Required | 
| yaraRule | YARA rule file name. | Optional | 
| useMostRecentPoint | If true, the backup scan will process restore points until the most recent one. | Required | 
| startDate | The backup scan will process restore points that were created starting from this date and time. | Optional | 
| useOldestPoint | If true, the backup scan will process restore points until the oldest one. | Required | 
| endDate | The backup scan will proces restore points that were created by this date and time. | Optional | 
| continueScan | If true, the backup scan will continue even after it finds affected restore points. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_malware_backup_scan.id | String | ID of the session. | 
| Veeam.VBR.start_malware_backup_scan.name | String | Name of the session. | 
| Veeam.VBR.start_malware_backup_scan.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.start_malware_backup_scan.sessionType | String | Type of the session. | 
| Veeam.VBR.start_malware_backup_scan.state | String | State of the session. | 
| Veeam.VBR.start_malware_backup_scan.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.start_malware_backup_scan.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.start_malware_backup_scan.progressPercent | String | Progress percentage of the session. | 
| Veeam.VBR.start_malware_backup_scan.result | unknown | Session result. | 
| Veeam.VBR.start_malware_backup_scan.resourceId | String | ID of the resource. | 
| Veeam.VBR.start_malware_backup_scan.resourceReference | String | URI of the resource. | 
| Veeam.VBR.start_malware_backup_scan.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.start_malware_backup_scan.usn | String | Update sequence number. | 
| Veeam.VBR.start_malware_backup_scan.platformName | String | Platform type. | 
| Veeam.VBR.start_malware_backup_scan.platformId | String | ID of the resource platform. | 

### veeam-vbr-mount-entra-id-tenant

***
Mounts a Microsoft Entra ID tenant from its backup and starts a mount session required for restore.

#### Base Command

`veeam-vbr-mount-entra-id-tenant`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| backupId | ID of a Microsoft Entra ID tenant backup. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.mount_entra_id_tenant.sessionId | String | Mount session ID. | 
| Veeam.VBR.mount_entra_id_tenant.sourceProperties.backupId | String | ID of a Microsoft Entra ID tenant backup. | 
| Veeam.VBR.mount_entra_id_tenant.sourceProperties.tenantId | String | Tenant ID assigned by Microsoft Entra ID. | 
| Veeam.VBR.mount_entra_id_tenant.sourceProperties.tenantName | String | Microsoft Entra ID tenant name. | 

### veeam-vbr-unmount-entra-id-tenant

***
Stops the mount session for a Microsoft Entra ID tenant.

#### Base Command

`veeam-vbr-unmount-entra-id-tenant`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sessionId | Mount session ID. | Required | 
| gracefulStop | If true, Veeam Backup &amp; Replication will produce a new restore point for those VMs that have already been processed and for VMs that are being processed at the moment. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.unmount_entra_id_tenant.id | String | ID of the session. | 
| Veeam.VBR.unmount_entra_id_tenant.name | String | Name of the session. | 
| Veeam.VBR.unmount_entra_id_tenant.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.unmount_entra_id_tenant.sessionType | String | Type of the session. | 
| Veeam.VBR.unmount_entra_id_tenant.state | String | State of the session. | 
| Veeam.VBR.unmount_entra_id_tenant.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.unmount_entra_id_tenant.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.unmount_entra_id_tenant.progressPercent | String | Progress percentage of the session. | 
| Veeam.VBR.unmount_entra_id_tenant.result | unknown | Session result. | 
| Veeam.VBR.unmount_entra_id_tenant.resourceId | String | ID of the resource. | 
| Veeam.VBR.unmount_entra_id_tenant.resourceReference | String | URI of the resource. | 
| Veeam.VBR.unmount_entra_id_tenant.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.unmount_entra_id_tenant.usn | String | Update sequence number. | 
| Veeam.VBR.unmount_entra_id_tenant.platformName | String | Platform type. | 
| Veeam.VBR.unmount_entra_id_tenant.platformId | String | ID of the resource platform. | 

### veeam-vbr-get-entra-id-items

***
Get Microsoft Entra ID Items. Browses Microsoft Entra ID items available in a backup.

#### Base Command

`veeam-vbr-get-entra-id-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| backupId | Backup ID. | Required | 
| type | Item type. Possible values are: User, Group, AdministrativeUnit, Role, Application. | Required | 
| skip | Number of items to skip. | Optional | 
| limit | Maximum number of items to return. Default is 100. | Optional | 
| displayName | Filter by user display name. | Optional | 
| mailAddress | Filter by user email address. | Optional | 
| sorting | JSON object specifying sorting options. Must include "property" and "direction" fields. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_entra_id_items.data.id | String | Item ID. | 
| Veeam.VBR.get_entra_id_items.data.displayName | String | Item display name. | 
| Veeam.VBR.get_entra_id_items.data.restorePointId | String | Restore point ID. | 
| Veeam.VBR.get_entra_id_items.data.restorePointDate | String | Restore point date and time. | 
| Veeam.VBR.get_entra_id_items.data.type | String | Item type. | 
| Veeam.VBR.get_entra_id_items.data.mailAddress | String | User email address. | 
| Veeam.VBR.get_entra_id_items.data.userName | String | User principal name. | 
| Veeam.VBR.get_entra_id_items.data.userType | String | User type. | 
| Veeam.VBR.get_entra_id_items.data.employeeType | String | Employee type. | 
| Veeam.VBR.get_entra_id_items.data.accountEnabled | Boolean | If true, the user account is enabled. | 
| Veeam.VBR.get_entra_id_items.data.companyName | String | Company name. | 
| Veeam.VBR.get_entra_id_items.data.creationType | String | Creation type. | 
| Veeam.VBR.get_entra_id_items.data.department | String | Company department. | 
| Veeam.VBR.get_entra_id_items.data.country | String | Country or region. | 
| Veeam.VBR.get_entra_id_items.data.jobTitle | String | Job title. | 
| Veeam.VBR.get_entra_id_items.data.officeLocation | String | Office location. | 

### veeam-vbr-get-entra-id-item-restore-points

***
Get Restore Points of Microsoft Entra ID Item.

#### Base Command

`veeam-vbr-get-entra-id-item-restore-points`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| backupId | Backup ID. | Required | 
| itemId | Item ID. | Required | 
| skip | Number of restore points to skip. | Optional | 
| limit | Maximum number of restore points to return. Default is 100. | Optional | 
| sorting | JSON object specifying sorting options. "property" must be "creationTime". "direction" can be "ascending" or "descending". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_entra_id_item_restore_points.data.id | String | Restore point ID. | 
| Veeam.VBR.get_entra_id_item_restore_points.data.creationTime | String | Date and time when the restore point was created. | 

### veeam-vbr-compare-entra-id-item-properties

***
Compare Microsoft Entra ID Item Properties between restore points or production.

#### Base Command

`veeam-vbr-compare-entra-id-item-properties`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sessionId | Mount session ID. | Required | 
| itemId | ID of Microsoft Entra ID item. | Required | 
| itemType | Item type. Possible values are: User, Group, AdminUnit, Role, Application. | Required | 
| oldRestorePointId | ID of an earlier restore point. | Required | 
| newRestorePointId | ID of a later restore point. If not specified, the item from the earlier restore point will be compared to the item in production. | Optional | 
| showUnchangedAttributes | If true, both changed and unchanged item properties are returned. Otherwise, only changed ones. | Optional | 
| reloadCache | If true, the mount session cache will be reset and new data will be obtained from Microsoft Entra ID. Only used when comparing to production (newRestorePointId not specified). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.compare_entra_id_item_properties.existsInOldRestorePoint | Boolean | If true, the item exists in the earlier restore point. | 
| Veeam.VBR.compare_entra_id_item_properties.existsInNewRestorePoint | Boolean | If true, the item exists in the later restore point. | 
| Veeam.VBR.compare_entra_id_item_properties.properties.propertyName | String | Property name. | 
| Veeam.VBR.compare_entra_id_item_properties.properties.oldValue | String | Property value from the earlier restore point. | 
| Veeam.VBR.compare_entra_id_item_properties.properties.newValue | String | Property value from the later restore point. | 
| Veeam.VBR.compare_entra_id_item_properties.properties.readOnly | Boolean | If true, the value is read-only. | 
| Veeam.VBR.compare_entra_id_item_properties.references.referenceType | String | Reference type. | 
| Veeam.VBR.compare_entra_id_item_properties.references.referenceTypeDisplayName | String | Display name of the reference type. | 
| Veeam.VBR.compare_entra_id_item_properties.references.values | unknown | Array of values. | 
| Veeam.VBR.compare_entra_id_item_properties.cacheTimestamp | String | Date and time the mount session cache was last updated. | 

### veeam-vbr-start-disk-publishing

***
Start Disk Publishing. Publishes disk content from a restore point via the Data Integration API using ISCSITarget mount mode.

#### Base Command

`veeam-vbr-start-disk-publishing`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| restorePointId | Restore point ID. You can use restore points from backups and snapshot replicas. | Required | 
| allowedIps | Comma-separated list of IP addresses of target servers that are allowed to access the iSCSI target server (mount server). | Required | 
| diskNames | Comma-separated list of disk names. | Optional | 
| mountHostId | Mount server ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.start_disk_publishing.id | String | Session ID. | 
| Veeam.VBR.start_disk_publishing.name | String | Session name. | 
| Veeam.VBR.start_disk_publishing.sessionType | String | Session type. | 
| Veeam.VBR.start_disk_publishing.state | String | Session state. | 
| Veeam.VBR.start_disk_publishing.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.start_disk_publishing.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.start_disk_publishing.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.start_disk_publishing.progressPercent | Number | Progress percentage of the session. | 
| Veeam.VBR.start_disk_publishing.result | unknown | Session result. | 
| Veeam.VBR.start_disk_publishing.resourceId | String | ID of the resource. | 
| Veeam.VBR.start_disk_publishing.resourceReference | String | URI of the resource. | 
| Veeam.VBR.start_disk_publishing.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.start_disk_publishing.usn | Number | Update sequence number. | 
| Veeam.VBR.start_disk_publishing.platformName | String | Platform type. | 
| Veeam.VBR.start_disk_publishing.platformId | String | ID of the resource platform. | 

### veeam-vbr-stop-disk-publishing

***
Stops publishing of disk content and unmounts the published disks.

#### Base Command

`veeam-vbr-stop-disk-publishing`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mountId | Mount point ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.stop_disk_publishing.id | String | Session ID. | 
| Veeam.VBR.stop_disk_publishing.name | String | Session name. | 
| Veeam.VBR.stop_disk_publishing.sessionType | String | Session type. | 
| Veeam.VBR.stop_disk_publishing.state | String | Session state. | 
| Veeam.VBR.stop_disk_publishing.jobId | String | ID of the job or job related activity. | 
| Veeam.VBR.stop_disk_publishing.creationTime | String | Date and time when the session was created. | 
| Veeam.VBR.stop_disk_publishing.endTime | String | Date and time when the session was ended. | 
| Veeam.VBR.stop_disk_publishing.progressPercent | Number | Progress percentage of the session. | 
| Veeam.VBR.stop_disk_publishing.result | unknown | Session result. | 
| Veeam.VBR.stop_disk_publishing.resourceId | String | ID of the resource. | 
| Veeam.VBR.stop_disk_publishing.resourceReference | String | URI of the resource. | 
| Veeam.VBR.stop_disk_publishing.parentSessionId | String | ID of the parent session. | 
| Veeam.VBR.stop_disk_publishing.usn | Number | Update sequence number. | 
| Veeam.VBR.stop_disk_publishing.platformName | String | Platform type. | 
| Veeam.VBR.stop_disk_publishing.platformId | String | ID of the resource platform. | 

### veeam-vbr-get-disk-publishing-mount-point

***
Gets information on a disk publishing mount point.

#### Base Command

`veeam-vbr-get-disk-publishing-mount-point`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mountId | Mount point ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.get_disk_publishing_mount_point.id | String | Mount point ID. | 
| Veeam.VBR.get_disk_publishing_mount_point.initiatorName | String | Account used to publish the disks. | 
| Veeam.VBR.get_disk_publishing_mount_point.backupId | String | Backup ID. | 
| Veeam.VBR.get_disk_publishing_mount_point.backupName | String | Backup name. | 
| Veeam.VBR.get_disk_publishing_mount_point.restorePointId | String | Restore point ID. | 
| Veeam.VBR.get_disk_publishing_mount_point.restorePointName | String | Restore point name. | 
| Veeam.VBR.get_disk_publishing_mount_point.mountState | String | Mount state. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.mode | String | Disk publishing mount mode. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.serverPort | Number | Port used by the mount point. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.serverIps | unknown | Array of target server IP addresses. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.disks.diskId | String | Disk ID. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.disks.diskName | String | The path of the published disk. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.disks.accessLink | String | iSCSI Qualified Name \(IQN\) of the disk. Only available for the iSCSI mount mode. | 
| Veeam.VBR.get_disk_publishing_mount_point.info.disks.mountPoints | unknown | Array of mount point paths. | 

### veeam-vbr-general-api-request

***
Sends a generic HTTP request to any VBR REST API endpoint.

#### Base Command

`veeam-vbr-general-api-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | API endpoint path (for example, api/v1/jobs). | Required | 
| method | Used HTTP method. Possible values are: get, post, put, patch, delete. Default is get. | Required | 
| data | JSON body. Required for POST/PUT/PATCH requests. | Optional | 
| params | Query parameters. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VBR.general_api_request | unknown | API response. | 
