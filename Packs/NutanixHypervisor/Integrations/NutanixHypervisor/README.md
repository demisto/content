Nutanix Hypervisor abstracts and isolates the VMs and their programs from the underlying server hardware, enabling a
more efficient use of physical resources, simpler maintenance and operations, and reduced costs. This integration was
integrated and tested with version v2 of Nutanix

## Configure Nutanix on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nutanix Hypervisor.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | base_url | Server URL \(e.g. https://example.net\) | True |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | credentials | Username | True |
    | incidentFetchInterval | Incidents Fetch Interval | False |
    | max_fetch | Maximum number of incidents per fetch | False |
    | alert_status_filters | Alert Status Filters | False |
    | alert_type_ids | alert_type_ids | False |
    | impact_types | Impact Types | False |
    | first_fetch | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nutanix-hypervisor-hosts-list
***
Get the list of physical hosts configured in the cluster.


#### Base Command

`nutanix-hypervisor-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Retrieve hosts that matches the filters given. Nutanix filters can be one of the field returned in the response by nutanix [GET hosts](https://www.nutanix.dev/reference/prism_element/v2/api/hosts/get-hosts-gethosts) API call. Some of the fields in the response are not supported. Known filters Nutanix service supports are: *host_nic_ids*, *host_gpus*, *storage_tier*, *das-sata.usage_bytes*, *storage.capacity_bytes*, *storage.logical_usage_bytes*, *storage_tier.das-sata.capacity_bytes*, *storage.usage_bytes*. If you wish to try any other filter, you can try to enter your own, and in case Nutanix does not support the filter, error will be thrown specifying the filter is invalid. Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value. Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example: storage.capacity_bytes==2;host_nic_ids!=35,host_gpus==x is parsed by Nutanix the following way: Return all hosts s.t (storage.capacity_bytes == 2 AND host_nic_ids != 35) OR host_gpus == x. | Optional | 
| page | Page number in the query response, default is 1. When page is specified, limit argument is required. | Optional | 
| limit | Limit of physical hosts to retrieve. Possible values are 1-1000. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Host.service_vmid | String | Service virtual machine id. | 
| NutanixHypervisor.Host.uuid | String | Host uuid. | 
| NutanixHypervisor.Host.name | String | Host name. | 
| NutanixHypervisor.Host.service_vmexternal_ip | String | Service virtual machine external ip. | 
| NutanixHypervisor.Host.service_vmnat_ip | String | service virtual machine network address translation ip. | 
| NutanixHypervisor.Host.service_vmnat_port | Number | Service virtual machine network address translation port. | 
| NutanixHypervisor.Host.oplog_disk_pct | Number | Oplog disk pct. | 
| NutanixHypervisor.Host.oplog_disk_size | Date | Oplog disk size. | 
| NutanixHypervisor.Host.hypervisor_key | String | Hypervisor key. | 
| NutanixHypervisor.Host.hypervisor_address | String | Hypervisor address. | 
| NutanixHypervisor.Host.hypervisor_username | String | Hypervisor username. | 
| NutanixHypervisor.Host.hypervisor_password | String | Hypervisor password. | 
| NutanixHypervisor.Host.backplane_ip | String | Backplane ip. | 
| NutanixHypervisor.Host.controller_vm_backplane_ip | String | Controller virtual machine backplane ip. | 
| NutanixHypervisor.Host.rdma_backplane_ips | Array | Remote directory memory access backplane ips. | 
| NutanixHypervisor.Host.management_server_name | String | Management server name. | 
| NutanixHypervisor.Host.ipmi_address | String | Ipmi address. | 
| NutanixHypervisor.Host.ipmi_username | String | Ipmi username. | 
| NutanixHypervisor.Host.ipmi_password | String | Ipmi password. | 
| NutanixHypervisor.Host.monitored | Boolean | Is host monitored. | 
| NutanixHypervisor.Host.position.ordinal | Number | Host ordinal position. | 
| NutanixHypervisor.Host.position.name | String | Host's position name. | 
| NutanixHypervisor.Host.position.physical_position | String | Physical position. Allowed values are \[C, L, R, TL, TR, BL, BR\]. Values are abbreviations for \[Center, Left, Right, Top Left, Top Right, Bottom Left, Bottom Right\]. | 
| NutanixHypervisor.Host.serial | String | Host serial id. | 
| NutanixHypervisor.Host.block_serial | String | Host block serial id. | 
| NutanixHypervisor.Host.block_model | String | Host block model. | 
| NutanixHypervisor.Host.block_model_name | String | Block model name. | 
| NutanixHypervisor.Host.block_location | String | Block location. | 
| NutanixHypervisor.Host.host_maintenance_mode_reason | String | Host maintenance reason, in case host is in maintenance. | 
| NutanixHypervisor.Host.hypervisor_state | String | Host's hypervisor state. | 
| NutanixHypervisor.Host.acropolis_connection_state | String | Acropolis connection status. | 
| NutanixHypervisor.Host.metadata_store_status | String | Meta data store status. | 
| NutanixHypervisor.Host.metadata_store_status_message | String | Meta data store status message. | 
| NutanixHypervisor.Host.state | String | Host state. | 
| NutanixHypervisor.Host.removal_status | String | Host removal status. | 
| NutanixHypervisor.Host.vzone_name | String | Virtual zone name. | 
| NutanixHypervisor.Host.cpu_model | String | Cpu model. | 
| NutanixHypervisor.Host.num_cpu_cores | Number | Number of cpu cores. | 
| NutanixHypervisor.Host.num_cpu_threads | Number | Number of cpu threads. | 
| NutanixHypervisor.Host.num_cpu_sockets | Number | Number of cpu sockets. | 
| NutanixHypervisor.Host.hypervisor_full_name | String | Host's hypervisor full name. | 
| NutanixHypervisor.Host.hypervisor_type | String | Hypervisor's type. | 
| NutanixHypervisor.Host.num_vms | Number | Host number of virtual machines. | 
| NutanixHypervisor.Host.boot_time_in_usecs | Number | Boot time in epoch time. | 
| NutanixHypervisor.Host.is_degraded | Boolean | Is host degraded. | 
| NutanixHypervisor.Host.is_secure_booted | Boolean | Is host secure booted. | 
| NutanixHypervisor.Host.is_hardware_virtualized | Boolean | Is hardware virtualized. | 
| NutanixHypervisor.Host.failover_cluster_fqdn | String | Failover cluster fully qualified domain name. | 
| NutanixHypervisor.Host.failover_cluster_node_state | String | Failover cluster node state. | 
| NutanixHypervisor.Host.reboot_pending | Boolean | Is reboot pending. | 
| NutanixHypervisor.Host.default_vm_location | String | Default virtual machine location. | 
| NutanixHypervisor.Host.default_vm_storage_container_id | String | Default virtual machine storage container id. | 
| NutanixHypervisor.Host.default_vm_storage_container_uuid | String | Default virtual machine storage container uuid. | 
| NutanixHypervisor.Host.default_vhd_location | String | Default virtual hard disk location. | 
| NutanixHypervisor.Host.default_vhd_storage_container_id | String | Default virtual hard disk storage container id. | 
| NutanixHypervisor.Host.default_vhd_storage_container_uuid | String | Default virtual hard disk storage container uuid. | 
| NutanixHypervisor.Host.bios_version | String | BIOS version. | 
| NutanixHypervisor.Host.bios_model | String | BIOS model. | 
| NutanixHypervisor.Host.bmc_version | String | BMC version. | 
| NutanixHypervisor.Host.bmc_model | String | BMC model. | 
| NutanixHypervisor.Host.hba_firmwares_list | Array | Host bus adapter firmwares list. | 
| NutanixHypervisor.Host.cluster_uuid | String | Host's cluster uuid. | 
| NutanixHypervisor.Host.has_csr | Boolean | Does host have csr. | 
| NutanixHypervisor.Host.host_gpus | Array | Host's gpus. | 
| NutanixHypervisor.Host.gpu_driver_version | String | Host gpu driver version. | 
| NutanixHypervisor.Host.host_type | String | Host type. | 
| NutanixHypervisor.Host.host_in_maintenance_mode | Boolean | Is host in maintenance mode. | 


#### Command Example
```!nutanix-hypervisor-hosts-list filter="num_vms==2" limit=3 page=1```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "Host": {
            "acropolis_connection_state": "kConnected",
            "block_model": "UseLayout",
            "block_model_name": "CommunityEdition",
            "block_serial": "xxxxxxxx",
            "boot_time": "2020-11-22T14:13:52.399817Z",
            "cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "controller_vm_backplane_ip": "xxx.xxx.x.xxx",
            "cpu_capacity_in_hz": 16760000000,
            "cpu_frequency_in_hz": 2095000000,
            "cpu_model": "Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz",
            "disk_hardware_configs": [
                {
                    "bad": false,
                    "boot_disk": true,
                    "can_add_as_new_disk": false,
                    "can_add_as_old_disk": false,
                    "current_firmware_version": "2.5+",
                    "disk_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xx",
                    "disk_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "location": 1,
                    "model": "Virtual disk",
                    "mount_path": "/home/nutanix/data/stargate-storage/disks/drive-scsi0-0-0-0",
                    "mounted": true,
                    "only_boot_disk": false,
                    "serial_number": "drive-scsi0-0-0-0",
                    "target_firmware_version": "2.5+",
                    "under_diagnosis": false,
                    "vendor": "Not Available"
                },
                {
                    "bad": false,
                    "boot_disk": false,
                    "can_add_as_new_disk": false,
                    "can_add_as_old_disk": false,
                    "current_firmware_version": "2.5+",
                    "disk_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xx",
                    "disk_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "location": 2,
                    "model": "Virtual disk",
                    "mount_path": "/home/nutanix/data/stargate-storage/disks/drive-scsi0-0-0-1",
                    "mounted": true,
                    "only_boot_disk": false,
                    "serial_number": "drive-scsi0-0-0-1",
                    "target_firmware_version": "2.5+",
                    "under_diagnosis": false,
                    "vendor": "Not Available"
                }
            ],
            "has_csr": false,
            "host_type": "HYPER_CONVERGED",
            "hypervisor_address": "xxx.xxx.x.xxx",
            "hypervisor_full_name": "Nutanix xxxxxxxx.xxx",
            "hypervisor_key": "xxx.xxx.x.xxx",
            "hypervisor_state": "kAcropolisNormal",
            "hypervisor_type": "kKvm",
            "hypervisor_username": "root",
            "is_degraded": false,
            "is_hardware_virtualized": false,
            "is_secure_booted": false,
            "management_server_name": "xxx.xxx.x.xxx",
            "memory_capacity_in_bytes": 33722204160,
            "metadata_store_status": "kNormalMode",
            "metadata_store_status_message": "Metadata store enabled on the node",
            "monitored": true,
            "name": "NTNX-xxxxxxxx-A",
            "num_cpu_cores": 8,
            "num_cpu_sockets": 2,
            "num_cpu_threads": 8,
            "num_vms": 2,
            "oplog_disk_pct": 10.8,
            "oplog_disk_size": 72426913110,
            "position": {
                "name": "",
                "ordinal": 1
            },
            "reboot_pending": false,
            "removal_status": [
                "NA"
            ],
            "serial": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "service_vmexternal_ip": "xxx.xxx.x.xxx",
            "service_vmid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x",
            "state": "NORMAL",
            "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "vzone_name": ""
        }
    }
}
```

#### Human Readable Output

>### Nutanix Hosts List
>|acropolis_connection_state|block_model|block_model_name|block_serial|boot_time|cluster_uuid|controller_vm_backplane_ip|cpu_capacity_in_hz|cpu_frequency_in_hz|cpu_model|has_csr|host_type|hypervisor_address|hypervisor_full_name|hypervisor_key|hypervisor_state|hypervisor_type|hypervisor_username|is_degraded|is_hardware_virtualized|is_secure_booted|management_server_name|memory_capacity_in_bytes|metadata_store_status|metadata_store_status_message|monitored|name|num_cpu_cores|num_cpu_sockets|num_cpu_threads|num_vms|oplog_disk_pct|oplog_disk_size|reboot_pending|removal_status|serial|service_vmexternal_ip|service_vmid|state|uuid|vzone_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| kConnected | UseLayout | CommunityEdition | xxxxxxxx | 2020-11-22T14:13:52.399817Z | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | xxx.xxx.x.xxx | 16760000000 | 2095000000 | Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz | false | HYPER_CONVERGED | xxx.xxx.x.xxx | Nutanix xxxxxxxx.xxx | xxx.xxx.x.xxx | kAcropolisNormal | kKvm | root | false | false | false | xxx.xxx.x.xxx | 33722204160 | kNormalMode | Metadata store enabled on the node | true | NTNX-xxxxxxxx-A | 8 | 2 | 8 | 2 | 10.8 | 72426913110 | false | NA | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | xxx.xxx.x.xxx | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x | NORMAL | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx |  |


### nutanix-hypervisor-vms-list
***
Get a list of virtual machines.


#### Base Command

`nutanix-hypervisor-vms-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Retrieve virtual machines that matches the filters given. . Nutanix filters can be one of the field returned in the response by nutanix [GET VMs](https://www.nutanix.dev/reference/prism_element/v2/api/vms/get-vms-getvms/) API call. Some of the fields in the response are not supported. Known filters Nutanix service supports are: *machine_type*, *power_state*, *ha_priority*, *uefi_boot*. If you wish to try any other filter, you can try to enter your own, and in case Nutanix does not support the filter, error will be thrown specifying the filter is invalid. Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value. Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example: machine_type==pc;power_state!=off,ha_priority==0 is parsed by Nutanix the following way: Return all virtual machines s.t (machine type == pc AND power_state != off) OR ha_priority == 0. | Optional | 
| limit | Maximum number of virtual machines to retrieve. Default is 50. | Optional | 
| offset | The offset to start retrieving virtual machines. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.VM.affinity.policy | String | Affinity policy. | 
| NutanixHypervisor.VM.affinity.host_uuids | String | List of host uuids of the affinity. | 
| NutanixHypervisor.VM.allow_live_migrate | Boolean | Does virtual machine allow live migrate. | 
| NutanixHypervisor.VM.gpus_assigned | Boolean | Does virtual machine have gpus assigned. | 
| NutanixHypervisor.VM.boot.uefi_boot | Boolean | Does UEFI boot. | 
| NutanixHypervisor.VM.ha_priority | Number | HA priority. | 
| NutanixHypervisor.VM.host_uuid | String | Host uuid of the virtual machine. | 
| NutanixHypervisor.VM.memory_mb | Number | The memory size in mega bytes. | 
| NutanixHypervisor.VM.name | String | The name of the virtual machine. | 
| NutanixHypervisor.VM.num_cores_per_vcpu | Number | Number of cores per vcpu. | 
| NutanixHypervisor.VM.num_vcpus | Number | Number of vcpus. | 
| NutanixHypervisor.VM.power_state | String | The virtual machine current power state. | 
| NutanixHypervisor.VM.timezone | String | The virtual machine time zone. | 
| NutanixHypervisor.VM.uuid | String | The uuid of the virtual machine. | 
| NutanixHypervisor.VM.vm_features.AGENT_VM | Boolean | Does virtual machine have the feature AGENT VM. | 
| NutanixHypervisor.VM.vm_features.VGA_CONSOLE | Boolean | Does virtual machine have the feature VGA CONSOLE. | 
| NutanixHypervisor.VM.vm_logical_timestamp | Number | The logical timestamp of the virtual machine. | 
| NutanixHypervisor.VM.machine_type | String | The machine type of the virtual machine. | 


#### Command Example
```!nutanix-hypervisor-vms-list filter="machine_type==pc,power_state!=off" length=3 offset=0```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "VM": {
            "affinity": {
                "host_uuids": [
                    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                ],
                "policy": "AFFINITY"
            },
            "allow_live_migrate": false,
            "boot": {
                "uefi_boot": false
            },
            "gpus_assigned": false,
            "ha_priority": 0,
            "host_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "machine_type": "pc",
            "memory_mb": 4096,
            "name": "CentOS7_Test",
            "num_cores_per_vcpu": 2,
            "num_vcpus": 2,
            "power_state": "on",
            "timezone": "UTC",
            "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "vm_features": {
                "AGENT_VM": false,
                "VGA_CONSOLE": true
            },
            "vm_logical_timestamp": 163
        }
    }
}
```

#### Human Readable Output

>### Nutanix Virtual Machines List
>|allow_live_migrate|gpus_assigned|ha_priority|host_uuid|machine_type|memory_mb|name|num_cores_per_vcpu|num_vcpus|power_state|timezone|uuid|vm_logical_timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | false | 0 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | pc | 4096 | CentOS7_Test | 2 | 2 | on | UTC | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | 163 |


### nutanix-hypervisor-vm-powerstatus-change
***
Set power state of a virtual machine. If the virtual machine is being powered on and no host is specified, the scheduler
will pick the one with the most available CPU and memory that can support the Virtual Machine. Note that no such host
may not be available. If the virtual machine is being power cycled, a different host can be specified to start it on.
This is also an asynchronous operation that results in the creation of a task object. The UUID of this task object is
returned as the response of this operation. With this task uuid, this task status can be monitored by using the
nutanix-hypervisor-task-poll command.

### Important
The following command requires cluster admin or higher permissions,
in case you want to use this command,
make sure the usern you are using have at least cluster admin permissions 
(Found in Nutanix Settings in "Users And Roles" Category)

#### Base Command

`nutanix-hypervisor-vm-powerstatus-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_uuid | Id of the virtual machine to change its power status. | Required | 
| host_uuid | If virtual machine is being transitioned with 'ON' or 'POWERCYCLE', this host will be chosen to run the virtual machine. | Optional | 
| transition | The new power state to which you want to transfer the virtual machine to. Possible values are: ON, OFF, POWERCYCLE, RESET, PAUSE, SUSPEND, RESUME, SAVE, ACPI_SHUTDOWN, ACPI_REBOOT. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.VMPowerStatus.task_uuid | String | The task uuid returned by Nutanix service for the power status change request. With this task uuid the task status can be monitored by using the nutanix-hypervisor-task-poll command. | 


#### Command Example
```!nutanix-hypervisor-vm-powerstatus-change vm_uuid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx transition=ON```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "VMPowerStatus": {
            "task_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        }
    }
}
```

#### Human Readable Output

>### Results
>|task_uuid|
>|---|
>| xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx |


### nutanix-hypervisor-task-poll
***
Poll tasks given by task_ids to check if they are ready. Returns all the tasks from 'task_ids' list that are ready at the moment Nutanix service was polled. In case no task is ready, returns a time out response.


#### Base Command

`nutanix-hypervisor-task-poll`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_ids | The IDs of the tasks to poll. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Task.timed_out | Boolean | Indicates if time out occurred during the task poll request from Nutanix. | 
| NutanixHypervisor.Task.uuid | String | The task uuid. | 
| NutanixHypervisor.Task.meta_request.method_name | String | The name of the method performed for this task. | 
| NutanixHypervisor.Task.meta_response.error_code | Number | The Error code returned for the task. | 
| NutanixHypervisor.Task.meta_response.error_detail | String | The error details incase error code was not 0. | 
| NutanixHypervisor.Task.create_time_usecs | Number | The time task was created in epoch. | 
| NutanixHypervisor.Task.start_time_usecs | Number | The start time of the task in epoch time. | 
| NutanixHypervisor.Task.complete_time_usecs | Number | The completion time of the task in epoch time. | 
| NutanixHypervisor.Task.last_updated_time_usecs | Number | The last update of the task in epoch time. | 
| NutanixHypervisor.Task.entity_list.entity_id | String | Id of the entity | 
| NutanixHypervisor.Task.entity_list.entity_type | String | Type of the entity. | 
| NutanixHypervisor.Task.entity_list.entity_name | String | The name of the entity. | 
| NutanixHypervisor.Task.operation_type | String | Operation type of the task. | 
| NutanixHypervisor.Task.message | String | Message. | 
| NutanixHypervisor.Task.percentage_complete | Number | Completion percentage of the task. | 
| NutanixHypervisor.Task.progress_status | String | Progress status of the task \(Succeeded, Failed, ..\). | 
| NutanixHypervisor.Task.subtask_uuid_list | String | The list of the uuids of the subtasks for this task. | 
| NutanixHypervisor.Task.cluster_uuid | String | The uuid of the cluster. | 


#### Command Example
```!nutanix-hypervisor-task-poll task_ids=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "Task": {
            "cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "complete_time": "2021-01-10T14:16:05.197853Z",
            "create_time": "2021-01-10T14:16:00.827398Z",
            "entity_list": [
                {
                    "entity_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "entity_type": "VM"
                }
            ],
            "last_updated": "2021-01-10T14:16:05.197853Z",
            "message": "",
            "meta_request": {
                "method_name": "VmChangePowerState"
            },
            "meta_response": {
                "error_code": 0
            },
            "operation_type": "VmChangePowerState",
            "percentage_complete": 100,
            "progress_status": "Succeeded",
            "start_time": "2021-01-10T14:16:00.863871Z",
            "subtask_uuid_list": [
                "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            ],
            "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        }
    }
}
```

#### Human Readable Output

>### Nutanix Hypervisor Tasks Status
>|Task ID|Progress Status|
>|---|---|
>| xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | Succeeded |


### nutanix-alerts-list
***
Get the list of Alerts generated in the cluster which matches the filters if given. Nutanix brings the latest alerts created in case there are more than 'limit' alerts.


#### Base Command

`nutanix-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or after the specified date/time will be retrieved. Time is expected to be in UTC. | Optional | 
| end_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or before the specified date/time will be retrieved. Time is expected to be in UTC. | Optional | 
| resolved | If resolved is true, retrieves alerts that have been resolved. If resolved is false, retrieves alerts that have not been resolved. Possible values are: true, false. | Optional | 
| auto_resolved | If auto_resolved is true, retrieves alerts that have been resolved, and were auto_resolved. If auto_resolved is false, retrieves alerts that have been resolved, and were not auto_resolved. Possible values are: true, false. | Optional | 
| acknowledged | If acknowledged is true, retrieves alerts that have been acknowledged.                     If acknowledged is false, retrieves alerts that have been acknowledged. Possible values are: true, false. | Optional | 
| severity | Comma separated list. Retrieve any alerts that their severity level matches one of the severities in severity list. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| alert_type_ids | Comma separated list. Retrieve alerts that id of their type matches one alert_type_id in alert_type_ids list. For example, alert 'Alert E-mail Failure' has type id of A111066. Given alert_type_ids= 'A111066', only alerts of 'Alert E-mail Failure' will be retrieved. | Optional | 
| impact_types | Comma separated list. Retrieve alerts that their impact type matches one of the impact types in impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types = 'SystemIndicator',only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be retrieved. Possible values are: Availability, Capacity, Configuration, Performance, System Indicator. | Optional | 
| entity_types | Comma separated list. Retrieve alerts that their entity_type matches one of the entity_type in entity_types list. For more details see Nutanix README. If Nutanix service can't recognize the entity type, it returns 404 response. | Optional | 
| page | Page number in the query response, default is 1. When page is specified, limit argument is required. | Optional | 
| limit | Limit of physical hosts to retrieve. Possible values are 1-1000. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Alerts.id | String | Id of the alert. | 
| NutanixHypervisor.Alerts.alert_type_uuid | String | Uuid of the type of the alert. | 
| NutanixHypervisor.Alerts.check_id | String | The check id of the alert. | 
| NutanixHypervisor.Alerts.resolved | Boolean | Was alert resolved. | 
| NutanixHypervisor.Alerts.auto_resolved | Boolean | Was alert auto resolved. | 
| NutanixHypervisor.Alerts.acknowledged | Boolean | Was alert acknowledged. | 
| NutanixHypervisor.Alerts.service_vmid | String | Service virtual machine id of the alert. | 
| NutanixHypervisor.Alerts.node_uuid | String | Node uuid. | 
| NutanixHypervisor.Alerts.created_time_stamp_in_usecs | Number | The time alert was created in epoch time. | 
| NutanixHypervisor.Alerts.last_occurrence_time_stamp_in_usecs | Number | The time of the last occurrence of the alert in epoch time. | 
| NutanixHypervisor.Alerts.cluster_uuid | String | The cluster uuid of the alert. | 
| NutanixHypervisor.Alerts.originating_cluster_uuid | String | The originating cluster uuid of the alert. | 
| NutanixHypervisor.Alerts.severity | String | The severity of the alert. | 
| NutanixHypervisor.Alerts.impact_types | String | The impact types of the alert. | 
| NutanixHypervisor.Alerts.classifications | String | The classifications of the alert. | 
| NutanixHypervisor.Alerts.acknowledged_by_username | String | The username of whom acknowledged the alert, if the alert was acknowledged by a user. | 
| NutanixHypervisor.Alerts.message | String | Alert message. | 
| NutanixHypervisor.Alerts.detailed_message | String | Alert detailed message. | 
| NutanixHypervisor.Alerts.alert_title | String | Alert title. | 
| NutanixHypervisor.Alerts.operation_type | String | Alert operation type. | 
| NutanixHypervisor.Alerts.acknowledged_time_stamp_in_usecs | Number | The time alert was acknowledged in epoch time. | 
| NutanixHypervisor.Alerts.resolved_time_stamp_in_usecs | Number | The time alert was resolved in epoch time. | 
| NutanixHypervisor.Alerts.resolved_by_username | String | The username whom resolved the alert, if the alert was resolved by a user. | 
| NutanixHypervisor.Alerts.user_defined | Boolean | Is the alert user defined or not. | 
| NutanixHypervisor.Alerts.affected_entities.entity_type | String | Affected entity type. | 
| NutanixHypervisor.Alerts.affected_entities.entity_type_display_name | String | The entity type display name of the affected entities. | 
| NutanixHypervisor.Alerts.affected_entities.entity_name | String | The entity display name of the affected entities. | 
| NutanixHypervisor.Alerts.affected_entities.uuid | String | The affected entity uuid. | 
| NutanixHypervisor.Alerts.affected_entities.id | String | The affected entity id. | 
| NutanixHypervisor.Alerts.context_types | String | Alert context types. | 
| NutanixHypervisor.Alerts.context_values | String | Alert context values. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.comparision_operator | String | Comparision operator used in metric. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.condition_type | String | condition type of the alert by metric. Can be \[STATIC, THRESHOLD, ANOMALY, SAFETY_ZONE\]. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.data_type | String | Data type used in metric. can be \[LONG, DOUBLE, BOOLEAN, STRING\]. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_category | String | Metric category. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_display_name | String | Metric display name. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_name | String | Metric name. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_value_details | Array | Metric value details. | 


#### Command Example
```!nutanix-alerts-list acknowledged=true auto_resolved=true resolved=true start_time=2018-12-31T21:34:54 limit=4```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "Alerts": [
            {
                "acknowledged": true,
                "acknowledged_by_username": "N/A",
                "acknowledged_time": "2020-11-25T15:28:02.804764Z",
                "affected_entities": [
                    {
                        "entity_type": "host",
                        "id": "2",
                        "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    }
                ],
                "alert_title": "{vm_type} time not synchronized with any external servers.",
                "alert_type_uuid": "A3026",
                "auto_resolved": true,
                "check_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xxxx",
                "classifications": [
                    "ControllerVM"
                ],
                "cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "context_types": [
                    "alert_msg",
                    "vm_type",
                    "arithmos_id",
                    "service_vm_id",
                    "ncc_version",
                    "nos_version",
                    "node_uuid",
                    "node_serial",
                    "block_serial"
                ],
                "context_values": [
                    "NTP leader is not synchronizing to an external NTP server",
                    "CVM",
                    "2",
                    "2",
                    "x.xx.x.x-xxxxxxxx",
                    "2020.09.16",
                    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "xxxxxxxx"
                ],
                "created_time": "2020-11-22T14:31:14.675609Z",
                "detailed_message": "",
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "impact_types": [
                    "Configuration"
                ],
                "last_occurrence": "2020-11-22T14:31:14.675609Z",
                "message": "The {vm_type} is not synchronizing time with any external servers. {alert_msg}",
                "node_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "operation_type": "kCreate",
                "originating_cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "resolved": true,
                "resolved_by_username": "N/A",
                "resolved_time": "2020-11-25T15:28:02.804758Z",
                "service_vmid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x",
                "severity": "kWarning",
                "user_defined": false
            },
            {
                "acknowledged": true,
                "acknowledged_by_username": "N/A",
                "acknowledged_time": "2020-11-25T15:28:02.851718Z",
                "affected_entities": [
                    {
                        "entity_type": "host",
                        "id": "2",
                        "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    }
                ],
                "alert_title": "Incorrect NTP Configuration",
                "alert_type_uuid": "A103076",
                "auto_resolved": true,
                "check_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xxxxxx",
                "classifications": [
                    "Cluster"
                ],
                "cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "context_types": [
                    "alert_msg",
                    "vm_type",
                    "arithmos_id",
                    "cvm_ip",
                    "service_vm_id",
                    "ncc_version",
                    "nos_version",
                    "node_uuid",
                    "node_serial",
                    "block_serial"
                ],
                "context_values": [
                    "This CVM is the NTP leader but it is not syncing time with any external NTP server. NTP configuration on CVM is not yet updated with the NTP servers configured in the cluster. The NTP configuration on the CVM will not be updated if the cluster time is in the future relative to the NTP servers.\n",
                    "CVM",
                    "2",
                    "xxx.xxx.x.xxx",
                    "2",
                    "x.xx.x.x-xxxxxxxx",
                    "2020.09.16",
                    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "xxxxxxxx"
                ],
                "created_time": "2020-11-22T14:31:14.619018Z",
                "detailed_message": "",
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "impact_types": [
                    "SystemIndicator"
                ],
                "last_occurrence": "2020-11-22T14:31:14.619018Z",
                "message": "{alert_msg}",
                "node_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "operation_type": "kCreate",
                "originating_cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "resolved": true,
                "resolved_by_username": "N/A",
                "resolved_time": "2020-11-25T15:28:02.851706Z",
                "service_vmid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x",
                "severity": "kWarning",
                "user_defined": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Nutanix Alert List
>|acknowledged|acknowledged_by_username|acknowledged_time|alert_title|alert_type_uuid|auto_resolved|check_id|classifications|cluster_uuid|context_types|context_values|created_time|detailed_message|id|impact_types|last_occurrence|message|node_uuid|operation_type|originating_cluster_uuid|resolved|resolved_by_username|resolved_time|service_vmid|severity|user_defined|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | N/A | 2020-11-25T15:28:02.804764Z | {vm_type} time not synchronized with any external servers. | A3026 | true | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xxxx | ControllerVM | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | alert_msg,<br/>vm_type,<br/>arithmos_id,<br/>service_vm_id,<br/>ncc_version,<br/>nos_version,<br/>node_uuid,<br/>node_serial,<br/>block_serial | NTP leader is not synchronizing to an external NTP server,<br/>CVM,<br/>2,<br/>2,<br/>x.xx.x.x-xxxxxxxx,<br/>2020.09.16,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx | 2020-11-22T14:31:14.675609Z |  | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | Configuration | 2020-11-22T14:31:14.675609Z | The {vm_type} is not synchronizing time with any external servers. {alert_msg} | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | kCreate | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | true | N/A | 2020-11-25T15:28:02.804758Z | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x | kWarning | false |
>| true | N/A | 2020-11-25T15:28:02.851718Z | Incorrect NTP Configuration | A103076 | true | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xxxxxx | Cluster | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | alert_msg,<br/>vm_type,<br/>arithmos_id,<br/>cvm_ip,<br/>service_vm_id,<br/>ncc_version,<br/>nos_version,<br/>node_uuid,<br/>node_serial,<br/>block_serial | This CVM is the NTP leader but it is not syncing time with any external NTP server. NTP configuration on CVM is not yet updated with the NTP servers configured in the cluster. The NTP configuration on the CVM will not be updated if the cluster time is in the future relative to the NTP servers.<br/>,<br/>CVM,<br/>2,<br/>xxx.xxx.x.xxx,<br/>2,<br/>x.xx.x.x-xxxxxxxx,<br/>2020.09.16,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx | 2020-11-22T14:31:14.619018Z |  | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | SystemIndicator | 2020-11-22T14:31:14.619018Z | {alert_msg} | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | kCreate | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | true | N/A | 2020-11-25T15:28:02.851706Z | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x | kWarning | false |


### nutanix-alert-acknowledge
***
Acknowledge alert with the specified alert_id.


#### Base Command

`nutanix-alert-acknowledge`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The id of the alert to acknowledge. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.AcknowledgedAlerts.id | String | Id of the alert to be acknowledged. | 
| NutanixHypervisor.AcknowledgedAlerts.successful | Boolean | Was acknowledge successful. | 
| NutanixHypervisor.AcknowledgedAlerts.message | String | The message returned by the acknowledge task. | 


#### Command Example
```!nutanix-alert-acknowledge alert_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "AcknowledgeAlerts": {
            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "successful": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|successful|
>|---|---|
>| xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | true |


### nutanix-alert-resolve
***
Resolve alert with the specified alert_id.

### Important
The following command requires cluster admin or higher permissions,
in case you want to use this command,
make sure the user you are using have at least cluster admin permissions
(Permissions are found in Nutanix Settings in "Users And Roles" Category)

#### Base Command

`nutanix-alert-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The id of the alert to resolve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.ResolvedAlerts.id | String | Id of the alert to be resolved. | 
| NutanixHypervisor.ResolvedAlerts.successful | Boolean | Was resolve successful. | 
| NutanixHypervisor.ResolvedAlerts.message | String | The message returned by the resolve task. | 


#### Command Example
```!nutanix-alert-resolve alert_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "ResolvedAlerts": {
            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "successful": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|successful|
>|---|---|
>| xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | true |


### nutanix-alerts-acknowledge-by-filter
***
Acknowledge alerts using a filters.

### Important
The following command requires cluster admin or higher permissions,
in case you want to use this command,
make sure the user you are using have at least cluster admin permissions
(Permissions are found in Nutanix Settings in "Users And Roles" Category)

#### Base Command

`nutanix-alerts-acknowledge-by-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or after the specified date/time will be acknowledged. Time is expected to be in UTC. | Optional | 
| end_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or before the specified date/time will be acknowledged. Time is expected to be in UTC. | Optional | 
| severity | Comma separated list. Acknowledge alerts that their severity level matches one of the severities in severity list. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| impact_types | Comma separated list. Acknowledge alerts that their impact type matches one of the impact types in impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types = 'SystemIndicator',only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be acknowledged. | Optional | 
| entity_types | Comma separated list. Retrieve alerts that their entity_type matches one of the entity_type in entity_types list. Nutanix entity types can found in 'Alert Policies' page mentioned in configuring instance description. Known entity types Nutanix service supports are *VM*, *Host*, *Disk*, *Storage Container*, *Cluster*. If Nutanix service can't recognize or does not support the entity type, it returns 404 response. | Optional | 
| limit | Maximum number of alerts to acknowledge. Nutanix does not have max for limit, but a very high limit value will cause read timeout exception. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.AcknowledgedFilterAlerts.num_successful_updates | Number | The number of the successful alerts acknowledges. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.num_failed_updates | Number | The number of the failed alerts to acknowledge. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.alert_status_list.id | String | Id of the status of the alert. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.alert_status_list.successful | Boolean | Was acknowledge for this task successful. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.alert_status_list.message | String | Message returned by acknowledge operation. | 


#### Command Example
```!nutanix-alerts-acknowledge-by-filter end_time=2021-12-22T13:14:15 entity_types=Host severity=WARNING```

#### Context Example
```json
{
  "NutanixHypervisor": {
    "Alert": {
      "num_successful_updates": 1,
      "num_failed_updates": 0,
      "alert_status_list": [
        {
          "id": "0:0",
          "successful": true,
          "message": null
        }
      ]
    }
  }
}
```

#### Human Readable Output

>### Results
>|num_failed_updates|num_successful_updates|
>|---|---|
>| 0 | 0 |


### nutanix-alerts-resolve-by-filter
***
Resolve alerts using a filters.

### Important
The following command requires cluster admin or higher permissions,
in case you want to use this command,
make sure the user you are using have at least cluster admin permissions
(Permissions are found in Nutanix Settings in "Users And Roles" Category)

#### Base Command

`nutanix-alerts-resolve-by-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or after the specified date/time will be resolved. Time is expected to be in UTC. | Optional | 
| end_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or before the specified date/time will be resolved. Time is expected to be in UTC. | Optional | 
| severity | Comma separated list. Resolve alerts that their severity level matches one of the severities in severity list. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| impact_types | Comma separated list. Resolve alerts that their impact type matches one of the impact types in impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types = 'SystemIndicator',only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be resolved. | Optional | 
| entity_types | Comma separated list. Retrieve alerts that their entity_type matches one of the entity_type in entity_types list. For more details see Nutanix README. If Nutanix service can't recognize the entity type, it returns 404 response. | Optional | 
| limit | Maximum number of alerts to resolve. Nutanix does not have max for limit, but a very high limit value will cause read timeout exception. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.ResolvedFilterAlerts.num_successful_updates | Number | The number of the successful alert resolves. | 
| NutanixHypervisor.ResolvedFilterAlerts.num_failed_updates | Number | The number of the failed alerts to resolve. | 
| NutanixHypervisor.ResolvedFilterAlerts.alert_status_list.id | String | Id of the status of the alert. | 
| NutanixHypervisor.ResolvedFilterAlerts.alert_status_list.successful | Boolean | Was resolve for this task successful. | 
| NutanixHypervisor.ResolvedFilterAlerts.alert_status_list.message | String | Message returned by resolve operation. | 


#### Command Example
```!nutanix-alerts-resolve-by-filter limit=2 impact_types=SystemIndicator entity_types=VM```

#### Context Example
```json
{
  "NutanixHypervisor": {
    "Alert": {
      "num_successful_updates": 1,
      "num_failed_updates": 0,
      "alert_status_list": [
        {
          "id": "0:0",
          "successful": true,
          "message": null
        }
      ]
    }
  }
}
```

#### Human Readable Output

>### Results
>|num_failed_updates|num_successful_updates|
>|---|---|
>| 0 | 0 |

