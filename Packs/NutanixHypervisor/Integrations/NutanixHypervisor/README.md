Nutanix Hypervisor abstracts and isolates the VMs and their programs from the underlying server hardware, enabling a
more efficient use of physical resources, simpler maintenance and operations, and reduced costs. This integration was
integrated and tested with version v2 of Nutanix.

## Configure Nutanix Hypervisor on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nutanix Hypervisor.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | \(e.g., https://192.168.0.1:57261\) | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Username |  | True |
    | Incidents Fetch Interval |  | False |
    | Maximum number of incidents per fetch | The maximum number of incidents to fetch each time. | False |
    | Alert Status Filters | Fetches incidents by the status filters given. For example, if acknowledged is true, then only alerts that have been acknowledged will be fetched. If 'Auto Resolved' or 'Not Auto Resolved' is selected, then by default also 'Resolved' will be set. | False |
    | Alert type IDs | Comma-separated list of alert type IDs. Fetches alerts whose type ID matches an alert_type_id in the alert_type_ids list. For example, alert 'Alert E-mail Failure' has type ID A111066. If alert_type_ids = 'A111066', only alerts of 'Alert E-mail Failure' will be displayed. | False |
    | Impact Types | Comma-separated list  of impact types. Fetch alerts whose impact type matches an impact type in Impact Types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. If Impact Types = 'SystemIndicator', only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be displayed. | False |
    | First fetch timestamp | format: `<number>` `<time unit>`, e.g., 12 hours, 7 days. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

### Available Alert Type IDs, Impact Types, and Entity Types
Alert Policies contains the list of all possible alerts in the system,
and their ID, impact type, and entity type. In order to check the optional values for these entities:

1. Go to your Nutanix UI and navigate to the *Alerts* screen. (Can be found under the second tab in the top left corner, see image below)
2. Navigate to the Alert Policies tab on the left sidebar.
You should see the following screen:
![Nutanix Alert Policy](../../doc_files/Alert_Policy.png)

* *ID* is the alert type ID filter parameter for fetching alerts, or the argument for the ***nutanix-hypervisor-alerts-list*** command.
* *Impact Type* is the impact type filter parameter for fetching alerts, or the argument for the ***nutanix-hypervisor-alerts-list*** command.

### Permissions
The following commands require cluster admin or higher permissions.
(Found in Nutanix Settings in the *Users And Roles* category.)

- ***nutanix-hypervisor-vm-powerstatus-change***
- ***nutanix-hypervisor-alert-acknowledge***
- ***nutanix-hypervisor-alert-resolve***
- ***nutanix-hypervisor-alerts-acknowledge-by-filter***
- ***nutanix-hypervisor-alerts-resolve-by-filter***

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nutanix-hypervisor-hosts-list
***
Gets the list of physical hosts configured in the cluster.


#### Base Command

`nutanix-hypervisor-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The filters used to define the hosts to retrieve. Nutanix filters can be one of the fields returned in the response by the Nutanix [GET hosts](https://www.nutanix.dev/reference/prism_element/v2/api/hosts/get-hosts-gethosts) API call. Some of the fields in the response are not supported. Known filters that the Nutanix service supports are: *host_nic_ids*, *host_gpus*, *storage_tier*, *das-sata.usage_bytes*, *storage.capacity_bytes*, *storage.logical_usage_bytes*, *storage_tier.das-sata.capacity_bytes*, *storage.usage_bytes*. You can try to enter your own filters, but if Nutanix does not support the filter, an error will be thrown specifying that the filter is invalid. Each filter is written in the following format: filter_name==filter_value or filter_name!=filter_value. Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for example, storage.capacity_bytes==2;host_nic_ids!=35,host_gpus==x, are parsed by Nutanix as follows: Return all hosts s.t (storage.capacity_bytes == 2 AND host_nic_ids != 35) OR host_gpus == x. | Optional | 
| page | Page number in the query response. Default is 1. | Optional | 
| limit | Maximum number of physical hosts to retrieve. Possible values are 1-1000. Default is 50. | Optional | 
| verbose | Receive extended information from Nutanix about hosts. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Host.service_vmid | String | Service virtual machine ID. | 
| NutanixHypervisor.Host.uuid | String | Host UUID. | 
| NutanixHypervisor.Host.name | String | Host name. | 
| NutanixHypervisor.Host.service_vmexternal_ip | String | Service virtual machine external IP. | 
| NutanixHypervisor.Host.service_vmnat_ip | String | Service virtual machine network address translation IP. | 
| NutanixHypervisor.Host.service_vmnat_port | Number | Service virtual machine network address translation port. | 
| NutanixHypervisor.Host.oplog_disk_pct | Number | Oplog disk pct. | 
| NutanixHypervisor.Host.oplog_disk_size | Date | Oplog disk size. | 
| NutanixHypervisor.Host.hypervisor_key | String | Hypervisor key. | 
| NutanixHypervisor.Host.hypervisor_address | String | Hypervisor address. | 
| NutanixHypervisor.Host.hypervisor_username | String | Hypervisor username. | 
| NutanixHypervisor.Host.hypervisor_password | String | Hypervisor password. | 
| NutanixHypervisor.Host.backplane_ip | String | Backplane IP. | 
| NutanixHypervisor.Host.controller_vm_backplane_ip | String | Controller virtual machine backplane IP. | 
| NutanixHypervisor.Host.rdma_backplane_ips | Unknown | Remote directory memory access backplane IPs. | 
| NutanixHypervisor.Host.management_server_name | String | Management server name. | 
| NutanixHypervisor.Host.ipmi_address | String | Intelligent platform management interface address. | 
| NutanixHypervisor.Host.ipmi_username | String | Intelligent platform management interface username. | 
| NutanixHypervisor.Host.ipmi_password | String | Intelligent platform management interface password. | 
| NutanixHypervisor.Host.monitored | Boolean | Whether the host is monitored. | 
| NutanixHypervisor.Host.position.ordinal | Number | Host ordinal position. | 
| NutanixHypervisor.Host.position.name | String | Host's position name. | 
| NutanixHypervisor.Host.position.physical_position | String | Physical position. Allowed values are \[C, L, R, TL, TR, BL, BR\]. Values are abbreviations for \[Center, Left, Right, Top Left, Top Right, Bottom Left, Bottom Right\]. | 
| NutanixHypervisor.Host.serial | String | Host serial ID. | 
| NutanixHypervisor.Host.block_serial | String | Host block serial ID. | 
| NutanixHypervisor.Host.block_model | String | Host block model. | 
| NutanixHypervisor.Host.block_model_name | String | Block model name. | 
| NutanixHypervisor.Host.block_location | String | Block location. | 
| NutanixHypervisor.Host.host_maintenance_mode_reason | String | Host maintenance reason, if host is in maintenance. | 
| NutanixHypervisor.Host.hypervisor_state | String | Host's hypervisor state. | 
| NutanixHypervisor.Host.acropolis_connection_state | String | Acropolis connection status. | 
| NutanixHypervisor.Host.metadata_store_status | String | Metadata store status. | 
| NutanixHypervisor.Host.metadata_store_status_message | String | Metadata store status message. | 
| NutanixHypervisor.Host.state | String | Host state. | 
| NutanixHypervisor.Host.removal_status | String | Host removal status. | 
| NutanixHypervisor.Host.vzone_name | String | Virtual zone name. | 
| NutanixHypervisor.Host.cpu_model | String | CPU model. | 
| NutanixHypervisor.Host.num_cpu_cores | Number | Number of CPU cores. | 
| NutanixHypervisor.Host.num_cpu_threads | Number | Number of CPU threads. | 
| NutanixHypervisor.Host.num_cpu_sockets | Number | Number of CPU sockets. | 
| NutanixHypervisor.Host.hypervisor_full_name | String | Host's hypervisor full name. | 
| NutanixHypervisor.Host.hypervisor_type | String | Hypervisor's type. | 
| NutanixHypervisor.Host.num_vms | Number | Host number of virtual machines. | 
| NutanixHypervisor.Host.boot_time_in_usecs | Number | Boot time in epoch time. | 
| NutanixHypervisor.Host.boot_time | date | Boot time in epoch time. | 
| NutanixHypervisor.Host.is_degraded | Boolean | Whether the host is degraded. | 
| NutanixHypervisor.Host.is_secure_booted | Boolean | Whether the host is secure booted. | 
| NutanixHypervisor.Host.is_hardware_virtualized | Boolean | Whether the hardware is virtualized. | 
| NutanixHypervisor.Host.failover_cluster_fqdn | String | Failover cluster fully qualified domain name. | 
| NutanixHypervisor.Host.failover_cluster_node_state | String | Failover cluster node state. | 
| NutanixHypervisor.Host.reboot_pending | Boolean | Whether reboot is pending. | 
| NutanixHypervisor.Host.default_vm_location | String | Default virtual machine location. | 
| NutanixHypervisor.Host.default_vm_storage_container_id | String | Default virtual machine storage container ID. | 
| NutanixHypervisor.Host.default_vm_storage_container_uuid | String | Default virtual machine storage container UUID. | 
| NutanixHypervisor.Host.default_vhd_location | String | Default virtual hard disk location. | 
| NutanixHypervisor.Host.default_vhd_storage_container_id | String | Default virtual hard disk storage container ID. | 
| NutanixHypervisor.Host.default_vhd_storage_container_uuid | String | Default virtual hard disk storage container UUID. | 
| NutanixHypervisor.Host.bios_version | String | BIOS version. | 
| NutanixHypervisor.Host.bios_model | String | BIOS model. | 
| NutanixHypervisor.Host.bmc_version | String | BMC version. | 
| NutanixHypervisor.Host.bmc_model | String | BMC model. | 
| NutanixHypervisor.Host.hba_firmwares_list | Unknown | Host bus adapter firmware list. | 
| NutanixHypervisor.Host.cluster_uuid | String | Host's cluster UUID. | 
| NutanixHypervisor.Host.has_csr | Boolean | Whether the host has a certificate signing request. | 
| NutanixHypervisor.Host.host_gpus | Unknown | Host's GPUs. | 
| NutanixHypervisor.Host.gpu_driver_version | String | Host GPU driver version. | 
| NutanixHypervisor.Host.host_type | String | Host type. | 
| NutanixHypervisor.Host.host_in_maintenance_mode | Boolean | Whether the host is in maintenance mode. | 


#### Command Example
```!nutanix-hypervisor-hosts-list filter="num_vms==2" limit=3 page=1```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "Host": {
            "boot_time": "2020-11-22T14:13:52.399817+00:00",
            "boot_time_in_usecs": 1606054432399817,
            "cluster_uuid": "asra1631-a234-zxd1-aa23-azxr124z23aq",
            "controller_vm_backplane_ip": "192.168.1.111",
            "cpu_model": "Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz",
            "has_csr": false,
            "host_type": "HYPER_CONVERGED",
            "hypervisor_address": "192.168.1.111",
            "hypervisor_full_name": "Nutanix 20190916.321",
            "hypervisor_key": "192.168.1.111",
            "hypervisor_type": "kKvm",
            "hypervisor_username": "root",
            "is_degraded": false,
            "is_hardware_virtualized": false,
            "is_secure_booted": false,
            "management_server_name": "192.168.1.111",
            "monitored": true,
            "name": "NTNX-386a5fb4-A",
            "num_cpu_cores": 8,
            "num_cpu_sockets": 2,
            "num_cpu_threads": 8,
            "num_vms": 2,
            "reboot_pending": false,
            "serial": "59bc015e-a22d-41ab-9ce2-a96164955e9q",
            "service_vmexternal_ip": "192.168.1.111",
            "service_vmid": "asra1631-a234-zxd1-aa23-azxr124z23aq::2",
            "state": "NORMAL",
            "uuid": "59bc015e-a22d-41ab-9ce2-a96164955e9q",
            "vzone_name": ""
        }
    }
}
```

#### Human Readable Output

>### Nutanix Hosts List
>|is_hardware_virtualized|host_type|serial|boot_time|hypervisor_type|num_cpu_sockets|hypervisor_full_name|hypervisor_username|uuid|vzone_name|hypervisor_address|num_vms|is_secure_booted|management_server_name|monitored|is_degraded|state|num_cpu_cores|name|service_vmid|service_vmexternal_ip|reboot_pending|cluster_uuid|has_csr|hypervisor_key|cpu_model|num_cpu_threads|controller_vm_backplane_ip|boot_time_in_usecs|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | HYPER_CONVERGED | 59bc015e-a22d-41ab-9ce2-a96164955e9q | 2020-11-22T14:13:52.399817+00:00 | kKvm | 2 | Nutanix 20190916.321 | root | 59bc015e-a22d-41ab-9ce2-a96164955e9q |  | 192.168.1.111 | 2 | false | 192.168.1.111 | true | false | NORMAL | 8 | NTNX-386a5fb4-A | asra1631-a234-zxd1-aa23-azxr124z23aq::2 | 192.168.1.111 | false | asra1631-a234-zxd1-aa23-azxr124z23aq | false | 192.168.1.111 | Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz | 8 | 192.168.1.111 | 1606054432399817 |


### nutanix-hypervisor-vms-list
***
Gets a list of virtual machines.


#### Base Command

`nutanix-hypervisor-vms-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Retrieve virtual machines that matches the filters given. . Nutanix filters can be one of the field returned in the response by nutanix [GET VMs](https://www.nutanix.dev/reference/prism_element/v2/api/vms/get-vms-getvms/) API call. Some of the fields in the response are not supported. Known filters Nutanix service supports are: *machine_type*, *power_state*, *ha_priority*, *uefi_boot*. You can try to enter your own filter,  but if Nutanix does not support the filter, an error will be thrown specifying the filter is invalid. Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value. Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example: machine_type==pc;power_state!=off,ha_priority==0 is parsed by Nutanix the following way: Return all virtual machines s.t (machine type == pc AND power_state != off) OR ha_priority == 0. | Optional | 
| limit | Maximum number of virtual machines to retrieve. Default is 50. | Optional | 
| offset | The offset to start retrieving virtual machines. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.VM.affinity.policy | String | Affinity policy. | 
| NutanixHypervisor.VM.affinity.host_uuids | String | List of host UUIDs of the affinity. | 
| NutanixHypervisor.VM.allow_live_migrate | Boolean | Whether the virtual machine allows live migration. | 
| NutanixHypervisor.VM.gpus_assigned | Boolean | Whether the virtual machine has GPUs assigned. | 
| NutanixHypervisor.VM.boot.uefi_boot | Boolean | Whether the Unified Extensible Firmware Interface boots. | 
| NutanixHypervisor.VM.ha_priority | Number | High availability priority. | 
| NutanixHypervisor.VM.host_uuid | String | Host UUID of the virtual machine. | 
| NutanixHypervisor.VM.memory_mb | Number | The memory size in megabytes. | 
| NutanixHypervisor.VM.name | String | The name of the virtual machine. | 
| NutanixHypervisor.VM.num_cores_per_vcpu | Number | Number of cores per vCPU. | 
| NutanixHypervisor.VM.num_vcpus | Number | Number of vCPUs. | 
| NutanixHypervisor.VM.power_state | String | The virtual machine current power state. | 
| NutanixHypervisor.VM.timezone | String | The virtual machine time zone. | 
| NutanixHypervisor.VM.uuid | String | The UUID of the virtual machine. | 
| NutanixHypervisor.VM.vm_features.AGENT_VM | Boolean | Whether the virtual machine has the AGENT VM feature. | 
| NutanixHypervisor.VM.vm_features.VGA_CONSOLE | Boolean | Whether the virtual machine has the VGA CONSOLE feature. | 
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
                    "59bc015e-a22d-41ab-9ce2-a96164955e9q"
                ],
                "policy": "AFFINITY"
            },
            "allow_live_migrate": false,
            "boot": {
                "uefi_boot": false
            },
            "gpus_assigned": false,
            "ha_priority": 0,
            "host_uuid": "59bc015e-a22d-41ab-9ce2-a96164955e9q",
            "machine_type": "pc",
            "memory_mb": 4096,
            "name": "CentOS7_Test",
            "num_cores_per_vcpu": 2,
            "num_vcpus": 2,
            "power_state": "on",
            "timezone": "UTC",
            "uuid": "16c3d845-dc54-4fb1-bfc8-7671dd230967",
            "vm_features": {
                "AGENT_VM": false,
                "VGA_CONSOLE": true
            },
            "vm_logical_timestamp": 243
        }
    }
}
```

#### Human Readable Output

>### Nutanix Virtual Machines List
>|timezone|allow_live_migrate|name|ha_priority|machine_type|memory_mb|uuid|power_state|num_cores_per_vcpu|vm_logical_timestamp|gpus_assigned|host_uuid|num_vcpus|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| UTC | false | CentOS7_Test | 0 | pc | 4096 | 16c3d845-dc54-4fb1-bfc8-7671dd230967 | on | 2 | 243 | false | 59bc015e-a22d-41ab-9ce2-a96164955e9q | 2 |


### nutanix-hypervisor-vm-powerstatus-change
***
Sets the power state of a virtual machine. If the virtual machine is being powered on and no host is specified, the host with
the most available CPU and memory will be chosen. Note that such a host may not be available. If the virtual machine is
being power cycled, a different host can be specified to start it on. The command returns a task UUID that can be
monitored by the nutanix-hypervisor-task-results-get command.

#### Base Command

`nutanix-hypervisor-vm-powerstatus-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_uuid | ID of the virtual machine to change its power status. Virtual machine ID is the 'uuid' field returned for by command 'nutanix-hypervisor-vms-list'. | Required | 
| host_uuid | The UUID of the host to be used to run the virtual machine if the virtual machine is transitioned with 'ON' or 'POWERCYCLE'. Host ID is the 'uuid' field returned for by command 'nutanix-hypervisor-hosts-list'. | Optional | 
| transition | The new power state to which you want to transfer the virtual machine to. Possible values are: ON, OFF, POWERCYCLE, RESET, PAUSE, SUSPEND, RESUME, SAVE, ACPI_SHUTDOWN, ACPI_REBOOT. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.VMPowerStatus.task_uuid | String | The task UUID returned by Nutanix service for the power status change request. With this task UUID the task status can be monitored by using the nutanix-hypervisor-task-results-get command. | 


#### Command Example
```!nutanix-hypervisor-vm-powerstatus-change vm_uuid=16c3d845-dc54-4fb1-bfc8-7671dd230967 transition=ON```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "VMPowerStatus": {
            "task_uuid": "7f522fb2-1b19-491a-ab49-763f48be8712"
        }
    }
}
```

#### Human Readable Output

>### Results
>|task_uuid|
>|---|
>| 7f522fb2-1b19-491a-ab49-763f48be8712 |


### nutanix-hypervisor-task-results-get
***
Returns the results of given tasks. If a task is not ready, its status will be returned.


#### Base Command

`nutanix-hypervisor-task-results-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_ids | Comma-separated list of the task IDs to get results to. Task ID is the 'task_uuid' field returned for by command 'nutanix-hypervisor-vm-powerstatus-change'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Task.timed_out | Boolean | Indicates if a timeout occurred during the poll request from Nutanix. | 
| NutanixHypervisor.Task.uuid | String | The task UUID. | 
| NutanixHypervisor.Task.meta_request.method_name | String | The name of the method performed for this task. | 
| NutanixHypervisor.Task.meta_response.error_code | Number | The error code returned for the task. | 
| NutanixHypervisor.Task.meta_response.error_detail | String | The error details if the error code was not 0. | 
| NutanixHypervisor.Task.create_time_usecs | Number | The time the task was created in epoch time. | 
| NutanixHypervisor.Task.create_time | date | The time task was created in epoch. | 
| NutanixHypervisor.Task.start_time_usecs | Number | The start time of the task in epoch time. | 
| NutanixHypervisor.Task.start_time | date | The start time of the task in epoch time. | 
| NutanixHypervisor.Task.complete_time_usecs | Number | The completion time of the task in epoch time. | 
| NutanixHypervisor.Task.complete_time | date | The completion time of the task in epoch time. | 
| NutanixHypervisor.Task.last_updated_time_usecs | Number | The last update of the task in epoch time. | 
| NutanixHypervisor.Task.last_updated | date | The last update of the task in epoch time. | 
| NutanixHypervisor.Task.entity_list.entity_id | String | ID of the entity. | 
| NutanixHypervisor.Task.entity_list.entity_type | String | Type of the entity. | 
| NutanixHypervisor.Task.entity_list.entity_name | String | The name of the entity. | 
| NutanixHypervisor.Task.operation_type | String | Operation type of the task. | 
| NutanixHypervisor.Task.message | String | Task message. | 
| NutanixHypervisor.Task.percentage_complete | Number | Completion percentage of the task. | 
| NutanixHypervisor.Task.progress_status | String | Progress status of the task, for example, Succeeded, Failed, etc. | 
| NutanixHypervisor.Task.subtask_uuid_list | String | The list of the UUIDs of the subtasks for this task. | 
| NutanixHypervisor.Task.cluster_uuid | String | The UUID of the cluster. | 


#### Command Example
```!nutanix-hypervisor-task-results-get task_ids=072f64d8-c737-4230-a1ec-199b449b9795```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "Task": {
            "cluster_uuid": "asra1631-a234-zxd1-aa23-azxr124z23aq",
            "complete_time": "2021-02-03T15:51:26.579757+00:00",
            "complete_time_usecs": 1612367486579757,
            "create_time": "2021-02-03T15:51:26.346257+00:00",
            "create_time_usecs": 1612367486346257,
            "entity_list": [
                {
                    "entity_id": "16c3d845-dc54-4fb1-bfc8-7671dd230967",
                    "entity_type": "VM"
                }
            ],
            "last_updated": "2021-02-03T15:51:26.579757+00:00",
            "last_updated_time_usecs": 1612367486579757,
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
            "start_time": "2021-02-03T15:51:26.376685+00:00",
            "start_time_usecs": 1612367486376685,
            "subtask_uuid_list": [
                "6f90a15d-ad76-4782-89bd-80811f162543"
            ],
            "uuid": "072f64d8-c737-4230-a1ec-199b449b9795"
        }
    }
}
```

#### Human Readable Output

>### Nutanix Hypervisor Tasks Status
>|cluster_uuid|complete_time|complete_time_usecs|create_time|create_time_usecs|entity_list|last_updated|last_updated_time_usecs|message|meta_request|meta_response|operation_type|percentage_complete|progress_status|start_time|start_time_usecs|subtask_uuid_list|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| asra1631-a234-zxd1-aa23-azxr124z23aq | 2021-02-03T15:51:26.579757+00:00 | 1612367486579757 | 2021-02-03T15:51:26.346257+00:00 | 1612367486346257 | {'entity_id': '16c3d845-dc54-4fb1-bfc8-7671dd230967', 'entity_type': 'VM'} | 2021-02-03T15:51:26.579757+00:00 | 1612367486579757 |  | method_name: VmChangePowerState | error_code: 17<br/>error_detail: Cannot complete request in state InvalidVmState: Cannot complete request in state On | VmChangePowerState | 100 | Failed | 2021-02-03T15:51:26.376685+00:00 | 1612367486376685 | 6f90a15d-ad76-4782-89bd-80811f162543 | 072f64d8-c737-4230-a1ec-199b449b9795 |


### nutanix-hypervisor-alerts-list
***
Gets the list of alerts generated in the cluster that matches the filters. Nutanix fetches the latest alerts created if there are more than the defined maximum number of alerts.


#### Base Command

`nutanix-hypervisor-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start date in ISO date format, epoch time or time range(`<number>` `<time unit>`, e.g., 12 hours, 7 days). Only alerts that were created on or after the specified date/time will be retrieved. If no time zone is specified, UTC time zone will be used. | Optional | 
| end_time | The end date in ISO date format, epoch time or time range(`<number&>` `<time unit>`, e.g., 12 hours, 7 days). Only alerts that were created on or before the specified date/time will be retrieved. If no time zone is specified, UTC time zone will be used. | Optional | 
| resolved | If true, retrieves alerts that have been resolved. If false, retrieves alerts that have not been resolved. Possible values are: true, false. | Optional | 
| auto_resolved | If true, retrieves alerts that have been resolved, and were auto_resolved. If false, retrieves alerts that have been resolved, and were not auto_resolved. Possible values are: true, false. | Optional | 
| acknowledged | If true, retrieves alerts that have been acknowledged. If false, retrieves alerts that have not been acknowledged. Possible values are: true, false. | Optional | 
| severity | Comma-separated list of the severity levels of the alerts to retrieve. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| alert_type_ids | Comma-separated list of alert type IDs. Will retrieve alerts whose type ID matches an alert_type_id in the alert_type_ids list. For example, alert 'Alert E-mail Failure' has type id of A111066. Given alert_type_ids= 'A111066', only alerts of 'Alert E-mail Failure' will be retrieved. | Optional | 
| impact_types | Comma-separated list of impact types. Possible values: Availability, Capacity, Configuration, Performance, and System Indicator. Will retrieve alerts whose impact type matches an impact types in the impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types ='SystemIndicator',only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be retrieved. Possible values are: Availability, Capacity, Configuration, Performance, System Indicator. | Optional | 
| entity_types | Comma-separated list of entity types. Will retrieve alerts whose entity_type matches an entity_type in the entity_types list. For details, see the Nutanix README. If the Nutanix service cannot recognize the entity type, it returns a 404 error. | Optional | 
| page | Page number in the query response. Default is 1. | Optional | 
| limit | Maximum number of physical hosts to retrieve. Possible values are 1-1000. Default is 50. | Optional | 
| verbose | Receive extended information from Nutanix about alerts. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Alerts.id | String | ID of the alert. | 
| NutanixHypervisor.Alerts.alert_type_uuid | String | UUID of the type of the alert. | 
| NutanixHypervisor.Alerts.check_id | String | The check ID of the alert. | 
| NutanixHypervisor.Alerts.resolved | Boolean | Whether the alert was resolved. | 
| NutanixHypervisor.Alerts.auto_resolved | Boolean | Whether the alert was auto resolved. | 
| NutanixHypervisor.Alerts.acknowledged | Boolean | Whether the alert was acknowledged. | 
| NutanixHypervisor.Alerts.service_vmid | String | Service virtual machine ID of the alert. | 
| NutanixHypervisor.Alerts.node_uuid | String | Node UUID. | 
| NutanixHypervisor.Alerts.created_time_stamp_in_usecs | Number | The time the alert was created in epoch time. | 
| NutanixHypervisor.Alerts.created_time | date | The time alert was created in epoch time. | 
| NutanixHypervisor.Alerts.last_occurrence_time_stamp_in_usecs | Number | The time of the last occurrence of the alert in epoch time. | 
| NutanixHypervisor.Alerts.last_occurrence | date | The time of the last occurrence of the alert in epoch time. | 
| NutanixHypervisor.Alerts.cluster_uuid | String | The cluster UUID of the alert. | 
| NutanixHypervisor.Alerts.originating_cluster_uuid | String | The originating cluster UUID of the alert. | 
| NutanixHypervisor.Alerts.severity | String | The severity of the alert. | 
| NutanixHypervisor.Alerts.impact_types | String | The impact types of the alert. | 
| NutanixHypervisor.Alerts.classifications | String | The classifications of the alert. | 
| NutanixHypervisor.Alerts.acknowledged_by_username | String | The username of whom acknowledged the alert, if the alert was acknowledged by a user. | 
| NutanixHypervisor.Alerts.message | String | Alert message. | 
| NutanixHypervisor.Alerts.detailed_message | String | Alert detailed message. | 
| NutanixHypervisor.Alerts.alert_title | String | Alert title. | 
| NutanixHypervisor.Alerts.operation_type | String | Alert operation type. | 
| NutanixHypervisor.Alerts.acknowledged_time_stamp_in_usecs | Number | The time the alert was acknowledged in epoch time. | 
| NutanixHypervisor.Alerts.acknowledged_time | date | The time the alert was acknowledged in epoch time. | 
| NutanixHypervisor.Alerts.resolved_time_stamp_in_usecs | Number | The time the alert was resolved in epoch time. | 
| NutanixHypervisor.Alerts.resolved_time | date | The time alert was resolved in epoch time. | 
| NutanixHypervisor.Alerts.resolved_by_username | String | The username whom resolved the alert, if the alert was resolved by a user. | 
| NutanixHypervisor.Alerts.user_defined | Boolean | Whether the alert user was defined. | 
| NutanixHypervisor.Alerts.affected_entities.entity_type | String | Affected entity type. | 
| NutanixHypervisor.Alerts.affected_entities.entity_type_display_name | String | The entity type display name of the affected entities. | 
| NutanixHypervisor.Alerts.affected_entities.entity_name | String | The entity display name of the affected entities. | 
| NutanixHypervisor.Alerts.affected_entities.uuid | String | The affected entity UUID. | 
| NutanixHypervisor.Alerts.affected_entities.id | String | The affected entity ID. | 
| NutanixHypervisor.Alerts.context_types | String | Alert context types. | 
| NutanixHypervisor.Alerts.context_values | String | Alert context values. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.comparison_operator | String | Comparison operator used in the metric. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.condition_type | String | Condition type of the alert by metric. Can be: STATIC, THRESHOLD, ANOMALY, SAFETY_ZONE. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.data_type | String | Data type used in the metric. Can be: LONG, DOUBLE, BOOLEAN, STRING. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_category | String | Metric category. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_display_name | String | Metric display name. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_name | String | Metric name. | 
| NutanixHypervisor.Alerts.alert_details.metric_details.metric_value_details | Unknown | Metric value details. | 


#### Command Example
```!nutanix-hypervisor-alerts-list acknowledged=true auto_resolved=true resolved=true start_time=2018-12-31T21:34:54 limit=4```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "Alerts": [
            {
                "acknowledged": true,
                "acknowledged_by_username": "N/A",
                "acknowledged_time": "2020-11-25T15:28:02.804764+00:00",
                "acknowledged_time_stamp_in_usecs": 1606318082804764,
                "affected_entities": [
                    {
                        "entity_type": "host",
                        "id": "2",
                        "uuid": "59bc015e-a22d-41ab-9ce2-a96164955e9q"
                    }
                ],
                "alert_title": "{vm_type} time not synchronized with any external servers.",
                "alert_type_uuid": "A3026",
                "auto_resolved": true,
                "check_id": "asra1631-a234-zxd1-aa23-azxr124z23aq::3026",
                "classifications": [
                    "ControllerVM"
                ],
                "cluster_uuid": "asra1631-a234-zxd1-aa23-azxr124z23aq",
                "created_time": "2020-11-22T14:31:14.675609+00:00",
                "created_time_stamp_in_usecs": 1606055474675609,
                "detailed_message": "",
                "id": "4b12dc84-2a77-4b3a-a40a-2dc47c919caa",
                "impact_types": [
                    "Configuration"
                ],
                "last_occurrence": "2020-11-22T14:31:14.675609+00:00",
                "last_occurrence_time_stamp_in_usecs": 1606055474675609,
                "message": "The {vm_type} is not synchronizing time with any external servers. {alert_msg}",
                "node_uuid": "59bc015e-a22d-41ab-9ce2-a96164955e9q",
                "operation_type": "kCreate",
                "originating_cluster_uuid": "asra1631-a234-zxd1-aa23-azxr124z23aq",
                "resolved": true,
                "resolved_by_username": "N/A",
                "resolved_time": "2020-11-25T15:28:02.804758+00:00",
                "resolved_time_stamp_in_usecs": 1606318082804758,
                "service_vmid": "asra1631-a234-zxd1-aa23-azxr124z23aq::2",
                "severity": "kWarning",
                "user_defined": false
            },
            {
                "acknowledged": true,
                "acknowledged_by_username": "N/A",
                "acknowledged_time": "2020-11-25T15:28:02.851718+00:00",
                "acknowledged_time_stamp_in_usecs": 1606318082851718,
                "affected_entities": [
                    {
                        "entity_type": "host",
                        "id": "2",
                        "uuid": "59bc015e-a22d-41ab-9ce2-a96164955e9q"
                    }
                ],
                "alert_title": "Incorrect NTP Configuration",
                "alert_type_uuid": "A103076",
                "auto_resolved": true,
                "check_id": "asra1631-a234-zxd1-aa23-azxr124z23aq::103076",
                "classifications": [
                    "Cluster"
                ],
                "cluster_uuid": "asra1631-a234-zxd1-aa23-azxr124z23aq",
                "created_time": "2020-11-22T14:31:14.619018+00:00",
                "created_time_stamp_in_usecs": 1606055474619018,
                "detailed_message": "",
                "id": "1c63dcd9-3b36-45a6-8991-d28cc661c861",
                "impact_types": [
                    "SystemIndicator"
                ],
                "last_occurrence": "2020-11-22T14:31:14.619018+00:00",
                "last_occurrence_time_stamp_in_usecs": 1606055474619018,
                "message": "{alert_msg}",
                "node_uuid": "59bc015e-a22d-41ab-9ce2-a96164955e9q",
                "operation_type": "kCreate",
                "originating_cluster_uuid": "asra1631-a234-zxd1-aa23-azxr124z23aq",
                "resolved": true,
                "resolved_by_username": "N/A",
                "resolved_time": "2020-11-25T15:28:02.851706+00:00",
                "resolved_time_stamp_in_usecs": 1606318082851706,
                "service_vmid": "asra1631-a234-zxd1-aa23-azxr124z23aq::2",
                "severity": "kWarning",
                "user_defined": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Nutanix Alert List
>|impact_types|created_time_stamp_in_usecs|created_time|severity|acknowledged_time_stamp_in_usecs|resolved|acknowledged_by_username|resolved_by_username|last_occurrence_time_stamp_in_usecs|acknowledged_time|check_id|alert_title|service_vmid|id|classifications|acknowledged|resolved_time|last_occurrence|alert_type_uuid|detailed_message|operation_type|originating_cluster_uuid|message|node_uuid|user_defined|cluster_uuid|auto_resolved|resolved_time_stamp_in_usecs|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Configuration | 1606055474675609 | 2020-11-22T14:31:14.675609+00:00 | kWarning | 1606318082804764 | true | N/A | N/A | 1606055474675609 | 2020-11-25T15:28:02.804764+00:00 | asra1631-a234-zxd1-aa23-azxr124z23aq::3026 | {vm_type} time not synchronized with any external servers. | asra1631-a234-zxd1-aa23-azxr124z23aq::2 | 4b12dc84-2a77-4b3a-a40a-2dc47c919caa | ControllerVM | true | 2020-11-25T15:28:02.804758+00:00 | 2020-11-22T14:31:14.675609+00:00 | A3026 |  | kCreate | asra1631-a234-zxd1-aa23-azxr124z23aq | The {vm_type} is not synchronizing time with any external servers. {alert_msg} | 59bc015e-a22d-41ab-9ce2-a96164955e9q | false | asra1631-a234-zxd1-aa23-azxr124z23aq | true | 1606318082804758 |
>| SystemIndicator | 1606055474619018 | 2020-11-22T14:31:14.619018+00:00 | kWarning | 1606318082851718 | true | N/A | N/A | 1606055474619018 | 2020-11-25T15:28:02.851718+00:00 | asra1631-a234-zxd1-aa23-azxr124z23aq::103076 | Incorrect NTP Configuration | asra1631-a234-zxd1-aa23-azxr124z23aq::2 | 1c63dcd9-3b36-45a6-8991-d28cc661c861 | Cluster | true | 2020-11-25T15:28:02.851706+00:00 | 2020-11-22T14:31:14.619018+00:00 | A103076 |  | kCreate | asra1631-a234-zxd1-aa23-azxr124z23aq | {alert_msg} | 59bc015e-a22d-41ab-9ce2-a96164955e9q | false | asra1631-a234-zxd1-aa23-azxr124z23aq | true | 1606318082851706 |


### nutanix-hypervisor-alert-acknowledge
***
Acknowledges the alert with the specified alert_id.


#### Base Command

`nutanix-hypervisor-alert-acknowledge`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to acknowledge. Alert ID is the 'id' field returned for alerts by command 'nutanix-hypervisor-alerts-list'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.AcknowledgedAlerts.id | String | ID of the alert to be acknowledged. | 
| NutanixHypervisor.AcknowledgedAlerts.successful | Boolean | Whether the alert was acknowledged successfully. | 
| NutanixHypervisor.AcknowledgedAlerts.message | String | The message returned by the acknowledge task. | 


#### Command Example
```!nutanix-hypervisor-alert-acknowledge alert_id=da53aaa3-8c29-4b68-9f27-e0927ca694ce```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "AcknowledgedAlerts": {
            "id": "da53aaa3-8c29-4b68-9f27-e0927ca694ce",
            "message": null,
            "successful": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|message|successful|
>|---|---|---|
>| da53aaa3-8c29-4b68-9f27-e0927ca694ce |  | true |


### nutanix-hypervisor-alert-resolve
***
Resolves the alert with the specified alert_id. Alert ID is the 'id' field returned for alerts by command 'nutanix-hypervisor-alerts-list'


#### Base Command

`nutanix-hypervisor-alert-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to resolve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.ResolvedAlerts.id | String | ID of the alert to be resolved. | 
| NutanixHypervisor.ResolvedAlerts.successful | Boolean | Whether the alert was resolved successfully. | 
| NutanixHypervisor.ResolvedAlerts.message | String | The message returned by the resolve task. | 


#### Command Example
```!nutanix-hypervisor-alert-resolve alert_id=da53aaa3-8c29-4b68-9f27-e0927ca694ce```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "ResolvedAlerts": {
            "id": "da53aaa3-8c29-4b68-9f27-e0927ca694ce",
            "message": null,
            "successful": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|message|successful|
>|---|---|---|
>| da53aaa3-8c29-4b68-9f27-e0927ca694ce |  | true |


### nutanix-hypervisor-alerts-acknowledge-by-filter
***
Acknowledges alerts using a filter.


#### Base Command

`nutanix-hypervisor-alerts-acknowledge-by-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start date in ISO date format, epoch time or time range(`<number>`; `<time unit>`, e.g., 12 hours, 7 days). Only alerts that were created on or after the specified date/time will be acknowledged. If no time zone is specified, UTC time zone will be used. | Optional | 
| end_time | The end date in ISO date format, epoch time or time range(`<number>` `<time unit>`;', e.g., 12 hours, 7 days). Only alerts that were created on or before the specified date/time will be acknowledged. If no time zone is specified, UTC time zone will be used. | Optional | 
| severity | Comma-separated list of the severity levels of the alerts to resolve. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| impact_types | Comma-separated list of impact types. Will acknowledge alerts whose impact type matches an impact types in the impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types ='SystemIndicator', only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be acknowledged. | Optional | 
| entity_types | Comma-separated list of entity types. Will retrieve alerts whose entity_type matches an entity_type in the entity_types list. For more details see Nutanix README. If Nutanix service cannot recognize the entity type, it returns a 404 error. | Optional | 
| limit | Maximum number of alerts to acknowledge. Nutanix does not have a maximum for the limit, but a very high limit will cause a read timeout exception. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.AcknowledgedFilterAlerts.num_successful_updates | Number | The number of the successful alerts acknowledged. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.num_failed_updates | Number | The number of the failed alerts to acknowledge. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.alert_status_list.id | String | ID of the status of the alert. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.alert_status_list.successful | Boolean | Whether acknowledgement for this task was successful. | 
| NutanixHypervisor.AcknowledgedFilterAlerts.alert_status_list.message | String | Message returned by the acknowledge operation. | 


#### Command Example
```!nutanix-hypervisor-alerts-acknowledge-by-filter end_time=2021-12-22T13:14:15 entity_types=Host severity=WARNING```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "AcknowledgedFilterAlerts": {
            "num_failed_updates": 0,
            "num_successful_updates": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|num_failed_updates|num_successful_updates|
>|---|---|
>| 0 | 0 |


### nutanix-hypervisor-alerts-resolve-by-filter
***
Resolves alerts using a filter.


#### Base Command

`nutanix-hypervisor-alerts-resolve-by-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start date in ISO date format, epoch time or time range(&lt;number&gt; &lt;time unit&gt;', e.g., 12 hours, 7 days). Only alerts that were created on or after the specified date/time will be resolved. If no time zone is specified, UTC time zone will be used. | Optional | 
| end_time | The end date in ISO date format, epoch time or time range(&lt;number&gt; &lt;time unit&gt;', e.g., 12 hours, 7 days). Only alerts that were created on or before the specified date/time will be resolved. If no time zone is specified, UTC time zone will be used. | Optional | 
| severity | Comma-separated list of the severity levels of the alerts to resolve. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| impact_types | Comma-separated list of impact types. Will resolve alerts whose impact type matches an impact types in the impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types = 'SystemIndicator', only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be resolved. | Optional | 
| entity_types | Comma-separated list of entity types. Will resolve alerts whose entity_type matches an entity_type in the entity_types list. For more details see Nutanix README. If Nutanix service cannot recognize the entity type, it returns a 404 error. | Optional | 
| limit | Maximum number of alerts to resolve. Nutanix does not have a maximum for the limit, but a very high limit value will cause a read timeout exception. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.ResolvedFilterAlerts.num_successful_updates | Number | The number of successful alerts resolved. | 
| NutanixHypervisor.ResolvedFilterAlerts.num_failed_updates | Number | The number of failed alerts to resolve. | 
| NutanixHypervisor.ResolvedFilterAlerts.alert_status_list.id | String | ID of the status of the alert. | 
| NutanixHypervisor.ResolvedFilterAlerts.alert_status_list.successful | Boolean | Whether the resolution for this task was successful. | 
| NutanixHypervisor.ResolvedFilterAlerts.alert_status_list.message | String | Message returned by the resolve operation. | 


#### Command Example
```!nutanix-hypervisor-alerts-resolve-by-filter limit=2 impact_types=SystemIndicator entity_types=VM```

#### Context Example
```json
{
    "NutanixHypervisor": {
        "ResolvedFilterAlerts": {
            "num_failed_updates": 0,
            "num_successful_updates": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|num_failed_updates|num_successful_updates|
>|---|---|
>| 0 | 0 |

