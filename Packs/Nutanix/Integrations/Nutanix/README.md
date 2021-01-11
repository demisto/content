Nutanix Hypervisor abstracts and isolates the VMs and their programs from the underlying server hardware, enabling a
more efficient use of physical resources, simpler maintenance and operations, and reduced costs. This integration was
integrated and tested with version v2 of Nutanix

## Configure Nutanix on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nutanix.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
          | --- | --- | --- |
   | base_url | Server URL \(e.g. https://example.net\) | True |
   | isFetch | Fetch incidents | False |
   | incidentType | Incident type | False |
   | insecure | Trust any certificate \(not secure\) | False |
   | proxy | Use system proxy settings | False |
   | username | Username | True |
   | password | Password | True |
   | incidentFetchInterval | Incidents Fetch Interval | False |
   | max_fetch |  | False |
   | resolved | Resolved | False |
   | auto_resolved | Auto Resolved | False |
   | acknowledged | Acknowledged | False |
   | alert_type_uuids | Alert Type Uuids | False |
   | entity_id | Entity Id | False |
   | impact_types | Impact Types | False |
   | classifications | Classifications | False |
   | entity_type_ids |  | False |
   | first_fetch | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### nutanix-hypervisor-hosts-list

***
Get the list of physical hosts configured in the cluster.

#### Base Command

`nutanix-hypervisor-hosts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Retrieve hosts that matches the filters given. Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value. Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example: storage.capacity_bytes==2;host_nic_ids!=35,host_gpus==x is parsed by Nutanix the following way: Return all hosts s.t (storage.capacity_bytes == 2 AND host_nic_ids != 35) OR host_gpus == x. | Optional | 
| page | Page number in the query response, default is 1. When page is specified, limit argument is required. | Optional | 
| limit | Limit of physical hosts to retrieve. Possible values are 1-1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Host | string | Host list | 

#### Command Example

```!nutanix-hypervisor-hosts-list filter="num_vms==2" limit=3 page=1```

#### Context Example

```json
{
  "NutanixHypervisor": {
    "Host": {
      "acropolis_connection_state": "kConnected",
      "backplane_ip": null,
      "bios_model": null,
      "bios_version": null,
      "block_location": null,
      "block_model": "UseLayout",
      "block_model_name": "CommunityEdition",
      "block_serial": "xxxxxxxx",
      "bmc_model": null,
      "bmc_version": null,
      "boot_time_in_usecs": 1606054432399817,
      "cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "controller_vm_backplane_ip": "xxx.xxx.x.xxx",
      "cpu_capacity_in_hz": 16760000000,
      "cpu_frequency_in_hz": 2095000000,
      "cpu_model": "Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz",
      "default_vhd_location": null,
      "default_vhd_storage_container_id": null,
      "default_vhd_storage_container_uuid": null,
      "default_vm_location": null,
      "default_vm_storage_container_id": null,
      "default_vm_storage_container_uuid": null,
      "disk_hardware_configs": {
        "1": {
          "background_operation": null,
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
        "10": null,
        "11": null,
        "12": null,
        "13": null,
        "14": null,
        "15": null,
        "16": null,
        "17": null,
        "18": null,
        "19": null,
        "2": {
          "background_operation": null,
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
        },
        "20": null,
        "21": null,
        "22": null,
        "23": null,
        "24": null,
        "25": null,
        "26": null,
        "3": null,
        "4": null,
        "5": null,
        "6": null,
        "7": null,
        "8": null,
        "9": null
      },
      "dynamic_ring_changing_node": null,
      "failover_cluster_fqdn": null,
      "failover_cluster_node_state": null,
      "gpu_driver_version": null,
      "has_csr": false,
      "hba_firmwares_list": null,
      "host_gpus": null,
      "host_in_maintenance_mode": null,
      "host_maintenance_mode_reason": null,
      "host_nic_ids": [],
      "host_type": "HYPER_CONVERGED",
      "hypervisor_address": "xxx.xxx.x.xxx",
      "hypervisor_full_name": "Nutanix xxxxxxxx.xxx",
      "hypervisor_key": "xxx.xxx.x.xxx",
      "hypervisor_password": null,
      "hypervisor_state": "kAcropolisNormal",
      "hypervisor_type": "kKvm",
      "hypervisor_username": "root",
      "ipmi_address": null,
      "ipmi_password": null,
      "ipmi_username": null,
      "is_degraded": false,
      "is_hardware_virtualized": false,
      "is_secure_booted": false,
      "key_management_device_to_certificate_status": {},
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
        "ordinal": 1,
        "physical_position": null
      },
      "rdma_backplane_ips": null,
      "reboot_pending": false,
      "removal_status": [
        "NA"
      ],
      "serial": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "service_vmexternal_ip": "xxx.xxx.x.xxx",
      "service_vmid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x",
      "service_vmnat_ip": null,
      "service_vmnat_port": null,
      "state": "NORMAL",
      "stats": {
        "avg_io_latency_usecs": "1342",
        "avg_read_io_latency_usecs": "-1",
        "avg_write_io_latency_usecs": "-1",
        "content_cache_hit_ppm": "1000000",
        "content_cache_logical_memory_usage_bytes": "3096143424",
        "content_cache_logical_ssd_usage_bytes": "0",
        "content_cache_num_dedup_ref_count_pph": "100",
        "content_cache_num_lookups": "9",
        "content_cache_physical_memory_usage_bytes": "3096143424",
        "content_cache_physical_ssd_usage_bytes": "0",
        "content_cache_saved_memory_usage_bytes": "0",
        "content_cache_saved_ssd_usage_bytes": "0",
        "controller_avg_io_latency_usecs": "0",
        "controller_avg_read_io_latency_usecs": "0",
        "controller_avg_read_io_size_kbytes": "0",
        "controller_avg_write_io_latency_usecs": "0",
        "controller_avg_write_io_size_kbytes": "0",
        "controller_io_bandwidth_kBps": "0",
        "controller_num_io": "0",
        "controller_num_iops": "0",
        "controller_num_random_io": "0",
        "controller_num_read_io": "0",
        "controller_num_read_iops": "0",
        "controller_num_seq_io": "-1",
        "controller_num_write_io": "0",
        "controller_num_write_iops": "0",
        "controller_random_io_ppm": "-1",
        "controller_read_io_bandwidth_kBps": "0",
        "controller_read_io_ppm": "0",
        "controller_seq_io_ppm": "-1",
        "controller_timespan_usecs": "30000000",
        "controller_total_io_size_kbytes": "0",
        "controller_total_io_time_usecs": "0",
        "controller_total_read_io_size_kbytes": "0",
        "controller_total_read_io_time_usecs": "0",
        "controller_total_transformed_usage_bytes": "-1",
        "controller_write_io_bandwidth_kBps": "0",
        "controller_write_io_ppm": "0",
        "hypervisor_avg_io_latency_usecs": "0",
        "hypervisor_avg_read_io_latency_usecs": "0",
        "hypervisor_avg_write_io_latency_usecs": "0",
        "hypervisor_cpu_usage_ppm": "136060",
        "hypervisor_io_bandwidth_kBps": "0",
        "hypervisor_memory_usage_ppm": "666265",
        "hypervisor_num_io": "0",
        "hypervisor_num_iops": "0",
        "hypervisor_num_read_io": "0",
        "hypervisor_num_read_iops": "0",
        "hypervisor_num_received_bytes": "0",
        "hypervisor_num_transmitted_bytes": "0",
        "hypervisor_num_write_io": "0",
        "hypervisor_num_write_iops": "0",
        "hypervisor_read_io_bandwidth_kBps": "0",
        "hypervisor_timespan_usecs": "35676623",
        "hypervisor_total_io_size_kbytes": "0",
        "hypervisor_total_io_time_usecs": "0",
        "hypervisor_total_read_io_size_kbytes": "0",
        "hypervisor_total_read_io_time_usecs": "0",
        "hypervisor_write_io_bandwidth_kBps": "0",
        "io_bandwidth_kBps": "1",
        "num_io": "6",
        "num_iops": "0",
        "num_random_io": "-1",
        "num_read_io": "3",
        "num_read_iops": "0",
        "num_seq_io": "-1",
        "num_write_io": "3",
        "num_write_iops": "0",
        "random_io_ppm": "-1",
        "read_io_bandwidth_kBps": "0",
        "read_io_ppm": "500000",
        "seq_io_ppm": "-1",
        "timespan_usecs": "30000000",
        "total_io_size_kbytes": "54",
        "total_io_time_usecs": "8057",
        "total_read_io_size_kbytes": "22",
        "total_read_io_time_usecs": "-1",
        "total_transformed_usage_bytes": "-1",
        "total_untransformed_usage_bytes": "-1",
        "write_io_bandwidth_kBps": "1",
        "write_io_ppm": "500000"
      },
      "usage_stats": {
        "storage.capacity_bytes": "511803343324",
        "storage.free_bytes": "508614924622",
        "storage.logical_usage_bytes": "3775823872",
        "storage.usage_bytes": "3188418702",
        "storage_tier.das-sata.capacity_bytes": "0",
        "storage_tier.das-sata.free_bytes": "0",
        "storage_tier.das-sata.usage_bytes": "0",
        "storage_tier.ssd.capacity_bytes": "511803343324",
        "storage_tier.ssd.free_bytes": "508614924622",
        "storage_tier.ssd.usage_bytes": "3188418702"
      },
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "vzone_name": ""
    }
  }
}
```

#### Human Readable Output

> ### Results
>|acropolis_connection_state|backplane_ip|bios_model|bios_version|block_location|block_model|block_model_name|block_serial|bmc_model|bmc_version|boot_time_in_usecs|cluster_uuid|controller_vm_backplane_ip|cpu_capacity_in_hz|cpu_frequency_in_hz|cpu_model|default_vhd_location|default_vhd_storage_container_id|default_vhd_storage_container_uuid|default_vm_location|default_vm_storage_container_id|default_vm_storage_container_uuid|disk_hardware_configs|dynamic_ring_changing_node|failover_cluster_fqdn|failover_cluster_node_state|gpu_driver_version|has_csr|hba_firmwares_list|host_gpus|host_in_maintenance_mode|host_maintenance_mode_reason|host_nic_ids|host_type|hypervisor_address|hypervisor_full_name|hypervisor_key|hypervisor_password|hypervisor_state|hypervisor_type|hypervisor_username|ipmi_address|ipmi_password|ipmi_username|is_degraded|is_hardware_virtualized|is_secure_booted|key_management_device_to_certificate_status|management_server_name|memory_capacity_in_bytes|metadata_store_status|metadata_store_status_message|monitored|name|num_cpu_cores|num_cpu_sockets|num_cpu_threads|num_vms|oplog_disk_pct|oplog_disk_size|position|rdma_backplane_ips|reboot_pending|removal_status|serial|service_vmexternal_ip|service_vmid|service_vmnat_ip|service_vmnat_port|state|stats|usage_stats|uuid|vzone_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| kConnected |  |  |  |  | UseLayout | CommunityEdition | xxxxxxxx |  |  | 1606054432399817 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | xxx.xxx.x.xxx | 16760000000 | 2095000000 | Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz |  |  |  |  |  |  | 1: {"serial_number": "drive-scsi0-0-0-0", "disk_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::12", "disk_uuid": "f062895b-8cc9-496a-bfd1-5d7e54cd285c", "location": 1, "bad": false, "mounted": true, "mount_path": "/home/nutanix/data/stargate-storage/disks/drive-scsi0-0-0-0", "model": "Virtual disk", "vendor": "Not Available", "boot_disk": true, "only_boot_disk": false, "under_diagnosis": false, "background_operation": null, "current_firmware_version": "2.5+", "target_firmware_version": "2.5+", "can_add_as_new_disk": false, "can_add_as_old_disk": false}<br/>2: {"serial_number": "drive-scsi0-0-0-1", "disk_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::13", "disk_uuid": "5be00813-22ed-47bd-8ee7-da295196d1a8", "location": 2, "bad": false, "mounted": true, "mount_path": "/home/nutanix/data/stargate-storage/disks/drive-scsi0-0-0-1", "model": "Virtual disk", "vendor": "Not Available", "boot_disk": false, "only_boot_disk": false, "under_diagnosis": false, "background_operation": null, "current_firmware_version": "2.5+", "target_firmware_version": "2.5+", "can_add_as_new_disk": false, "can_add_as_old_disk": false}<br/>3: null<br/>4: null<br/>5: null<br/>6: null<br/>7: null<br/>8: null<br/>9: null<br/>10: null<br/>11: null<br/>12: null<br/>13: null<br/>14: null<br/>15: null<br/>16: null<br/>17: null<br/>18: null<br/>19: null<br/>20: null<br/>21: null<br/>22: null<br/>23: null<br/>24: null<br/>25: null<br/>26: null |  |  |  |  | false |  |  |  |  |  | HYPER_CONVERGED | 192.168.1.120 | Nutanix 20190916.276 | 192.168.1.120 |  | kAcropolisNormal | kKvm | root |  |  |  | false | false | false |  | 192.168.1.120 | 33722204160 | kNormalMode | Metadata store enabled on the node | true | NTNX-xxxxxxxx-A | 8 | 2 | 8 | 2 | 10.8 | 72426913110 | ordinal: 1<br/>name: <br/>physical_position: null |  | false | NA | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | xxx.xxx.x.xxx | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x |  |  | NORMAL | hypervisor_avg_io_latency_usecs: 0<br/>num_read_iops: 0<br/>hypervisor_write_io_bandwidth_kBps: 0<br/>timespan_usecs: 30000000<br/>controller_num_read_iops: 0<br/>read_io_ppm: 500000<br/>controller_num_iops: 0<br/>total_read_io_time_usecs: -1<br/>controller_total_read_io_time_usecs: 0<br/>hypervisor_num_io: 0<br/>controller_total_transformed_usage_bytes: -1<br/>hypervisor_cpu_usage_ppm: 136060<br/>controller_num_write_io: 0<br/>avg_read_io_latency_usecs: -1<br/>content_cache_logical_ssd_usage_bytes: 0<br/>controller_total_io_time_usecs: 0<br/>controller_total_read_io_size_kbytes: 0<br/>controller_num_seq_io: -1<br/>controller_read_io_ppm: 0<br/>content_cache_num_lookups: 9<br/>controller_total_io_size_kbytes: 0<br/>content_cache_hit_ppm: 1000000<br/>controller_num_io: 0<br/>hypervisor_avg_read_io_latency_usecs: 0<br/>content_cache_num_dedup_ref_count_pph: 100<br/>num_write_iops: 0<br/>controller_num_random_io: 0<br/>num_iops: 0<br/>hypervisor_num_read_io: 0<br/>hypervisor_total_read_io_time_usecs: 0<br/>controller_avg_io_latency_usecs: 0<br/>num_io: 6<br/>controller_num_read_io: 0<br/>hypervisor_num_write_io: 0<br/>controller_seq_io_ppm: -1<br/>controller_read_io_bandwidth_kBps: 0<br/>controller_io_bandwidth_kBps: 0<br/>hypervisor_num_received_bytes: 0<br/>hypervisor_timespan_usecs: 35676623<br/>hypervisor_num_write_iops: 0<br/>total_read_io_size_kbytes: 22<br/>hypervisor_total_io_size_kbytes: 0<br/>avg_io_latency_usecs: 1342<br/>hypervisor_num_read_iops: 0<br/>content_cache_saved_ssd_usage_bytes: 0<br/>controller_write_io_bandwidth_kBps: 0<br/>controller_write_io_ppm: 0<br/>hypervisor_avg_write_io_latency_usecs: 0<br/>hypervisor_num_transmitted_bytes: 0<br/>hypervisor_total_read_io_size_kbytes: 0<br/>read_io_bandwidth_kBps: 0<br/>hypervisor_memory_usage_ppm: 666265<br/>hypervisor_num_iops: 0<br/>hypervisor_io_bandwidth_kBps: 0<br/>controller_num_write_iops: 0<br/>total_io_time_usecs: 8057<br/>content_cache_physical_ssd_usage_bytes: 0<br/>controller_random_io_ppm: -1<br/>controller_avg_read_io_size_kbytes: 0<br/>total_transformed_usage_bytes: -1<br/>avg_write_io_latency_usecs: -1<br/>num_read_io: 3<br/>write_io_bandwidth_kBps: 1<br/>hypervisor_read_io_bandwidth_kBps: 0<br/>random_io_ppm: -1<br/>total_untransformed_usage_bytes: -1<br/>hypervisor_total_io_time_usecs: 0<br/>num_random_io: -1<br/>controller_avg_write_io_size_kbytes: 0<br/>controller_avg_read_io_latency_usecs: 0<br/>num_write_io: 3<br/>total_io_size_kbytes: 54<br/>io_bandwidth_kBps: 1<br/>content_cache_physical_memory_usage_bytes: 3096143424<br/>controller_timespan_usecs: 30000000<br/>num_seq_io: -1<br/>content_cache_saved_memory_usage_bytes: 0<br/>seq_io_ppm: -1<br/>write_io_ppm: 500000<br/>controller_avg_write_io_latency_usecs: 0<br/>content_cache_logical_memory_usage_bytes: 3096143424 | storage_tier.das-sata.usage_bytes: 0<br/>storage.capacity_bytes: 511803343324<br/>storage.logical_usage_bytes: 3775823872<br/>storage_tier.das-sata.capacity_bytes: 0<br/>storage.free_bytes: 508614924622<br/>storage_tier.ssd.usage_bytes: 3188418702<br/>storage_tier.ssd.capacity_bytes: 511803343324<br/>storage_tier.das-sata.free_bytes: 0<br/>storage.usage_bytes: 3188418702<br/>storage_tier.ssd.free_bytes: 508614924622 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx |  |

### nutanix-hypervisor-vms-list

***
Get a list of virtual machines.

#### Base Command

`nutanix-hypervisor-vms-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Retrieve virtual machines that matches the filters given. Each filter is written in the following way: filter_name==filter_value or filter_name!=filter_value. Possible combinations of OR (using comma ',') and AND (using semicolon ';'), for Example: machine_type==pc;power_state!=off,ha_priority==0 is parsed by Nutanix the following way: Return all virtual machines s.t (machine type == pc AND power_state != off) OR ha_priority == 0. | Optional | 
| length | Number of virtual machines to retrieve. | Optional | 
| offset | The offset to start retrieving virtual machines. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.VM..affinity.policy | String | Affinity policy. | 
| NutanixHypervisor.VM..affinity.host_uuids | String | TODO. | 
| NutanixHypervisor.VM..allow_live_migrate | Boolean | Does virtual machine allow live migrate. | 
| NutanixHypervisor.VM..gpus_assigned | Boolean | Does virtual machine have gpus assigned. | 
| NutanixHypervisor.VM..boot.uefi_boot | Boolean | Does UEFI boot. | 
| NutanixHypervisor.VM..ha_priority | Number | HA priority. | 
| NutanixHypervisor.VM..host_uuid | String | Host uuid of the virtual machine. | 
| NutanixHypervisor.VM..memory_mb | Number | The memory size in mega bytes. | 
| NutanixHypervisor.VM..name | String | The name of the virtual machine. | 
| NutanixHypervisor.VM..num_cores_per_vcpu | Number | Number of cores per vcpu. | 
| NutanixHypervisor.VM..num_vcpus | Number | Number of vcpus. | 
| NutanixHypervisor.VM..power_state | String | The virtual machine current power state. | 
| NutanixHypervisor.VM..timezone | String | The virtual machine time zone. | 
| NutanixHypervisor.VM..uuid | String | The uuid of the virtual machine. | 
| NutanixHypervisor.VM..vm_features.AGENT_VM | Boolean | Does virtual machine have the feature AGENT VM. | 
| NutanixHypervisor.VM..vm_features.VGA_CONSOLE | Boolean | Does virtual machine have the feature VGA CONSOLE. | 
| NutanixHypervisor.VM..vm_logical_timestamp | Number | The logical timestamp of the virtual machine. | 
| NutanixHypervisor.VM..machine_type | String | The machine type of the virtual machine. | 

#### Command Example

```!nutanix-hypervisor-vms-list filter="num_vms==machine_type==pc,power_state!=off" length=3 offset=0```

#### Context Example

```json
{
  "NutanixHypervisor": {
    "VM": {
      "affinity": {
        "host_uuids": [
          "xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
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
      "vm_logical_timestamp": 86
    }
  }
}
```

#### Human Readable Output

> ### Results
>|affinity|allow_live_migrate|boot|gpus_assigned|ha_priority|host_uuid|machine_type|memory_mb|name|num_cores_per_vcpu|num_vcpus|power_state|timezone|uuid|vm_features|vm_logical_timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| policy: AFFINITY<br/>host_uuids: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | false | uefi_boot: false | false | 0 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | pc | 4096 | CentOS7_Test | 2 | 2 | on | UTC | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | AGENT_VM: false<br/>VGA_CONSOLE: true | 86 |

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

> ### Results
>|task_uuid|
>|---|
>| yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy |

### nutanix-hypervisor-task-poll

***
Poll tasks given by task_ids to check if they are ready. Returns all the tasks from 'task_ids' list that are ready at
the moment Nutanix service was polled. In case no task is ready, waits until at least one task is ready, unless given
argument 'timeout_interval' which waits time_interval seconds and in case no task had finished, returns a time out
response.

#### Base Command

`nutanix-hypervisor-task-poll`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_ids | The IDs of the tasks to poll. | Required | 
| timeout_interval | An integer number. Waits time_interval seconds and in case no task had finished, returns a time out response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Task..uuid | String | The task uuid. | 
| NutanixHypervisor.Task..meta_request.method_name | String | The name of the method performed for this task. | 
| NutanixHypervisor.Task..meta_response.error_code | Number | The Error code returned for the task. | 
| NutanixHypervisor.Task..meta_response.error_detail | String | The error details incase error code was not 0. | 
| NutanixHypervisor.Task..create_time_usecs | Number | The time task was created in epoch. | 
| NutanixHypervisor.Task..start_time_usecs | Number | The start time of the task in epoch time. | 
| NutanixHypervisor.Task..complete_time_usecs | Number | The completion time of the task in epoch time. | 
| NutanixHypervisor.Task..last_updated_time_usecs | Number | The last update of the task in epoch time. | 
| NutanixHypervisor.Task..entity_list.entity_id | String | Id of the entity. | 
| NutanixHypervisor.Task..entity_list.entity_type | String | Type of the entity. | 
| NutanixHypervisor.Task..entity_list.entity_name | String | The name of the entity. | 
| NutanixHypervisor.Task..operation_type | String | Operation type of the task. | 
| NutanixHypervisor.Task..message | String | Message. | 
| NutanixHypervisor.Task..percentage_complete | Number | Completion percentage of the task. | 
| NutanixHypervisor.Task..progress_status | String | Progress status of the task \(Succeeded, Failed, ...\). | 
| NutanixHypervisor.Task..subtask_uuid_list | String | The list of the uuids of the subtasks for this task. | 
| NutanixHypervisor.Task..cluster_uuid | String | The uuid of the cluster. | 

#### Command Example

```!nutanix-hypervisor-task-poll task_ids=b111bb11-b1b1-11b1-1bbb-1bb11b11111b```

#### Context Example

```json
{
  "NutanixHypervisor": {
    "Task": {
      "cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "complete_time_usecs": 1610288165197853,
      "create_time_usecs": 1610288160827398,
      "entity_list": [
        {
          "entity_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "entity_name": null,
          "entity_type": "VM"
        }
      ],
      "last_updated_time_usecs": 1610288165197853,
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
      "start_time_usecs": 1610288160863871,
      "subtask_uuid_list": [
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      ],
      "uuid": "b111bb11-b1b1-11b1-1bbb-1bb11b11111b"
    }
  }
}
```

#### Human Readable Output

> ### Results
>|cluster_uuid|complete_time_usecs|create_time_usecs|entity_list|last_updated_time_usecs|message|meta_request|meta_response|operation_type|percentage_complete|progress_status|start_time_usecs|subtask_uuid_list|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | 1610288165197853 | 1610288160827398 | {'entity_id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'entity_type': 'VM', 'entity_name': None} | 1610288165197853 |  | method_name: VmChangePowerState | error_code: 0 | VmChangePowerState | 100 | Succeeded | 1610288160863871 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | b111bb11-b1b1-11b1-1bbb-1bb11b11111b |

### nutanix-alerts-list

***
Get the list of Alerts generated in the cluster which matches the filters if given.

#### Base Command

`nutanix-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or after the specified date/time will be retrieved. Time is expected to be in UTC. | Optional | 
| end_time | A date in the format YYYY-MM-DDTHH:MM:SS (for example 2020-12-31T23:59:00). Only alerts that were created on or before the specified date/time will be retrieved. Time is expected to be in UTC. | Optional | 
| resolved | If resolved is True, retrieves alerts that have been resolved. If resolved is False, retrieves alerts that have not been resolved. Possible values are: true, false. | Optional | 
| auto_resolved | If auto_resolved is True, retrieves alerts that have been resolved, and were auto_resolved. If auto_resolved is False, retrieves alerts that have been resolved, and were not auto_resolved. Possible values are: true, false. | Optional | 
| acknowledged | If acknowledged is True, retrieves alerts that have been acknowledged. If acknowledged is False, retrieves alerts that have been acknowledged. Possible values are: true, false. | Optional | 
| severity | Comma separated list. Retrieve any alerts that their severity level matches one of the severities in severity list. Possible values are: CRITICAL, WARNING, INFO, AUDIT. | Optional | 
| alert_type_uuids | Comma separated list. Retrieve alerts that id of their type matches one alert_type_uuid in alert_type_uuids list. For example, alert 'Alert E-mail Failure' has type id of A111066. Given alert_type_uuids= 'A111066', only alerts of 'Alert E-mail Failure' will be retrieved. | Optional | 
| entity_ids | ADD DESCRIPTION. | Optional | 
| impact_types | Comma separated list. Retrieve alerts that their impact type matches one of the impact types in impact_types list. For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'. Given impact_types = 'SystemIndicator',only alerts with impact type 'SystemIndicator', such as 'Incorrect NTP Configuration' will be retrieved. Possible values are: Availability, Capacity, Configuration, Performance, System Indicator. | Optional | 
| classifications | Comma separated list. Retrieve alerts that their classifications matches one of the classification in classifications list given. For example, alert 'Pulse cannot connect to REST server endpoint' has classification of Cluster. Given classifications = 'cluster', only alerts with classification of 'cluster', such as 'Pulse cannot connect to REST server endpoint' will be retrieved. | Optional | 
| entity_types | Comma separated list. Retrieve alerts that their entity_type matches one of the entity_type in entity_types list. Examples for entity types: [VM, Host, Disk, Storage Container, Cluster]. If Nutanix service can't recognize the entity type, it returns 404 response. | Optional | 
| page | Page number in the query response, default is 1. When page is specified, limit argument is required. | Optional | 
| limit | Limit of physical hosts to retrieve. Possible values are 1-1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Alerts | unknown | ADD DESCRIPTION | 

#### Command Example

```!nutanix-alerts-list acknowledged=true auto_resolved=true start_time=2018-12-31T21:34:54 limit=4```

#### Context Example

```json
{
  "NutanixHypervisor": {
    "Alerts": [
      {
        "acknowledged": true,
        "acknowledged_by_username": "N/A",
        "acknowledged_time_stamp_in_usecs": 1606318082804764,
        "affected_entities": [
          {
            "entity_name": null,
            "entity_type": "host",
            "entity_type_display_name": null,
            "id": "2",
            "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          }
        ],
        "alert_details": null,
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
          "xxxx.xx.xx",
          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "xxxxxxxx"
        ],
        "created_time_stamp_in_usecs": 1606055474675609,
        "detailed_message": "",
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "impact_types": [
          "Configuration"
        ],
        "last_occurrence_time_stamp_in_usecs": 1606055474675609,
        "message": "The {vm_type} is not synchronizing time with any external servers. {alert_msg}",
        "node_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "operation_type": "kCreate",
        "originating_cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "possible_causes": [],
        "resolved": true,
        "resolved_by_username": "N/A",
        "resolved_time_stamp_in_usecs": 1606318082804758,
        "service_vmid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x",
        "severity": "kWarning",
        "user_defined": false
      },
      {
        "acknowledged": true,
        "acknowledged_by_username": "N/A",
        "acknowledged_time_stamp_in_usecs": 1606318082851718,
        "affected_entities": [
          {
            "entity_name": null,
            "entity_type": "host",
            "entity_type_display_name": null,
            "id": "2",
            "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          }
        ],
        "alert_details": null,
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
          "xxxx.xx.xx",
          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "xxxxxxxx"
        ],
        "created_time_stamp_in_usecs": 1606055474619018,
        "detailed_message": "",
        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "impact_types": [
          "SystemIndicator"
        ],
        "last_occurrence_time_stamp_in_usecs": 1606055474619018,
        "message": "{alert_msg}",
        "node_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "operation_type": "kCreate",
        "originating_cluster_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "possible_causes": [],
        "resolved": true,
        "resolved_by_username": "N/A",
        "resolved_time_stamp_in_usecs": 1606318082851706,
        "service_vmid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x",
        "severity": "kWarning",
        "user_defined": false
      }
    ]
  }
}
```

#### Human Readable Output

> ### Results
>|acknowledged|acknowledged_by_username|acknowledged_time_stamp_in_usecs|affected_entities|alert_details|alert_title|alert_type_uuid|auto_resolved|check_id|classifications|cluster_uuid|context_types|context_values|created_time_stamp_in_usecs|detailed_message|id|impact_types|last_occurrence_time_stamp_in_usecs|message|node_uuid|operation_type|originating_cluster_uuid|possible_causes|resolved|resolved_by_username|resolved_time_stamp_in_usecs|service_vmid|severity|user_defined|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | N/A | 1606318082804764 | {'entity_type': 'host', 'entity_type_display_name': None, 'entity_name': None, 'uuid': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'id': '2'} |  | {vm_type} time not synchronized with any external servers. | A3026 | true | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xxxx | ControllerVM | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | alert_msg,<br/>vm_type,<br/>arithmos_id,<br/>service_vm_id,<br/>ncc_version,<br/>nos_version,<br/>node_uuid,<br/>node_serial,<br/>block_serial | NTP leader is not synchronizing to an external NTP server,<br/>CVM,<br/>2,<br/>2,<br/>x.xx.x.x-xxxxxxxx,<br/>xxxx.xx.xx,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx | 1606055474675609 |  | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | Configuration | 1606055474675609 | The {vm_type} is not synchronizing time with any external servers. {alert_msg} | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | kCreate | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx |  | true | N/A | 1606318082804758 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x | kWarning | false |
>| true | N/A | 1606318082851718 | {'entity_type': 'host', 'entity_type_display_name': None, 'entity_name': None, 'uuid': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'id': '2'} |  | Incorrect NTP Configuration | A103076 | true | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::xxxxxx | Cluster | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | alert_msg,<br/>vm_type,<br/>arithmos_id,<br/>cvm_ip,<br/>service_vm_id,<br/>ncc_version,<br/>nos_version,<br/>node_uuid,<br/>node_serial,<br/>block_serial | This CVM is the NTP leader but it is not syncing time with any external NTP server. NTP configuration on CVM is not yet updated with the NTP servers configured in the cluster. The NTP configuration on the CVM will not be updated if the cluster time is in the future relative to the NTP servers.<br/>,<br/>CVM,<br/>2,<br/>xxx.xxx.x.xxx,<br/>2,<br/>x.xx.x.x-xxxxxxxx,<br/>xxxx.xx.xx,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,<br/>xxxxxxxx | 1606055474619018 |  | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | SystemIndicator | 1606055474619018 | {alert_msg} | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | kCreate | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx |  | true | N/A | 1606318082851706 | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::x | kWarning | false |

### nutanix-alert-acknowledge

***
Acknowledge alert with the specified alert_id.

### Important
The following command requires cluster admin or higher permissions,
in case you want to use this command,
make sure the user you are using have at least cluster admin permissions
(Permissions are found in Nutanix Settings in "Users And Roles" Category)

#### Base Command

`nutanix-alert-acknowledge`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The id of the alert to acknowledge. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Alert.id | String | Id of the alert to be acknowledged. | 
| NutanixHypervisor.Alert.successful | Boolean | Was acknowledge successful. | 
| NutanixHypervisor.Alert.message | String | The message returned by the acknowledge task. | 

#### Command Example

```!nutanix-alert-acknowledge alert_id=a1a1a1a1-1111-1111-1a1a-aa1a11a1a1a1```

#### Context Example

```json
{
  "NutanixHypervisor": {
    "Alert": {
      "id": "a1a1a1a1-1111-1111-1a1a-aa1a11a1a1a1",
      "message": null,
      "successful": true
    }
  }
}
```

#### Human Readable Output

> ### Results
>|id|message|successful|
>|---|---|---|
>| a1a1a1a1-1111-1111-1a1a-aa1a11a1a1a1 |  | true |

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
| NutanixHypervisor.Alert.id | String | Id of the alert to be resolved. | 
| NutanixHypervisor.Alert.successful | Boolean | Was resolve successful. | 
| NutanixHypervisor.Alert.message | String | The message returned by the resolve task. | 

#### Command Example

```!nutanix-alert-resolve alert_id=a1a1a1a1-1111-1111-1a1a-aa1a11a1a1a1```

#### Context Example

```json
{
  "NutanixHypervisor": {
    "Alert": {
      "id": "a1a1a1a1-1111-1111-1a1a-aa1a11a1a1a1",
      "message": null,
      "successful": true
    }
  }
}
```

#### Human Readable Output

> ### Results
>|id|message|successful|
>|---|---|---|
>| a1a1a1a1-1111-1111-1a1a-aa1a11a1a1a1 |  | true |

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
| classifications | Comma separated list. Acknowledge alerts that their classifications matches one of the classification in classifications list given. For example, alert 'Pulse cannot connect to REST server endpoint' has classification of Cluster. Given classifications = 'cluster', only alerts with classification of 'cluster', such as 'Pulse cannot connect to REST server endpoint' will be acknowledged. | Optional | 
| entity_types | Comma separated list. Acknowledge alerts that their entity_type matches one of the entity_type in entity_types list. Examples for entity types: [VM, Host, Disk, Storage Container, Cluster]. If Nutanix service can't recognize the entity type, it returns 404 response. | Optional | 
| entity_type_ids | TODO. | Optional | 
| limit | Maximum number of alerts to acknowledge. Nutanix does not have max for limit, but a very high limit value will cause read timeout exception. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Alert.num_successful_updates | Number | The number of the successful alerts acknowledges. | 
| NutanixHypervisor.Alert.num_failed_updates | Number | The number of the failed alerts to acknowledge. | 
| NutanixHypervisor.Alert.alert_status_list.id | String | TODO | 
| NutanixHypervisor.Alert.alert_status_list.successful | Boolean | Was acknowledge for this task successful. | 
| NutanixHypervisor.Alert.alert_status_list.message | String | Message returned by acknowledge operation. | 

#### Command Example

```!nutanix-alerts-acknowledge-by-filter end_time=2021-12-22T13:14:15 entity_types=Host classifications=ControllerVM severity=WARNING```

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

> ### Results
>|alert_status_list|num_failed_updates|num_successful_updates|
>|---|---|---|
>| {"id": "0:0", "successful": true, "message": null} | 0 | 1 |

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
| classifications | Comma separated list.Resolve alerts that their classifications matches one of the classification in classifications list given. For example, alert 'Pulse cannot connect to REST server endpoint' has classification of Cluster. Given classifications = 'cluster', only alerts with classification of 'cluster', such as 'Pulse cannot connect to REST server endpoint' will be resolved. | Optional | 
| entity_types | Comma separated list. Resolve alerts that their entity_type matches one of the entity_type in entity_types list. Examples for entity types: [VM, Host, Disk, Storage Container, Cluster]. If Nutanix service can't recognize the entity type, it returns 404 response. | Optional | 
| entity_type_ids | TODO. | Optional | 
| limit | Maximum number of alerts to resolve. Nutanix does not have max for limit, but a very high limit value will cause read timeout exception. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NutanixHypervisor.Alert.num_successful_updates | Number | The number of the successful alert resolves. | 
| NutanixHypervisor.Alert.num_failed_updates | Number | The number of the failed alerts to resolve. | 
| NutanixHypervisor.Alert.alert_status_list.id | String | TODO | 
| NutanixHypervisor.Alert.alert_status_list.successful | Boolean | Was resolve for this task successful. | 
| NutanixHypervisor.Alert.alert_status_list.message | String | Message returned by resolve operation. | 

#### Command Example

```!nutanix-alerts-resolve-by-filter classifications=cluster limit=2 impact_types=SystemIndicator entity_types=VM```

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

> ### Results
>|alert_status_list|num_failed_updates|num_successful_updates|
>|---|---|---|
>| {"id": "0:0", "successful": true, "message": null} | 0 | 1 |

