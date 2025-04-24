This integration enables the management of VMware vCenter and ESXi hosts directly from XSOAR using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the hosts by utilising VMware APIs.

## Requirements
* vCenter or ESXi Server 6.5 and above
* Paid License on vCenter or ESXi Server. Free vSphere Hypervistor will be read-only

## Networking
By default, TCP port 443 will be used to initiate a REST API connection to the vSphere host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.
## Configure Ansible VMware in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Hostname | The hostname or IP address of the vSphere vCenter or ESXi server. | True |
| Port | The port of the vSphere vCenter or ESXi server. | True |
| Username | The username to access the vSphere vCenter or ESXi server. | True |
| Password | The password to access the vSphere vCenter or ESXi server. | True |
| Validate Certs | Allows connection when SSL certificates are not valid. Set to \`false\` when certificates are not trusted. | True |


## Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

## State Arguement
Some of the commands in this integration take a state argument. These define the desired end state of the object being managed. As a result these commands are able to perform multiple management operations depending on the desired state value. Common state values are:
| **State** | **Result** |
| --- | --- |
| present | Object should exist. If not present, the object will be created with the provided parameters. If present but not with correct parameters, it will be modified to met provided parameters. |
| running | Object should be running not stopped. |
| stopped | Object should be stopped not running. |
| restarted | Object will be restarted. |
| absent | Object should not exist. If it it exists it will be deleted. |

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vmware-about-info
***
Provides information about VMware server to which user is connecting to
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_about_info_module.html


#### Base Command

`vmware-about-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareAboutInfo.about_info | string | dict about VMware server | 


#### Command Example
```!vmware-about-info ```

#### Context Example
```json
{
    "VMware": {
        "VmwareAboutInfo": [
            {
                "about_info": {
                    "api_type": "VirtualCenter",
                    "api_version": "6.5",
                    "build": "8024368",
                    "instance_uuid": "a2ed9f62-9d30-4ee8-90d0-0f8f830448b4",
                    "license_product_name": "VMware VirtualCenter Server",
                    "license_product_version": "6.0",
                    "locale_build": "000",
                    "locale_version": "INTL",
                    "os_type": "linux-x64",
                    "product_full_name": "VMware vCenter Server 6.5.0 build-8024368",
                    "product_line_id": "vpx",
                    "product_name": "VMware vCenter Server",
                    "vendor": "VMware, Inc.",
                    "version": "6.5.0"
                },
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## About_Info
>    * api_type: VirtualCenter
>    * api_version: 6.5
>    * build: 8024368
>    * instance_uuid: a2ed9f62-9d30-4ee8-90d0-0f8f830448b4
>    * license_product_name: VMware VirtualCenter Server
>    * license_product_version: 6.0
>    * locale_build: 000
>    * locale_version: INTL
>    * os_type: linux-x64
>    * product_full_name: VMware vCenter Server 6.5.0 build-8024368
>    * product_line_id: vpx
>    * product_name: VMware vCenter Server
>    * vendor: VMware, Inc.
>    * version: 6.5.0


### vmware-category
***
Manage VMware categories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_category_module.html


#### Base Command

`vmware-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category_name | The name of category to manage. | Required | 
| category_description | The category description. This is required only if `state` is set to `present`. This parameter is ignored, when `state` is set to `absent`. | Optional | 
| category_cardinality | The category cardinality. This parameter is ignored, when updating existing category. Possible values are: multiple, single. Default is multiple. | Optional | 
| new_category_name | The new name for an existing category. This value is used while updating an existing category. | Optional | 
| state | The state of category. If set to `present` and category does not exists, then category is created. If set to `present` and category exists, then category is updated. If set to `absent` and category exists, then category is deleted. If set to `absent` and category does not exists, no action is taken. Process of updating category only allows name, description change. Possible values are: present, absent. Default is present. | Optional | 
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareCategory.category_results | unknown | dictionary of category metadata | 




### vmware-category-info
***
Gather info about VMware tag categories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_category_info_module.html


#### Base Command

`vmware-category-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareCategoryInfo.tag_category_info | unknown | metadata of tag categories | 




### vmware-cfg-backup
***
Backup / Restore / Reset ESXi host configuration
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_cfg_backup_module.html


#### Base Command

`vmware-cfg-backup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | Name of ESXi server. This is required only if authentication against a vCenter is done. | Optional | 
| dest | The destination where the ESXi configuration bundle will be saved. The `dest` can be a folder or a file. If `dest` is a folder, the backup file will be saved in the folder with the default filename generated from the ESXi server. If `dest` is a file, the backup file will be saved with that filename. The file extension will always be .tgz. | Optional | 
| src | The file containing the ESXi configuration that will be restored. | Optional | 
| state | If `saved`, the .tgz backup bundle will be saved in `dest`. If `absent`, the host configuration will be reset to default values. If `loaded`, the backup file in `src` will be loaded to the ESXi host rewriting the hosts settings. Possible values are: saved, absent, loaded. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareCfgBackup.dest_file | string | The full path of where the file holding the ESXi configurations was stored | 


#### Command Example
```!vmware-cfg-backup state="saved" dest="/tmp/" esxi_hostname="esxi01"```

#### Context Example
```json
{
    "VMware": {
        "VmwareCfgBackup": [
            {
                "changed": true,
                "dest_file": "/tmp/configBundle-esxi01.tgz",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * dest_file: /tmp/configBundle-esxi01.tgz


### vmware-cluster
***
Manage VMware vSphere clusters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_cluster_module.html


#### Base Command

`vmware-cluster`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster to be managed. | Required | 
| datacenter | The name of the datacenter. | Required | 
| ignore_drs | If set to `yes`, DRS will not be configured; all explicit and default DRS related configurations will be ignored. Default is no. | Optional | 
| ignore_ha | If set to `yes`, HA will not be configured; all explicit and default HA related configurations will be ignored. Default is no. | Optional | 
| ignore_vsan | If set to `yes`, VSAN will not be configured; all explicit and default VSAN related configurations will be ignored. Default is no. | Optional | 
| enable_drs | If set to `yes`, will enable DRS when the cluster is created. Use `enable_drs` of `vmware_cluster_drs` instead. Deprecated option, will be removed in version 2.12. Default is no. | Optional | 
| drs_enable_vm_behavior_overrides | Determines whether DRS Behavior overrides for individual virtual machines are enabled. If set to `True`, overrides `drs_default_vm_behavior`. Use `drs_enable_vm_behavior_overrides` of `vmware_cluster_drs` instead. Deprecated option, will be removed in version 2.12. Possible values are: Yes, No. Default is Yes. | Optional | 
| drs_default_vm_behavior | Specifies the cluster-wide default DRS behavior for virtual machines. If set to `partiallyAutomated`, then vCenter generate recommendations for virtual machine migration and for the placement with a host. vCenter automatically implement placement at power on. If set to `manual`, then vCenter generate recommendations for virtual machine migration and for the placement with a host. vCenter should not implement the recommendations automatically. If set to `fullyAutomated`, then vCenter should automate both the migration of virtual machines and their placement with a host at power on. Use `drs_default_vm_behavior` of `vmware_cluster_drs` instead. Deprecated option, will be removed in version 2.12. Possible values are: fullyAutomated, manual, partiallyAutomated. Default is fullyAutomated. | Optional | 
| drs_vmotion_rate | Threshold for generated ClusterRecommendations. Use `drs_vmotion_rate` of `vmware_cluster_drs` instead. Deprecated option, will be removed in version 2.12. Possible values are: 1, 2, 3, 4, 5. Default is 3. | Optional | 
| enable_ha | If set to `yes` will enable HA when the cluster is created. Use `enable_ha` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Default is no. | Optional | 
| ha_host_monitoring | Indicates whether HA restarts virtual machines after a host fails. If set to `enabled`, HA restarts virtual machines after a host fails. If set to `disabled`, HA does not restart virtual machines after a host fails. If `enable_ha` is set to `no`, then this value is ignored. Use `ha_host_monitoring` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Possible values are: enabled, disabled. Default is enabled. | Optional | 
| ha_vm_monitoring | Indicates the state of virtual machine health monitoring service. If set to `vmAndAppMonitoring`, HA response to both virtual machine and application heartbeat failure. If set to `vmMonitoringDisabled`, virtual machine health monitoring is disabled. If set to `vmMonitoringOnly`, HA response to virtual machine heartbeat failure. If `enable_ha` is set to `no`, then this value is ignored. Use `ha_vm_monitoring` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Possible values are: vmAndAppMonitoring, vmMonitoringOnly, vmMonitoringDisabled. Default is vmMonitoringDisabled. | Optional | 
| ha_failover_level | Number of host failures that should be tolerated, still guaranteeing sufficient resources to restart virtual machines on available hosts. Accepts integer values only. Use `slot_based_admission_control`, `reservation_based_admission_control` or `failover_host_admission_control` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Default is 2. | Optional | 
| ha_admission_control_enabled | Determines if strict admission control is enabled. It is recommended to set this parameter to `True`, please refer documentation for more details. Use `slot_based_admission_control`, `reservation_based_admission_control` or `failover_host_admission_control` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Possible values are: Yes, No. Default is Yes. | Optional | 
| ha_vm_failure_interval | The number of seconds after which virtual machine is declared as failed if no heartbeat has been received. This setting is only valid if `ha_vm_monitoring` is set to, either `vmAndAppMonitoring` or `vmMonitoringOnly`. Unit is seconds. Use `ha_vm_failure_interval` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Default is 30. | Optional | 
| ha_vm_min_up_time | The number of seconds for the virtual machine's heartbeats to stabilize after the virtual machine has been powered on. This setting is only valid if `ha_vm_monitoring` is set to, either `vmAndAppMonitoring` or `vmMonitoringOnly`. Unit is seconds. Use `ha_vm_min_up_time` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Default is 120. | Optional | 
| ha_vm_max_failures | Maximum number of failures and automated resets allowed during the time that `ha_vm_max_failure_window` specifies. This setting is only valid if `ha_vm_monitoring` is set to, either `vmAndAppMonitoring` or `vmMonitoringOnly`. Use `ha_vm_max_failures` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Default is 3. | Optional | 
| ha_vm_max_failure_window | The number of seconds for the window during which up to `ha_vm_max_failures` resets can occur before automated responses stop. This setting is only valid if `ha_vm_monitoring` is set to, either `vmAndAppMonitoring` or `vmMonitoringOnly`. Unit is seconds. Default specifies no failure window. Use `ha_vm_max_failure_window` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Default is -1. | Optional | 
| ha_restart_priority | Determines the preference that HA gives to a virtual machine if sufficient capacity is not available to power on all failed virtual machines. This setting is only valid if `ha_vm_monitoring` is set to, either `vmAndAppMonitoring` or `vmMonitoringOnly`. If set to `disabled`, then HA is disabled for this virtual machine. If set to `high`, then virtual machine with this priority have a higher chance of powering on after a failure, when there is insufficient capacity on hosts to meet all virtual machine needs. If set to `medium`, then virtual machine with this priority have an intermediate chance of powering on after a failure, when there is insufficient capacity on hosts to meet all virtual machine needs. If set to `low`, then virtual machine with this priority have a lower chance of powering on after a failure, when there is insufficient capacity on hosts to meet all virtual machine needs. Use `ha_restart_priority` of `vmware_cluster_ha` instead. Deprecated option, will be removed in version 2.12. Possible values are: disabled, high, low, medium. Default is medium. | Optional | 
| enable_vsan | If set to `yes` will enable vSAN when the cluster is created. Use `enable_vsan` of `vmware_cluster_vsan` instead. Deprecated option, will be removed in version 2.12. Default is no. | Optional | 
| vsan_auto_claim_storage | Determines whether the VSAN service is configured to automatically claim local storage on VSAN-enabled hosts in the cluster. Use `vsan_auto_claim_storage` of `vmware_cluster_vsan` instead. Deprecated option, will be removed in version 2.12. Possible values are: Yes, No. Default is No. | Optional | 
| state | Create `present` or remove `absent` a VMware vSphere cluster. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-cluster datacenter="DC1" cluster_name="cluster" enable_ha="False" enable_drs="False" enable_vsan="False" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareCluster": [
            {
                "changed": false,
                "result": null,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * result: None


### vmware-cluster-drs
***
Manage Distributed Resource Scheduler (DRS) on VMware vSphere clusters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_cluster_drs_module.html


#### Base Command

`vmware-cluster-drs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster to be managed. | Required | 
| datacenter | The name of the datacenter. | Required | 
| enable_drs | Whether to enable DRS. Default is no. | Optional | 
| drs_enable_vm_behavior_overrides | Whether DRS Behavior overrides for individual virtual machines are enabled. If set to `True`, overrides `drs_default_vm_behavior`. Possible values are: Yes, No. Default is Yes. | Optional | 
| drs_default_vm_behavior | Specifies the cluster-wide default DRS behavior for virtual machines. If set to `partiallyAutomated`, vCenter generates recommendations for virtual machine migration and for the placement with a host, then automatically implements placement recommendations at power on. If set to `manual`, then vCenter generates recommendations for virtual machine migration and for the placement with a host, but does not implement the recommendations automatically. If set to `fullyAutomated`, then vCenter automates both the migration of virtual machines and their placement with a host at power on. Possible values are: fullyAutomated, manual, partiallyAutomated. Default is fullyAutomated. | Optional | 
| drs_vmotion_rate | Threshold for generated ClusterRecommendations. Possible values are: 1, 2, 3, 4, 5. Default is 3. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-cluster-drs datacenter="DC1" cluster_name="cluster" enable_drs="False" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareClusterDrs": [
            {
                "changed": false,
                "result": null,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * result: None


### vmware-cluster-ha
***
Manage High Availability (HA) on VMware vSphere clusters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_cluster_ha_module.html


#### Base Command

`vmware-cluster-ha`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster to be managed. | Required | 
| datacenter | The name of the datacenter. | Required | 
| enable_ha | Whether to enable HA. Default is no. | Optional | 
| ha_host_monitoring | Whether HA restarts virtual machines after a host fails. If set to `enabled`, HA restarts virtual machines after a host fails. If set to `disabled`, HA does not restart virtual machines after a host fails. If `enable_ha` is set to `no`, then this value is ignored. Possible values are: enabled, disabled. Default is enabled. | Optional | 
| ha_vm_monitoring | State of virtual machine health monitoring service. If set to `vmAndAppMonitoring`, HA response to both virtual machine and application heartbeat failure. If set to `vmMonitoringDisabled`, virtual machine health monitoring is disabled. If set to `vmMonitoringOnly`, HA response to virtual machine heartbeat failure. If `enable_ha` is set to `no`, then this value is ignored. Possible values are: vmAndAppMonitoring, vmMonitoringOnly, vmMonitoringDisabled. Default is vmMonitoringDisabled. | Optional | 
| host_isolation_response | Indicates whether or VMs should be powered off if a host determines that it is isolated from the rest of the compute resource. If set to `none`, do not power off VMs in the event of a host network isolation. If set to `powerOff`, power off VMs in the event of a host network isolation. If set to `shutdown`, shut down VMs guest operating system in the event of a host network isolation. Possible values are: none, powerOff, shutdown. Default is none. | Optional | 
| slot_based_admission_control | Configure slot based admission control policy. `slot_based_admission_control`, `reservation_based_admission_control` and `failover_host_admission_control` are mutually exclusive. | Optional | 
| reservation_based_admission_control | Configure reservation based admission control policy. `slot_based_admission_control`, `reservation_based_admission_control` and `failover_host_admission_control` are mutually exclusive. | Optional | 
| failover_host_admission_control | Configure dedicated failover hosts. `slot_based_admission_control`, `reservation_based_admission_control` and `failover_host_admission_control` are mutually exclusive. | Optional | 
| ha_vm_failure_interval | The number of seconds after which virtual machine is declared as failed if no heartbeat has been received. This setting is only valid if `ha_vm_monitoring` is set to, either `vmAndAppMonitoring` or `vmMonitoringOnly`. Unit is seconds. Default is 30. | Optional | 
| ha_vm_min_up_time | The number of seconds for the virtual machine's heartbeats to stabilize after the virtual machine has been powered on. Valid only when `ha_vm_monitoring` is set to either `vmAndAppMonitoring` or `vmMonitoringOnly`. Unit is seconds. Default is 120. | Optional | 
| ha_vm_max_failures | Maximum number of failures and automated resets allowed during the time that `ha_vm_max_failure_window` specifies. Valid only when `ha_vm_monitoring` is set to either `vmAndAppMonitoring` or `vmMonitoringOnly`. Default is 3. | Optional | 
| ha_vm_max_failure_window | The number of seconds for the window during which up to `ha_vm_max_failures` resets can occur before automated responses stop. Valid only when `ha_vm_monitoring` is set to either `vmAndAppMonitoring` or `vmMonitoringOnly`. Unit is seconds. Default specifies no failure window. Default is -1. | Optional | 
| ha_restart_priority | Priority HA gives to a virtual machine if sufficient capacity is not available to power on all failed virtual machines. Valid only if `ha_vm_monitoring` is set to either `vmAndAppMonitoring` or `vmMonitoringOnly`. If set to `disabled`, then HA is disabled for this virtual machine. If set to `high`, then virtual machine with this priority have a higher chance of powering on after a failure, when there is insufficient capacity on hosts to meet all virtual machine needs. If set to `medium`, then virtual machine with this priority have an intermediate chance of powering on after a failure, when there is insufficient capacity on hosts to meet all virtual machine needs. If set to `low`, then virtual machine with this priority have a lower chance of powering on after a failure, when there is insufficient capacity on hosts to meet all virtual machine needs. Possible values are: disabled, high, low, medium. Default is medium. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-cluster-ha datacenter="DC1" cluster_name="cluster" enable_ha="False" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareClusterHa": [
            {
                "changed": false,
                "result": null,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * result: None


### vmware-cluster-info
***
Gather info about clusters available in given vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_cluster_info_module.html


#### Base Command

`vmware-cluster-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | Datacenter to search for cluster/s. This parameter is required, if `cluster_name` is not supplied. | Optional | 
| cluster_name | Name of the cluster. If set, information of this cluster will be returned. This parameter is required, if `datacenter` is not supplied. | Optional | 
| show_tag | Tags related to cluster are shown if set to `True`. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareClusterInfo.clusters | unknown | metadata about the available clusters | 


#### Command Example
```!vmware-cluster-info datacenter="DC1" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareClusterInfo": [
            {
                "changed": false,
                "clusters": {
                    "cluster": {
                        "datacenter": "DC1",
                        "drs_default_vm_behavior": "fullyAutomated",
                        "drs_enable_vm_behavior_overrides": true,
                        "drs_vmotion_rate": 3,
                        "enable_ha": false,
                        "enabled_drs": false,
                        "enabled_vsan": false,
                        "ha_admission_control_enabled": true,
                        "ha_failover_level": 2,
                        "ha_host_monitoring": "enabled",
                        "ha_restart_priority": [
                            "medium"
                        ],
                        "ha_vm_failure_interval": [
                            30
                        ],
                        "ha_vm_max_failure_window": [
                            -1
                        ],
                        "ha_vm_max_failures": [
                            3
                        ],
                        "ha_vm_min_up_time": [
                            120
                        ],
                        "ha_vm_monitoring": "vmMonitoringDisabled",
                        "ha_vm_tools_monitoring": [
                            "vmMonitoringDisabled"
                        ],
                        "hosts": [
                            {
                                "folder": "/DC1/host/cluster",
                                "name": "esxi01"
                            }
                        ],
                        "moid": "domain-c7",
                        "resource_summary": {
                            "cpuCapacityMHz": 5330,
                            "cpuUsedMHz": 32,
                            "memCapacityMB": 6143,
                            "memUsedMB": 1487,
                            "pMemAvailableMB": null,
                            "pMemCapacityMB": null,
                            "storageCapacityMB": 7936,
                            "storageUsedMB": 1439
                        },
                        "tags": [],
                        "vsan_auto_claim_storage": false
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Clusters
>    * ### Cluster
>      * datacenter: DC1
>      * drs_default_vm_behavior: fullyAutomated
>      * drs_enable_vm_behavior_overrides: True
>      * drs_vmotion_rate: 3
>      * enable_ha: False
>      * enabled_drs: False
>      * enabled_vsan: False
>      * ha_admission_control_enabled: True
>      * ha_failover_level: 2
>      * ha_host_monitoring: enabled
>      * ha_vm_monitoring: vmMonitoringDisabled
>      * moid: domain-c7
>      * vsan_auto_claim_storage: False
>      * #### Ha_Restart_Priority
>        * 0: medium
>      * #### Ha_Vm_Failure_Interval
>        * 0: 30
>      * #### Ha_Vm_Max_Failure_Window
>        * 0: -1
>      * #### Ha_Vm_Max_Failures
>        * 0: 3
>      * #### Ha_Vm_Min_Up_Time
>        * 0: 120
>      * #### Ha_Vm_Tools_Monitoring
>        * 0: vmMonitoringDisabled
>      * #### Hosts
>      * #### esxi01
>        * folder: /DC1/host/cluster
>        * name: esxi01
>      * #### Resource_Summary
>        * cpuCapacityMHz: 5330
>        * cpuUsedMHz: 32
>        * memCapacityMB: 6143
>        * memUsedMB: 1487
>        * pMemAvailableMB: None
>        * pMemCapacityMB: None
>        * storageCapacityMB: 7936
>        * storageUsedMB: 1439
>      * #### Tags


### vmware-cluster-vsan
***
Manages virtual storage area network (vSAN) configuration on VMware vSphere clusters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_cluster_vsan_module.html


#### Base Command

`vmware-cluster-vsan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster to be managed. | Required | 
| datacenter | The name of the datacenter. | Required | 
| enable_vsan | Whether to enable vSAN. Default is no. | Optional | 
| vsan_auto_claim_storage | Whether the VSAN service is configured to automatically claim local storage on VSAN-enabled hosts in the cluster. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-content-deploy-template
***
Deploy Virtual Machine from template stored in content library.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_content_deploy_template_module.html


#### Base Command

`vmware-content-deploy-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The name of template from which VM to be deployed. | Required | 
| name | The name of the VM to be deployed. | Required | 
| datacenter | Name of the datacenter, where VM to be deployed. | Required | 
| datastore | Name of the datastore to store deployed VM and disk. | Required | 
| folder | Name of the folder in datacenter in which to place deployed VM. | Required | 
| host | Name of the ESX Host in datacenter in which to place deployed VM. | Required | 
| resource_pool | Name of the resourcepool in datacenter in which to place deployed VM. | Optional | 
| cluster | Name of the cluster in datacenter in which to place deployed VM. | Optional | 
| state | The state of Virtual Machine deployed from template in content library. If set to `present` and VM does not exists, then VM is created. If set to `present` and VM exists, no action is taken. If set to `poweredon` and VM does not exists, then VM is created with powered on state. If set to `poweredon` and VM exists, no action is taken. Possible values are: present, poweredon. Default is present. | Optional | 
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareContentDeployTemplate.vm_deploy_info | unknown | Virtual machine deployment message and vm_id | 




### vmware-content-library-info
***
Gather information about VMware Content Library
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_content_library_info_module.html


#### Base Command

`vmware-content-library-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| library_id | content library id for which details needs to be fetched. | Optional | 
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareContentLibraryInfo.content_lib_details | unknown | list of content library metadata | 
| VMware.VmwareContentLibraryInfo.content_libs | unknown | list of content libraries | 




### vmware-content-library-manager
***
Create, update and delete VMware content library
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_content_library_manager_module.html


#### Base Command

`vmware-content-library-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| library_name | The name of VMware content library to manage. | Required | 
| library_description | The content library description. This is required only if `state` is set to `present`. This parameter is ignored, when `state` is set to `absent`. Process of updating content library only allows description change. | Optional | 
| library_type | The content library type. This is required only if `state` is set to `present`. This parameter is ignored, when `state` is set to `absent`. Possible values are: local, subscribed. Default is local. | Optional | 
| datastore_name | Name of the datastore on which backing content library is created. This is required only if `state` is set to `present`. This parameter is ignored, when `state` is set to `absent`. Currently only datastore backing creation is supported. | Optional | 
| state | The state of content library. If set to `present` and library does not exists, then content library is created. If set to `present` and library exists, then content library is updated. If set to `absent` and library exists, then content library is deleted. If set to `absent` and library does not exists, no action is taken. Possible values are: present, absent. Default is present. | Optional | 
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareContentLibraryManager.content_library_info | unknown | library creation success and library_id | 




### vmware-datacenter
***
Manage VMware vSphere Datacenters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_datacenter_module.html


#### Base Command

`vmware-datacenter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter_name | The name of the datacenter the cluster will be created in. | Required | 
| state | If the datacenter should be present or absent. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-datacenter datacenter_name="DC1" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDatacenter": [
            {
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False


### vmware-datastore-cluster
***
Manage VMware vSphere datastore clusters
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_datastore_cluster_module.html


#### Base Command

`vmware-datastore-cluster`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter_name | The name of the datacenter. You must specify either a `datacenter_name` or a `folder`. Mutually exclusive with `folder` parameter. | Optional | 
| datastore_cluster_name | The name of the datastore cluster. | Required | 
| state | If the datastore cluster should be present or absent. Possible values are: present, absent. Default is present. | Optional | 
| folder | Destination folder, absolute path to place datastore cluster in. The folder should include the datacenter. This parameter is case sensitive. You must specify either a `folder` or a `datacenter_name`. Examples: folder: /datacenter1/datastore folder: datacenter1/datastore folder: /datacenter1/datastore/folder1 folder: datacenter1/datastore/folder1 folder: /folder1/datacenter1/datastore folder: folder1/datacenter1/datastore folder: /folder1/datacenter1/datastore/folder2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDatastoreCluster.result | string | information about datastore cluster operation | 


#### Command Example
```!vmware-datastore-cluster datacenter_name="DC1" datastore_cluster_name="Storage_Cluster" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDatastoreCluster": [
            {
                "changed": true,
                "result": "Datastore cluster 'Storage_Cluster' created successfully.",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * result: Datastore cluster 'Storage_Cluster' created successfully.


### vmware-datastore-info
***
Gather info about datastores available in given vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_datastore_info_module.html


#### Base Command

`vmware-datastore-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the datastore to match. If set, information of specific datastores are returned. | Optional | 
| datacenter | Datacenter to search for datastores. This parameter is required, if `cluster` is not supplied. | Optional | 
| cluster | Cluster to search for datastores. If set, information of datastores belonging this clusters will be returned. This parameter is required, if `datacenter` is not supplied. | Optional | 
| gather_nfs_mount_info | Gather mount information of NFS datastores. Disabled per default because this slows down the execution if you have a lot of datastores. Possible values are: Yes, No. Default is No. | Optional | 
| gather_vmfs_mount_info | Gather mount information of VMFS datastores. Disabled per default because this slows down the execution if you have a lot of datastores. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDatastoreInfo.datastores | unknown | metadata about the available datastores | 


#### Command Example
```!vmware-datastore-info datacenter_name="DC1" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDatastoreInfo": [
            {
                "changed": false,
                "datastores": [
                    {
                        "accessible": true,
                        "capacity": 8321499136,
                        "datastore_cluster": "N/A",
                        "freeSpace": 6812598272,
                        "maintenanceMode": "normal",
                        "multipleHostAccess": false,
                        "name": "datastore1",
                        "provisioned": 1508900864,
                        "type": "VMFS",
                        "uncommitted": 0,
                        "url": "ds:///vmfs/volumes/60eafb85-4b6578d0-c0a8-000c29d92704/"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Datastores
>  * ## Datastore1
>    * accessible: True
>    * capacity: 8321499136
>    * datastore_cluster: N/A
>    * freeSpace: 6812598272
>    * maintenanceMode: normal
>    * multipleHostAccess: False
>    * name: datastore1
>    * provisioned: 1508900864
>    * type: VMFS
>    * uncommitted: 0
>    * url: ds:///vmfs/volumes/60eafb85-4b6578d0-c0a8-000c29d92704/


### vmware-datastore-maintenancemode
***
Place a datastore into maintenance mode
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_datastore_maintenancemode_module.html


#### Base Command

`vmware-datastore-maintenancemode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datastore | Name of datastore to manage. If `datastore_cluster` or `cluster_name` are not set, this parameter is required. | Optional | 
| datastore_cluster | Name of the datastore cluster from all child datastores to be managed. If `datastore` or `cluster_name` are not set, this parameter is required. | Optional | 
| cluster_name | Name of the cluster where datastore is connected to. If multiple datastores are connected to the given cluster, then all datastores will be managed by `state`. If `datastore` or `datastore_cluster` are not set, this parameter is required. | Optional | 
| state | If set to `present`, then enter datastore into maintenance mode. If set to `present` and datastore is already in maintenance mode, then no action will be taken. If set to `absent` and datastore is in maintenance mode, then exit maintenance mode. If set to `absent` and datastore is not in maintenance mode, then no action will be taken. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDatastoreMaintenancemode.results | unknown | Action taken for datastore | 


#### Command Example
```!vmware-datastore-maintenancemode datastore="datastore1" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDatastoreMaintenancemode": [
            {
                "changed": true,
                "datastore_status": {
                    "datastore1": "Datastore 'datastore1' entered in maintenance mode."
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Datastore_Status
>    * datastore1: Datastore 'datastore1' entered in maintenance mode.


### vmware-dns-config
***
Manage VMware ESXi DNS Configuration
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dns_config_module.html


#### Base Command

`vmware-dns-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_hostname_to | The hostname that an ESXi host should be changed to. | Required | 
| domainname | The domain the ESXi host should be apart of. | Required | 
| dns_servers | The DNS servers that the host should be configured to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-dns-config change_hostname_to="esxi01" domainname="foo.org" dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDnsConfig": [
            {
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False

### vmware-drs-group
***
Creates vm/host group in a given cluster.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_drs_group_module.html


#### Base Command

`vmware-drs-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Cluster to create vm/host group. | Required | 
| datacenter | Datacenter to search for given cluster. If not set, we use first cluster we encounter with `cluster_name`. | Optional | 
| group_name | The name of the group to create or remove. | Required | 
| hosts | List of hosts to create in group. Required only if `vms` is not set. | Optional | 
| state | If set to `present` and the group doesn't exists then the group will be created. If set to `absent` and the group exists then the group will be deleted. Possible values are: present, absent. Default is present. | Required | 
| vms | List of vms to create in group. Required only if `hosts` is not set. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDrsGroup.drs_group_facts | unknown | Metadata about DRS group created | 


#### Command Example
```!vmware-drs-group cluster_name="cluster" datacenter_name="DC1" group_name="TEST_VM_01" vms="Sample_VM" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDrsGroup": [
            {
                "changed": false,
                "msg": "Updated vm group TEST_VM_01 successfully",
                "result": {
                    "cluster": [
                        {
                            "group_name": "TEST_VM_01",
                            "type": "vm",
                            "vms": [
                                "Sample_VM"
                            ]
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * msg: Updated vm group TEST_VM_01 successfully
>  * ## Result
>    * ### Cluster
>    * ### Test_Vm_01
>      * group_name: TEST_VM_01
>      * type: vm
>      * #### Vms
>        * 0: Sample_VM


### vmware-drs-group-info
***
Gathers info about DRS VM/Host groups on the given cluster
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_drs_group_info_module.html


#### Base Command

`vmware-drs-group-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Cluster to search for VM/Host groups. If set, information of DRS groups belonging this cluster will be returned. Not needed if `datacenter` is set. | Optional | 
| datacenter | Datacenter to search for DRS VM/Host groups. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDrsGroupInfo.drs_group_info | unknown | Metadata about DRS group from given cluster / datacenter | 


#### Command Example
```!vmware-drs-group-info datacenter="DC1" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDrsGroupInfo": [
            {
                "changed": false,
                "drs_group_info": {
                    "cluster": [
                        {
                            "group_name": "TEST_VM_01",
                            "type": "vm",
                            "vms": [
                                "Sample_VM"
                            ]
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Drs_Group_Info
>    * ### Cluster
>    * ### Test_Vm_01
>      * group_name: TEST_VM_01
>      * type: vm
>      * #### Vms
>        * 0: Sample_VM

### vmware-drs-rule-info
***
Gathers info about DRS rule on the given cluster
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_drs_rule_info_module.html


#### Base Command

`vmware-drs-rule-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. DRS information for the given cluster will be returned. This is required parameter if `datacenter` parameter is not provided. | Optional | 
| datacenter | Name of the datacenter. DRS information for all the clusters from the given datacenter will be returned. This is required parameter if `cluster_name` parameter is not provided. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDrsRuleInfo.drs_rule_info | unknown | metadata about DRS rule from given cluster / datacenter | 


#### Command Example
```!vmware-drs-rule-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDrsRuleInfo": [
            {
                "changed": false,
                "drs_rule_info": {
                    "cluster": []
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Drs_Rule_Info
>    * ### Cluster


### vmware-dvs-host
***
Add or remove a host from distributed virtual switch
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvs_host_module.html


#### Base Command

`vmware-dvs-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | The ESXi hostname. | Required | 
| switch_name | The name of the Distributed vSwitch. | Required | 
| vmnics | The ESXi hosts vmnics to use with the Distributed vSwitch. | Required | 
| state | If the host should be present or absent attached to the vSwitch. Possible values are: present, absent. Default is present. | Required | 
| vendor_specific_config | List of key,value dictionaries for the Vendor Specific Configuration. Element attributes are: - `key` (str): Key of setting. (default: None) - `value` (str): Value of setting. (default: None). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-dvs-portgroup
***
Create or remove a Distributed vSwitch portgroup.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvs_portgroup_module.html


#### Base Command

`vmware-dvs-portgroup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| portgroup_name | The name of the portgroup that is to be created or deleted. | Required | 
| switch_name | The name of the distributed vSwitch the port group should be created on. | Required | 
| vlan_id | The VLAN ID that should be configured with the portgroup, use 0 for no VLAN. If `vlan_trunk` is configured to be `true`, this can be a combination of multiple ranges and numbers, example: 1-200, 205, 400-4094. The valid `vlan_id` range is from 0 to 4094. Overlapping ranges are allowed. | Required | 
| num_ports | The number of ports the portgroup should contain. | Required | 
| portgroup_type | See VMware KB 1022312 regarding portgroup types. Possible values are: earlyBinding, lateBinding, ephemeral. | Required | 
| state | Determines if the portgroup should be present or not. Possible values are: present, absent. | Required | 
| vlan_trunk | Indicates whether this is a VLAN trunk or not. Possible values are: Yes, No. Default is No. | Optional | 
| network_policy | Dictionary which configures the different security values for portgroup. Valid attributes are: - `promiscuous` (bool): indicates whether promiscuous mode is allowed. (default: false) - `forged_transmits` (bool): indicates whether forged transmits are allowed. (default: false) - `mac_changes` (bool): indicates whether mac changes are allowed. (default: false). Default is {'promiscuous': False, 'forged_transmits': False, 'mac_changes': False}. | Optional | 
| teaming_policy | Dictionary which configures the different teaming values for portgroup. Valid attributes are: - `load_balance_policy` (string): Network adapter teaming policy. (default: loadbalance_srcid) - choices: [ loadbalance_ip, loadbalance_srcmac, loadbalance_srcid, loadbalance_loadbased, failover_explicit] - "loadbalance_loadbased" is available from version 2.6 and onwards - `inbound_policy` (bool): Indicate whether or not the teaming policy is applied to inbound frames as well. (default: False) - `notify_switches` (bool): Indicate whether or not to notify the physical switch if a link fails. (default: True) - `rolling_order` (bool): Indicate whether or not to use a rolling policy when restoring links. (default: False). Default is {'notify_switches': True, 'load_balance_policy': 'loadbalance_srcid', 'inbound_policy': False, 'rolling_order': False}. | Optional | 
| port_policy | Dictionary which configures the advanced policy settings for the portgroup. Valid attributes are: - `block_override` (bool): indicates if the block policy can be changed per port. (default: true) - `ipfix_override` (bool): indicates if the ipfix policy can be changed per port. (default: false) - `live_port_move` (bool): indicates if a live port can be moved in or out of the portgroup. (default: false) - `network_rp_override` (bool): indicates if the network resource pool can be changed per port. (default: false) - `port_config_reset_at_disconnect` (bool): indicates if the configuration of a port is reset automatically after disconnect. (default: true) - `security_override` (bool): indicates if the security policy can be changed per port. (default: false) - `shaping_override` (bool): indicates if the shaping policy can be changed per port. (default: false) - `traffic_filter_override` (bool): indicates if the traffic filter can be changed per port. (default: false) - `uplink_teaming_override` (bool): indicates if the uplink teaming policy can be changed per port. (default: false) - `vendor_config_override` (bool): indicates if the vendor config can be changed per port. (default: false) - `vlan_override` (bool): indicates if the vlan can be changed per port. (default: false). Default is {'traffic_filter_override': False, 'network_rp_override': False, 'live_port_move': False, 'security_override': False, 'vendor_config_override': False, 'port_config_reset_at_disconnect': True, 'uplink_teaming_override': False, 'block_override': True, 'shaping_override': False, 'vlan_override': False, 'ipfix_override': False}. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-dvs-portgroup portgroup_name="vlan-123-portrgoup" switch_name="dvSwitch" vlan_id="123" num_ports="120" portgroup_type="earlyBinding" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvsPortgroup": [
            {
                "changed": true,
                "result": "None",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * result: None

### vmware-dvs-portgroup-find
***
Find portgroup(s) in a VMware environment
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvs_portgroup_find_module.html


#### Base Command

`vmware-dvs-portgroup-find`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dvswitch | Name of a distributed vSwitch to look for. | Optional | 
| vlanid | VLAN id can be any number between 1 and 4094. This search criteria will looks into VLAN ranges to find possible matches. | Optional | 
| name | string to check inside the name of the portgroup. Basic containment check using python `in` operation. | Optional | 
| show_uplink | Show or hide uplink portgroups. Only relevant when `vlanid` is supplied. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvsPortgroupFind.dvs_portgroups | unknown | basic details of portgroups found | 


#### Command Example
```!vmware-dvs-portgroup-find dvswitch="dvSwitch" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvsPortgroupFind": [
            {
                "changed": false,
                "dvs_portgroups": [
                    {
                        "dvswitch": "dvSwitch",
                        "name": "vlan-123-portrgoup",
                        "pvlan": false,
                        "trunk": false,
                        "vlan_id": "123"
                    },
                    {
                        "dvswitch": "dvSwitch",
                        "name": "dvSwitch-DVUplinks-23",
                        "pvlan": false,
                        "trunk": true,
                        "vlan_id": "0-4094"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Dvs_Portgroups
>  * ## Vlan-123-Portrgoup
>    * dvswitch: dvSwitch
>    * name: vlan-123-portrgoup
>    * pvlan: False
>    * trunk: False
>    * vlan_id: 123
>  * ## Dvswitch-Dvuplinks-23
>    * dvswitch: dvSwitch
>    * name: dvSwitch-DVUplinks-23
>    * pvlan: False
>    * trunk: True
>    * vlan_id: 0-4094


### vmware-dvs-portgroup-info
***
Gathers info DVS portgroup configurations
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvs_portgroup_info_module.html


#### Base Command

`vmware-dvs-portgroup-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | Name of the datacenter. | Required | 
| dvswitch | Name of a dvswitch to look for. | Optional | 
| show_network_policy | Show or hide network policies of DVS portgroup. Possible values are: Yes, No. Default is Yes. | Optional | 
| show_port_policy | Show or hide port policies of DVS portgroup. Possible values are: Yes, No. Default is Yes. | Optional | 
| show_teaming_policy | Show or hide teaming policies of DVS portgroup. Possible values are: Yes, No. Default is Yes. | Optional | 
| show_vlan_info | Show or hide vlan information of the DVS portgroup. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvsPortgroupInfo.dvs_portgroup_info | unknown | metadata about DVS portgroup configuration | 


#### Command Example
```!vmware-dvs-portgroup-info datacenter="DC1"```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvsPortgroupInfo": [
            {
                "changed": false,
                "dvs_portgroup_info": {
                    "dvSwitch": [
                        {
                            "description": null,
                            "dvswitch_name": "dvSwitch",
                            "key": "dvportgroup-25",
                            "network_policy": {
                                "forged_transmits": false,
                                "mac_changes": false,
                                "promiscuous": false
                            },
                            "num_ports": 120,
                            "port_policy": {
                                "block_override": true,
                                "ipfix_override": false,
                                "live_port_move": false,
                                "network_rp_override": false,
                                "port_config_reset_at_disconnect": true,
                                "security_override": false,
                                "shaping_override": false,
                                "traffic_filter_override": false,
                                "uplink_teaming_override": false,
                                "vendor_config_override": false,
                                "vlan_override": false
                            },
                            "portgroup_name": "vlan-123-portrgoup",
                            "teaming_policy": {
                                "inbound_policy": false,
                                "notify_switches": true,
                                "policy": "loadbalance_srcid",
                                "rolling_order": false
                            },
                            "type": "earlyBinding",
                            "vlan_info": {}
                        },
                        {
                            "description": null,
                            "dvswitch_name": "dvSwitch",
                            "key": "dvportgroup-24",
                            "network_policy": {
                                "forged_transmits": true,
                                "mac_changes": false,
                                "promiscuous": false
                            },
                            "num_ports": 0,
                            "port_policy": {
                                "block_override": true,
                                "ipfix_override": false,
                                "live_port_move": false,
                                "network_rp_override": false,
                                "port_config_reset_at_disconnect": true,
                                "security_override": false,
                                "shaping_override": false,
                                "traffic_filter_override": false,
                                "uplink_teaming_override": false,
                                "vendor_config_override": false,
                                "vlan_override": false
                            },
                            "portgroup_name": "dvSwitch-DVUplinks-23",
                            "teaming_policy": {
                                "inbound_policy": true,
                                "notify_switches": true,
                                "policy": "loadbalance_srcid",
                                "rolling_order": false
                            },
                            "type": "earlyBinding",
                            "vlan_info": {}
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Dvs_Portgroup_Info
>    * ### Dvswitch
>    * ### Dvswitch
>      * description: None
>      * dvswitch_name: dvSwitch
>      * key: dvportgroup-25
>      * num_ports: 120
>      * portgroup_name: vlan-123-portrgoup
>      * type: earlyBinding
>      * #### Network_Policy
>        * forged_transmits: False
>        * mac_changes: False
>        * promiscuous: False
>      * #### Port_Policy
>        * block_override: True
>        * ipfix_override: False
>        * live_port_move: False
>        * network_rp_override: False
>        * port_config_reset_at_disconnect: True
>        * security_override: False
>        * shaping_override: False
>        * traffic_filter_override: False
>        * uplink_teaming_override: False
>        * vendor_config_override: False
>        * vlan_override: False
>      * #### Teaming_Policy
>        * inbound_policy: False
>        * notify_switches: True
>        * policy: loadbalance_srcid
>        * rolling_order: False
>      * #### Vlan_Info
>    * ### Dvswitch
>      * description: None
>      * dvswitch_name: dvSwitch
>      * key: dvportgroup-24
>      * num_ports: 0
>      * portgroup_name: dvSwitch-DVUplinks-23
>      * type: earlyBinding
>      * #### Network_Policy
>        * forged_transmits: True
>        * mac_changes: False
>        * promiscuous: False
>      * #### Port_Policy
>        * block_override: True
>        * ipfix_override: False
>        * live_port_move: False
>        * network_rp_override: False
>        * port_config_reset_at_disconnect: True
>        * security_override: False
>        * shaping_override: False
>        * traffic_filter_override: False
>        * uplink_teaming_override: False
>        * vendor_config_override: False
>        * vlan_override: False
>      * #### Teaming_Policy
>        * inbound_policy: True
>        * notify_switches: True
>        * policy: loadbalance_srcid
>        * rolling_order: False
>      * #### Vlan_Info


### vmware-dvswitch
***
Create or remove a Distributed Switch
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvswitch_module.html


#### Base Command

`vmware-dvswitch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter_name | The name of the datacenter that will contain the Distributed Switch. This parameter is optional, if `folder` is provided. Mutually exclusive with `folder` parameter. | Optional | 
| switch_name | The name of the distribute vSwitch to create or remove. | Required | 
| switch_version | The version of the Distributed Switch to create. Can be 6.0.0, 5.5.0, 5.1.0, 5.0.0 with a vCenter running vSphere 6.0 and 6.5. Can be 6.6.0, 6.5.0, 6.0.0 with a vCenter running vSphere 6.7. The version must match the version of the ESXi hosts you want to connect. The version of the vCenter server is used if not specified. Required only if `state` is set to `present`. Possible values are: 5.0.0, 5.1.0, 5.5.0, 6.0.0, 6.5.0, 6.6.0. | Optional | 
| mtu | The switch maximum transmission unit. Required parameter for `state` both `present` and `absent`, before Ansible 2.6 version. Required only if `state` is set to `present`, for Ansible 2.6 and onwards. Accepts value between 1280 to 9000 (both inclusive). Default is 1500. | Optional | 
| multicast_filtering_mode | The multicast filtering mode. `basic` mode: multicast traffic for virtual machines is forwarded according to the destination MAC address of the multicast group. `snooping` mode: the Distributed Switch provides IGMP and MLD snooping according to RFC 4541. Possible values are: basic, snooping. Default is basic. | Optional | 
| uplink_quantity | Quantity of uplink per ESXi host added to the Distributed Switch. The uplink quantity can be increased or decreased, but a decrease will only be successfull if the uplink isn't used by a portgroup. Required parameter for `state` both `present` and `absent`, before Ansible 2.6 version. Required only if `state` is set to `present`, for Ansible 2.6 and onwards. | Optional | 
| uplink_prefix | The prefix used for the naming of the uplinks. Only valid if the Distributed Switch will be created. Not used if the Distributed Switch is already present. Uplinks are created as Uplink 1, Uplink 2, etc. pp. by default. Default is Uplink . | Optional | 
| discovery_proto | Link discovery protocol between Cisco and Link Layer discovery. Required parameter for `state` both `present` and `absent`, before Ansible 2.6 version. Required only if `state` is set to `present`, for Ansible 2.6 and onwards. `cdp`: Use Cisco Discovery Protocol (CDP). `lldp`: Use Link Layer Discovery Protocol (LLDP). `disabled`: Do not use a discovery protocol. Possible values are: cdp, lldp, disabled. Default is cdp. | Optional | 
| discovery_operation | Select the discovery operation. Required parameter for `state` both `present` and `absent`, before Ansible 2.6 version. Required only if `state` is set to `present`, for Ansible 2.6 and onwards. Possible values are: both, advertise, listen. Default is listen. | Optional | 
| contact | Dictionary which configures administrator contact name and description for the Distributed Switch. Valid attributes are: - `name` (str): Administrator name. - `description` (str): Description or other details. | Optional | 
| description | Description of the Distributed Switch. | Optional | 
| health_check | Dictionary which configures Health Check for the Distributed Switch. Valid attributes are: - `vlan_mtu` (bool): VLAN and MTU health check. (default: False) - `teaming_failover` (bool): Teaming and failover health check. (default: False) - `vlan_mtu_interval` (int): VLAN and MTU health check interval (minutes). (default: 0) - The default for `vlan_mtu_interval` is 1 in the vSphere Client if the VLAN and MTU health check is enabled. - `teaming_failover_interval` (int): Teaming and failover health check interval (minutes). (default: 0) - The default for `teaming_failover_interval` is 1 in the vSphere Client if the Teaming and failover health check is enabled. Default is {'vlan_mtu': False, 'teaming_failover': False, 'vlan_mtu_interval': 0, 'teaming_failover_interval': 0}. | Optional | 
| state | If set to `present` and the Distributed Switch doesn't exists then the Distributed Switch will be created. If set to `absent` and the Distributed Switch exists then the Distributed Switch will be deleted. Possible values are: present, absent. Default is present. | Optional | 
| folder | Destination folder, absolute path to place dvswitch in. The folder should include the datacenter. This parameter is case sensitive. This parameter is optional, if `datacenter` is provided. Examples: folder: /datacenter1/network folder: datacenter1/network folder: /datacenter1/network/folder1 folder: datacenter1/network/folder1 folder: /folder1/datacenter1/network folder: folder1/datacenter1/network folder: /folder1/datacenter1/network/folder2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvswitch.result | string | information about performed operation | 


#### Command Example
```!vmware-dvswitch datacenter="DC1" switch_name="dvSwitch" version="6.0.0" mtu="9000" uplink_quantity="2" discovery_protocol="lldp" discovery_operation="both" state="present"  datacenter_name="DC1"```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvswitch": [
            {
                "changed": true,
                "result": "DVS created",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * result: DVS created

### vmware-dvswitch-lacp
***
Manage LACP configuration on a Distributed Switch
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvswitch_lacp_module.html


#### Base Command

`vmware-dvswitch-lacp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | The name of the Distributed Switch to manage. | Required | 
| support_mode | The LACP support mode. `basic`: One Link Aggregation Control Protocol group in the switch (singleLag). `enhanced`: Multiple Link Aggregation Control Protocol groups in the switch (multipleLag). Possible values are: basic, enhanced. Default is basic. | Optional | 
| link_aggregation_groups | Can only be used if `lacp_support` is set to `enhanced`. The following parameters are required: - `name` (string): Name of the LAG. - `uplink_number` (int): Number of uplinks. Can 1 to 30. - `mode` (string): The negotiating state of the uplinks/ports. - choices: [ active, passive ] - `load_balancing_mode` (string): Load balancing algorithm. - Valid attributes are: - srcTcpUdpPort: Source TCP/UDP port number. - srcDestIpTcpUdpPortVlan: Source and destination IP, source and destination TCP/UDP port number and VLAN. - srcIpVlan: Source IP and VLAN. - srcDestTcpUdpPort: Source and destination TCP/UDP port number. - srcMac: Source MAC address. - destIp: Destination IP. - destMac: Destination MAC address. - vlan: VLAN only. - srcDestIp: Source and Destination IP. - srcIpTcpUdpPortVlan: Source IP, TCP/UDP port number and VLAN. - srcDestIpTcpUdpPort: Source and destination IP and TCP/UDP port number. - srcDestMac: Source and destination MAC address. - destIpTcpUdpPort: Destination IP and TCP/UDP port number. - srcPortId: Source Virtual Port Id. - srcIp: Source IP. - srcIpTcpUdpPort: Source IP and TCP/UDP port number. - destIpTcpUdpPortVlan: Destination IP, TCP/UDP port number and VLAN. - destTcpUdpPort: Destination TCP/UDP port number. - destIpVlan: Destination IP and VLAN. - srcDestIpVlan: Source and destination IP and VLAN. - The default load balancing mode in the vSphere Client is srcDestIpTcpUdpPortVlan. Please see examples for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvswitchLacp.result | string | information about performed operation | 


#### Command Example
```!vmware-dvswitch-lacp switch="dvSwitch" support_mode="enhanced" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvswitchLacp": [
            {
                "changed": true,
                "dvswitch": "dvSwitch",
                "link_aggregation_groups": [],
                "result": "support mode changed",
                "status": "CHANGED",
                "support_mode": "enhanced",
                "support_mode_previous": "basic"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * dvswitch: dvSwitch
>  * result: support mode changed
>  * support_mode: enhanced
>  * support_mode_previous: basic
>  * ## Link_Aggregation_Groups

### vmware-dvswitch-nioc
***
Manage distributed switch Network IO Control
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvswitch_nioc_module.html


#### Base Command

`vmware-dvswitch-nioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | The name of the distributed switch. | Required | 
| version | Network IO control version. Possible values are: version2, version3. | Optional | 
| state | Enable or disable NIOC on the distributed switch. Possible values are: present, absent. Default is present. | Optional | 
| resources | List of dicts containing { name: Resource name is one of the following: "faultTolerance", "hbr", "iSCSI", "management", "nfs", "vdp", "virtualMachine", "vmotion", "vsan" limit: The maximum allowed usage for a traffic class belonging to this resource pool per host physical NIC. reservation: (Ignored if NIOC version is set to version2) Amount of bandwidth resource that is guaranteed available to the host infrastructure traffic class. If the utilization is less than the reservation, the extra bandwidth is used for other host infrastructure traffic class types. Reservation is not allowed to exceed the value of limit, if limit is set. Unit is Mbits/sec. shares_level: The allocation level ("low", "normal", "high", "custom"). The level is a simplified view of shares. Levels map to a pre-determined set of numeric values for shares. shares: Ignored unless shares_level is "custom".  The number of shares allocated. reservation: Ignored unless version is "version3". Amount of bandwidth resource that is guaranteed available to the host infrastructure traffic class. }. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvswitchNioc.dvswitch_nioc_status | string | result of the changes | 
| VMware.VmwareDvswitchNioc.resources_changed | unknown | list of resources which were changed | 


#### Command Example
```!vmware-dvswitch-nioc switch="dvSwitch" version="version3" resources="{{ [{'name': 'vmotion', 'limit': -1, 'reservation': 128, 'shares_level': 'normal'}, {'name': 'vsan', 'limit': -1, 'shares_level': 'custom', 'shares': 99, 'reservation': 256}] }}" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvswitchNioc": [
            {
                "changed": true,
                "dvswitch_nioc_status": "Enabled NIOC with version version3",
                "resources_changed": [
                    "vmotion",
                    "vsan"
                ],
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * dvswitch_nioc_status: Enabled NIOC with version version3
>  * ## Resources_Changed
>    * 0: vmotion
>    * 1: vsan

### vmware-dvswitch-pvlans
***
Manage Private VLAN configuration of a Distributed Switch
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvswitch_pvlans_module.html


#### Base Command

`vmware-dvswitch-pvlans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | The name of the Distributed Switch. | Required | 
| primary_pvlans | A list of VLAN IDs that should be configured as Primary PVLANs. If `primary_pvlans` isn't specified, all PVLANs will be deleted if present. Each member of the list requires primary_pvlan_id (int) set. The secondary promiscuous PVLAN will be created automatically. If `secondary_pvlans` isn't specified, the primary PVLANs and each secondary promiscuous PVLAN will be created. Please see examples for more information. | Optional | 
| secondary_pvlans | A list of VLAN IDs that should be configured as Secondary PVLANs. `primary_pvlans` need to be specified to create any Secondary PVLAN. If `primary_pvlans` isn't specified, all PVLANs will be deleted if present. Each member of the list requires primary_pvlan_id (int), secondary_pvlan_id (int), and pvlan_type (str) to be set. The type of the secondary PVLAN can be isolated or community. The secondary promiscuous PVLAN will be created automatically. Please see examples for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvswitchPvlans.result | string | information about performed operation | 




### vmware-dvswitch-uplink-pg
***
Manage uplink portproup configuration of a Distributed Switch
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_dvswitch_uplink_pg_module.html


#### Base Command

`vmware-dvswitch-uplink-pg`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | The name of the Distributed Switch. | Required | 
| name | The name of the uplink portgroup. The current name will be used if not specified. | Optional | 
| description | The description of the uplink portgroup. | Optional | 
| advanced | Dictionary which configures the advanced policy settings for the uplink portgroup. Valid attributes are: - `port_config_reset_at_disconnect` (bool): indicates if the configuration of a port is reset automatically after disconnect. (default: true) - `block_override` (bool): indicates if the block policy can be changed per port. (default: true) - `netflow_override` (bool): indicates if the NetFlow policy can be changed per port. (default: false) - `traffic_filter_override` (bool): indicates if the traffic filter can be changed per port. (default: false) - `vendor_config_override` (bool): indicates if the vendor config can be changed per port. (default: false) - `vlan_override` (bool): indicates if the vlan can be changed per port. (default: false). Default is {'port_config_reset_at_disconnect': True, 'block_override': True, 'vendor_config_override': False, 'vlan_override': False, 'netflow_override': False, 'traffic_filter_override': False}. | Optional | 
| vlan_trunk_range | The VLAN trunk range that should be configured with the uplink portgroup. This can be a combination of multiple ranges and numbers, example: [ 2-3967, 4049-4092 ]. Default is ['0-4094']. | Optional | 
| lacp | Dictionary which configures the LACP settings for the uplink portgroup. The options are only used if the LACP support mode is set to 'basic'. The following parameters are required: - `status` (str): Indicates if LACP is enabled. (default: disabled) - `mode` (str): The negotiating state of the uplinks/ports. (default: passive). Default is {'status': 'disabled', 'mode': 'passive'}. | Optional | 
| netflow_enabled | Indicates if NetFlow is enabled on the uplink portgroup. Possible values are: Yes, No. Default is No. | Optional | 
| block_all_ports | Indicates if all ports are blocked on the uplink portgroup. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareDvswitchUplinkPg.result | string | information about performed operation | 


#### Command Example
```!vmware-dvswitch-uplink-pg switch="dvSwitch" name="dvSwitch-DVUplinks" advanced="{{ {'port_config_reset_at_disconnect': True, 'block_override': True, 'vendor_config_override': False, 'vlan_override': False, 'netflow_override': False, 'traffic_filter_override': False} }}" vlan_trunk_range="0-4094" netflow_enabled="False" block_all_ports="False" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareDvswitchUplinkPg": [
            {
                "adv_block_ports": true,
                "adv_netflow": false,
                "adv_reset_at_disconnect": true,
                "adv_traffic_filtering": false,
                "adv_vendor_conf": false,
                "adv_vlan": false,
                "block_all_ports": false,
                "changed": true,
                "description": null,
                "dvswitch": "dvSwitch",
                "name": "dvSwitch-DVUplinks",
                "name_previous": "dvSwitch-DVUplinks-23",
                "netflow_enabled": false,
                "result": "name changed",
                "status": "CHANGED",
                "vlan_trunk_range": [
                    "0-4094"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * adv_block_ports: True
>  * adv_netflow: False
>  * adv_reset_at_disconnect: True
>  * adv_traffic_filtering: False
>  * adv_vendor_conf: False
>  * adv_vlan: False
>  * block_all_ports: False
>  * changed: True
>  * description: None
>  * dvswitch: dvSwitch
>  * name: dvSwitch-DVUplinks
>  * name_previous: dvSwitch-DVUplinks-23
>  * netflow_enabled: False
>  * result: name changed
>  * ## Vlan_Trunk_Range
>    * 0: 0-4094

### vmware-evc-mode
***
Enable/Disable EVC mode on vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_evc_mode_module.html


#### Base Command

`vmware-evc-mode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter_name | The name of the datacenter the cluster belongs to that you want to enable or disable EVC mode on. | Required | 
| cluster_name | The name of the cluster to enable or disable EVC mode on. | Required | 
| evc_mode | Required for `state=present`. The EVC mode to enable or disable on the cluster. (intel-broadwell, intel-nehalem, intel-merom, etc.). | Required | 
| state | Add or remove EVC mode. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareEvcMode.result | string | information about performed operation | 


#### Command Example
```!vmware-evc-mode datacenter_name="DC1" cluster_name="cluster" evc_mode="intel-merom" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareEvcMode": [
            {
                "changed": false,
                "msg": "EVC Mode is already set to 'intel-merom' on 'cluster'.",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * msg: EVC Mode is already set to 'intel-merom' on 'cluster'.



### vmware-folder-info
***
Provides information about folders in a datacenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_folder_info_module.html


#### Base Command

`vmware-folder-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | Name of the datacenter. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareFolderInfo.folder_info | string | dict about folders | 


#### Command Example
```!vmware-folder-info datacenter="DC1" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareFolderInfo": [
            {
                "changed": false,
                "flat_folder_info": [
                    {
                        "moid": "group-v3",
                        "path": "/DC1/vm"
                    }
                ],
                "folder_info": {
                    "datastoreFolders": {
                        "moid": "group-s5",
                        "path": "/DC1/datastore",
                        "subfolders": {
                            "Storage_Cluster": {
                                "moid": "group-p13",
                                "path": "/DC1/datastore/Storage_Cluster",
                                "subfolders": {}
                            }
                        }
                    },
                    "hostFolders": {
                        "moid": "group-h4",
                        "path": "/DC1/host",
                        "subfolders": {}
                    },
                    "networkFolders": {
                        "moid": "group-n6",
                        "path": "/DC1/network",
                        "subfolders": {}
                    },
                    "vmFolders": {
                        "moid": "group-v3",
                        "path": "/DC1/vm",
                        "subfolders": {
                            "Discovered virtual machine": {
                                "moid": "group-v9",
                                "path": "/DC1/vm/Discovered virtual machine",
                                "subfolders": {}
                            }
                        }
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Flat_Folder_Info
>  * ## Group-V3
>    * moid: group-v3
>    * path: /DC1/vm
>  * ## Folder_Info
>    * ### Datastorefolders
>      * moid: group-s5
>      * path: /DC1/datastore
>      * #### Subfolders
>        * ##### Storage_Cluster
>          * moid: group-p13
>          * path: /DC1/datastore/Storage_Cluster
>          * ###### Subfolders
>    * ### Hostfolders
>      * moid: group-h4
>      * path: /DC1/host
>      * #### Subfolders
>    * ### Networkfolders
>      * moid: group-n6
>      * path: /DC1/network
>      * #### Subfolders
>    * ### Vmfolders
>      * moid: group-v3
>      * path: /DC1/vm
>      * #### Subfolders
>        * ##### Discovered Virtual Machine
>          * moid: group-v9
>          * path: /DC1/vm/Discovered virtual machine
>          * ###### Subfolders


### vmware-guest
***
Manages virtual machines in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_module.html


#### Base Command

`vmware-guest`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Specify the state the virtual machine should be in. If `state` is set to `present` and virtual machine exists, ensure the virtual machine configurations conforms to task arguments. If `state` is set to `absent` and virtual machine exists, then the specified virtual machine is removed with its associated components. If `state` is set to one of the following `poweredon`, `poweredoff`, `present`, `restarted`, `suspended` and virtual machine does not exists, then virtual machine is deployed with given parameters. If `state` is set to `poweredon` and virtual machine exists with powerstate other than powered on, then the specified virtual machine is powered on. If `state` is set to `poweredoff` and virtual machine exists with powerstate other than powered off, then the specified virtual machine is powered off. If `state` is set to `restarted` and virtual machine exists, then the virtual machine is restarted. If `state` is set to `suspended` and virtual machine exists, then the virtual machine is set to suspended mode. If `state` is set to `shutdownguest` and virtual machine exists, then the virtual machine is shutdown. If `state` is set to `rebootguest` and virtual machine exists, then the virtual machine is rebooted. Possible values are: present, absent, poweredon, poweredoff, restarted, suspended, shutdownguest, rebootguest. Default is present. | Optional | 
| name | Name of the virtual machine to work with. Virtual machine names in vCenter are not necessarily unique, which may be problematic, see `name_match`. If multiple virtual machines with same name exists, then `folder` is required parameter to identify uniqueness of the virtual machine. This parameter is required, if `state` is set to `poweredon`, `poweredoff`, `present`, `restarted`, `suspended` and virtual machine does not exists. This parameter is case sensitive. | Required | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| uuid | UUID of the virtual machine to manage if known, this is VMware's unique identifier. This is required if `name` is not supplied. If virtual machine does not exists, then this parameter is ignored. Please note that a supplied UUID will be ignored on virtual machine creation, as VMware creates the UUID internally. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| template | Template or existing virtual machine used to create new virtual machine. If this value is not set, virtual machine is created without using a template. If the virtual machine already exists, this parameter will be ignored. This parameter is case sensitive. You can also specify template or VM UUID for identifying source. version_added 2.8. Use `hw_product_uuid` from `vmware_guest_facts` as UUID value. From version 2.8 onwards, absolute path to virtual machine or template can be used. | Optional | 
| is_template | Flag the instance as a template. This will mark the given virtual machine as template. Default is no. | Optional | 
| folder | Destination folder, absolute path to find an existing guest or create the new guest. The folder should include the datacenter. ESX's datacenter is ha-datacenter. This parameter is case sensitive. This parameter is required, while deploying new virtual machine. version_added 2.5. If multiple machines are found with same name, this parameter is used to identify uniqueness of the virtual machine. version_added 2.5 Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| hardware | Manage virtual machine's hardware attributes. All parameters case sensitive. Valid attributes are: - `hotadd_cpu` (boolean): Allow virtual CPUs to be added while the virtual machine is running. - `hotremove_cpu` (boolean): Allow virtual CPUs to be removed while the virtual machine is running. version_added: 2.5 - `hotadd_memory` (boolean): Allow memory to be added while the virtual machine is running. - `memory_mb` (integer): Amount of memory in MB. - `nested_virt` (bool): Enable nested virtualization. version_added: 2.5 - `num_cpus` (integer): Number of CPUs. - `num_cpu_cores_per_socket` (integer): Number of Cores Per Socket. `num_cpus` must be a multiple of `num_cpu_cores_per_socket`. For example to create a VM with 2 sockets of 4 cores, specify `num_cpus`: 8 and `num_cpu_cores_per_socket`: 4 - `scsi` (string): Valid values are `buslogic`, `lsilogic`, `lsilogicsas` and `paravirtual` (default). - `memory_reservation_lock` (boolean): If set true, memory resource reservation for the virtual machine will always be equal to the virtual machine's memory size. version_added: 2.5 - `max_connections` (integer): Maximum number of active remote display connections for the virtual machines. version_added: 2.5. - `mem_limit` (integer): The memory utilization of a virtual machine will not exceed this limit. Unit is MB. version_added: 2.5 - `mem_reservation` (integer): The amount of memory resource that is guaranteed available to the virtual machine. Unit is MB. `memory_reservation` is alias to this. version_added: 2.5 - `cpu_limit` (integer): The CPU utilization of a virtual machine will not exceed this limit. Unit is MHz. version_added: 2.5 - `cpu_reservation` (integer): The amount of CPU resource that is guaranteed available to the virtual machine. Unit is MHz. version_added: 2.5 - `version` (integer): The Virtual machine hardware versions. Default is 10 (ESXi 5.5 and onwards). Please check VMware documentation for correct virtual machine hardware version. Incorrect hardware version may lead to failure in deployment. If hardware version is already equal to the given version then no action is taken. version_added: 2.6 - `boot_firmware` (string): Choose which firmware should be used to boot the virtual machine. Allowed values are "bios" and "efi". version_added: 2.7 - `virt_based_security` (bool): Enable Virtualization Based Security feature for Windows 10. (Support from Virtual machine hardware version 14, Guest OS Windows 10 64 bit, Windows Server 2016). | Optional | 
| guest_id | Set the guest ID. This parameter is case sensitive. Examples: virtual machine with RHEL7 64 bit, will be 'rhel7_64Guest' virtual machine with CentOS 64 bit, will be 'centos64Guest' virtual machine with Ubuntu 64 bit, will be 'ubuntu64Guest' This field is required when creating a virtual machine, not required when creating from the template. Valid values are referenced here: `https://code.vmware.com/apis/358/doc/vim.vm.GuestOsDescriptor.GuestOsIdentifier.html`. | Optional | 
| disk | A list of disks to add. This parameter is case sensitive. Shrinking disks is not supported. Removing existing disks of the virtual machine is not supported. Valid attributes are: - `size_[tb,gb,mb,kb]` (integer): Disk storage size in specified unit. - `type` (string): Valid values are: - `thin` thin disk - `eagerzeroedthick` eagerzeroedthick disk, added in version 2.5 Default: `None` thick disk, no eagerzero. - `datastore` (string): The name of datastore which will be used for the disk. If `autoselect_datastore` is set to True, then will select the less used datastore whose name contains this "disk.datastore" string. - `filename` (string): Existing disk image to be used. Filename must already exist on the datastore. Specify filename string in `[datastore_name] path/to/file.vmdk` format. Added in version 2.8. - `autoselect_datastore` (bool): select the less used datastore. "disk.datastore" and "disk.autoselect_datastore" will not be used if `datastore` is specified outside this `disk` configuration. - `disk_mode` (string): Type of disk mode. Added in version 2.6 - Available options are : - `persistent`: Changes are immediately and permanently written to the virtual disk. This is default. - `independent_persistent`: Same as persistent, but not affected by snapshots. - `independent_nonpersistent`: Changes to virtual disk are made to a redo log and discarded at power off, but not affected by snapshots. | Optional | 
| cdrom | A CD-ROM configuration for the virtual machine. Or a list of CD-ROMs configuration for the virtual machine. Added in version 2.9. Parameters `controller_type`, `controller_number`, `unit_number`, `state` are added for a list of CD-ROMs configuration support. Valid attributes are: - `type` (string): The type of CD-ROM, valid options are `none`, `client` or `iso`. With `none` the CD-ROM will be disconnected but present. - `iso_path` (string): The datastore path to the ISO file to use, in the form of `[datastore1] path/to/file.iso`. Required if type is set `iso`. - `controller_type` (string): Default value is `ide`. Only `ide` controller type for CD-ROM is supported for now, will add SATA controller type in the future. - `controller_number` (int): For `ide` controller, valid value is 0 or 1. - `unit_number` (int): For CD-ROM device attach to `ide` controller, valid value is 0 or 1. `controller_number` and `unit_number` are mandatory attributes. - `state` (string): Valid value is `present` or `absent`. Default is `present`. If set to `absent`, then the specified CD-ROM will be removed. For `ide` controller, hot-add or hot-remove CD-ROM is not supported. | Optional | 
| resource_pool | Use the given resource pool for virtual machine operation. This parameter is case sensitive. Resource pool should be child of the selected host parent. | Optional | 
| wait_for_ip_address | Wait until vCenter detects an IP address for the virtual machine. This requires vmware-tools (vmtoolsd) to properly work after creation. vmware-tools needs to be installed on the given virtual machine in order to work with this parameter. Default is no. | Optional | 
| wait_for_customization | Wait until vCenter detects all guest customizations as successfully completed. When enabled, the VM will automatically be powered on. Default is no. | Optional | 
| state_change_timeout | If the `state` is set to `shutdownguest`, by default the module will return immediately after sending the shutdown signal. If this argument is set to a positive integer, the module will instead wait for the virtual machine to reach the poweredoff state. The value sets a timeout in seconds for the module to wait for the state change. Default is 0. | Optional | 
| snapshot_src | Name of the existing snapshot to use to create a clone of a virtual machine. This parameter is case sensitive. While creating linked clone using `linked_clone` parameter, this parameter is required. | Optional | 
| linked_clone | Whether to create a linked clone from the snapshot specified. If specified, then `snapshot_src` is required parameter. Default is no. | Optional | 
| force | Ignore warnings and complete the actions. This parameter is useful while removing virtual machine which is powered on state. This module reflects the VMware vCenter API and UI workflow, as such, in some cases the `force` flag will be mandatory to perform the action to ensure you are certain the action has to be taken, no matter what the consequence. This is specifically the case for removing a powered on the virtual machine when `state` is set to `absent`. Default is no. | Optional | 
| datacenter | Destination datacenter for the deploy operation. This parameter is case sensitive. Default is ha-datacenter. | Optional | 
| cluster | The cluster name where the virtual machine will run. This is a required parameter, if `esxi_hostname` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. This parameter is case sensitive. | Optional | 
| esxi_hostname | The ESXi hostname where the virtual machine will run. This is a required parameter, if `cluster` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. This parameter is case sensitive. | Optional | 
| annotation | A note or annotation to include in the virtual machine. | Optional | 
| customvalues | Define a list of custom values to set on virtual machine. A custom value object takes two fields `key` and `value`. Incorrect key and values will be ignored. | Optional | 
| networks | A list of networks (in the order of the NICs). Removing NICs is not allowed, while reconfiguring the virtual machine. All parameters and VMware object names are case sensitive. One of the below parameters is required per entry: - `name` (string): Name of the portgroup or distributed virtual portgroup for this interface. When specifying distributed virtual portgroup make sure given `esxi_hostname` or `cluster` is associated with it. - `vlan` (integer): VLAN number for this interface. Optional parameters per entry (used for virtual hardware): - `device_type` (string): Virtual network device (one of `e1000`, `e1000e`, `pcnet32`, `vmxnet2`, `vmxnet3` (default), `sriov`). - `mac` (string): Customize MAC address. - `dvswitch_name` (string): Name of the distributed vSwitch. This value is required if multiple distributed portgroups exists with the same name. version_added 2.7 - `start_connected` (bool): Indicates that virtual network adapter starts with associated virtual machine powers on. version_added: 2.5 Optional parameters per entry (used for OS customization): - `type` (string): Type of IP assignment (either `dhcp` or `static`). `dhcp` is default. - `ip` (string): Static IP address (implies `type: static`). - `netmask` (string): Static netmask required for `ip`. - `gateway` (string): Static gateway. - `dns_servers` (string): DNS servers for this network interface (Windows). - `domain` (string): Domain name for this network interface (Windows). - `wake_on_lan` (bool): Indicates if wake-on-LAN is enabled on this virtual network adapter. version_added: 2.5 - `allow_guest_control` (bool): Enables guest control over whether the connectable device is connected. version_added: 2.5. | Optional | 
| customization | Parameters for OS customization when cloning from the template or the virtual machine, or apply to the existing virtual machine directly. Not all operating systems are supported for customization with respective vCenter version, please check VMware documentation for respective OS customization. For supported customization operating system matrix, (see `http://partnerweb.vmware.com/programs/guestOS/guest-os-customization-matrix.pdf`) All parameters and VMware object names are case sensitive. Linux based OSes requires Perl package to be installed for OS customizations. Common parameters (Linux/Windows): - `existing_vm` (bool): If set to `True`, do OS customization on the specified virtual machine directly. If set to `False` or not specified, do OS customization when cloning from the template or the virtual machine. version_added: 2.8 - `dns_servers` (list): List of DNS servers to configure. - `dns_suffix` (list): List of domain suffixes, also known as DNS search path (default: `domain` parameter). - `domain` (string): DNS domain name to use. - `hostname` (string): Computer hostname (default: shorted `name` parameter). Allowed characters are alphanumeric (uppercase and lowercase) and minus, rest of the characters are dropped as per RFC 952. Parameters related to Linux customization: - `timezone` (string): Timezone (See List of supported time zones for different vSphere versions in Linux/Unix systems (2145518) `https://kb.vmware.com/s/article/2145518`). version_added: 2.9 - `hwclockUTC` (bool): Specifies whether the hardware clock is in UTC or local time. True when the hardware clock is in UTC, False when the hardware clock is in local time. version_added: 2.9 Parameters related to Windows customization: - `autologon` (bool): Auto logon after virtual machine customization (default: False). - `autologoncount` (int): Number of autologon after reboot (default: 1). - `domainadmin` (string): User used to join in AD domain (mandatory with `joindomain`). - `domainadminpassword` (string): Password used to join in AD domain (mandatory with `joindomain`). - `fullname` (string): Server owner name (default: Administrator). - `joindomain` (string): AD domain to join (Not compatible with `joinworkgroup`). - `joinworkgroup` (string): Workgroup to join (Not compatible with `joindomain`, default: WORKGROUP). - `orgname` (string): Organisation name (default: ACME). - `password` (string): Local administrator password. - `productid` (string): Product ID. - `runonce` (list): List of commands to run at first user logon. - `timezone` (int): Timezone (See `https://msdn.microsoft.com/en-us/library/ms912391.aspx`). | Optional | 
| vapp_properties | A list of vApp properties For full list of attributes and types refer to: `https://github.com/vmware/pyvmomi/blob/master/docs/vim/vApp/PropertyInfo.rst` Basic attributes are: - `id` (string): Property id - required. - `value` (string): Property value. - `type` (string): Value type, string type by default. - `operation`: `remove`: This attribute is required only when removing properties. | Optional | 
| customization_spec | Unique name identifying the requested customization specification. This parameter is case sensitive. If set, then overrides `customization` parameter values. | Optional | 
| datastore | Specify datastore or datastore cluster to provision virtual machine. This parameter takes precedence over "disk.datastore" parameter. This parameter can be used to override datastore or datastore cluster setting of the virtual machine when deployed from the template. Please see example for more usage. | Optional | 
| convert | Specify convert disk type while cloning template or virtual machine. Possible values are: thin, thick, eagerzeroedthick. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuest.instance | unknown | metadata about the new virtual machine | 




### vmware-guest-boot-info
***
Gather info about boot options for the given virtual machine
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_boot_info_module.html


#### Base Command

`vmware-guest-boot-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VM to work with. This is required if `uuid` or `moid` parameter is not supplied. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's BIOS UUID by default. This is required if `name` or `moid` parameter is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestBootInfo.vm_boot_info | unknown | metadata about boot order of virtual machine | 




### vmware-guest-boot-manager
***
Manage boot options for the given virtual machine
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_boot_manager_module.html


#### Base Command

`vmware-guest-boot-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VM to work with. This is required if `uuid` or `moid` parameter is not supplied. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's BIOS UUID by default. This is required if `name` or `moid` parameter is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| boot_order | List of the boot devices. | Optional | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| boot_delay | Delay in milliseconds before starting the boot sequence. Default is 0. | Optional | 
| enter_bios_setup | If set to `True`, the virtual machine automatically enters BIOS setup the next time it boots. The virtual machine resets this flag, so that the machine boots proceeds normally. Possible values are: Yes, No. Default is No. | Optional | 
| boot_retry_enabled | If set to `True`, the virtual machine that fails to boot, will try to boot again after `boot_retry_delay` is expired. If set to `False`, the virtual machine waits indefinitely for user intervention. Possible values are: Yes, No. Default is No. | Optional | 
| boot_retry_delay | Specify the time in milliseconds between virtual machine boot failure and subsequent attempt to boot again. If set, will automatically set `boot_retry_enabled` to `True` as this parameter is required. Default is 0. | Optional | 
| boot_firmware | Choose which firmware should be used to boot the virtual machine. Possible values are: bios, efi. | Optional | 
| secure_boot_enabled | Choose if EFI secure boot should be enabled.  EFI secure boot can only be enabled with boot_firmware = efi. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestBootManager.vm_boot_status | unknown | metadata about boot order of virtual machine | 




### vmware-guest-custom-attribute-defs
***
Manage custom attributes definitions for virtual machine from VMware
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_custom_attribute_defs_module.html


#### Base Command

`vmware-guest-custom-attribute-defs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_key | Name of the custom attribute definition. This is required parameter, if `state` is set to `present` or `absent`. | Optional | 
| state | Manage definition of custom attributes. If set to `present` and definition not present, then custom attribute definition is created. If set to `present` and definition is present, then no action taken. If set to `absent` and definition is present, then custom attribute definition is removed. If set to `absent` and definition is absent, then no action taken. Possible values are: present, absent. Default is present. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestCustomAttributeDefs.custom_attribute_defs | unknown | list of all current attribute definitions | 


#### Command Example
```!vmware-guest-custom-attribute-defs state="present" attribute_key="custom_attr_def_1" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestCustomAttributeDefs": [
            {
                "changed": true,
                "custom_attribute_defs": [
                    "AutoDeploy.MachineIdentity",
                    "com.vmware.vcIntegrity.customField.scheduledTask.action",
                    "com.vmware.vcIntegrity.customField.scheduledTask.signature",
                    "com.vmware.vcIntegrity.customField.scheduledTask.target",
                    "custom_attr_def_1"
                ],
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Custom_Attribute_Defs
>    * 0: AutoDeploy.MachineIdentity
>    * 1: com.vmware.vcIntegrity.customField.scheduledTask.action
>    * 2: com.vmware.vcIntegrity.customField.scheduledTask.signature
>    * 3: com.vmware.vcIntegrity.customField.scheduledTask.target
>    * 4: custom_attr_def_1


### vmware-guest-custom-attributes
***
Manage custom attributes from VMware for the given virtual machine
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_custom_attributes_module.html


#### Base Command

`vmware-guest-custom-attributes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine to work with. This is required parameter, if `uuid` or `moid` is not supplied. | Required | 
| state | The action to take. If set to `present`, then custom attribute is added or updated. If set to `absent`, then custom attribute is removed. Possible values are: present, absent. Default is present. | Optional | 
| uuid | UUID of the virtual machine to manage if known. This is VMware's unique identifier. This is required parameter, if `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| folder | Absolute path to find an existing guest. This is required parameter, if `name` is supplied and multiple virtual machines with same name are found. | Optional | 
| datacenter | Datacenter name where the virtual machine is located in. | Required | 
| attributes | A list of name and value of custom attributes that needs to be manage. Value of custom attribute is not required and will be ignored, if `state` is set to `absent`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestCustomAttributes.custom_attributes | unknown | metadata about the virtual machine attributes | 




### vmware-guest-customization-info
***
Gather info about VM customization specifications
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_customization_info_module.html


#### Base Command

`vmware-guest-customization-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| spec_name | Name of customization specification to find. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestCustomizationInfo.custom_spec_info | unknown | metadata about the customization specification | 


#### Command Example
```!vmware-guest-customization-info ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestCustomizationInfo": [
            {
                "changed": false,
                "custom_spec_info": {},
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Custom_Spec_Info


### vmware-guest-disk
***
Manage disks related to virtual machine in given vCenter infrastructure
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_disk_module.html


#### Base Command

`vmware-guest-disk`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine. This is a required parameter, if parameter `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to gather facts if known, this is VMware's unique identifier. This is a required parameter, if parameter `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is a required parameter, only if multiple VMs are found with same name. The folder should include the datacenter. ESX's datacenter is ha-datacenter Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | The datacenter name to which virtual machine belongs to. | Required | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| disk | A list of disks to add. The virtual disk related information is provided using this list. All values and parameters are case sensitive. Valid attributes are: - `size[_tb,_gb,_mb,_kb]` (integer): Disk storage size in specified unit. If `size` specified then unit must be specified. There is no space allowed in between size number and unit. Only first occurrence in disk element will be considered, even if there are multiple size* parameters available. - `type` (string): Valid values are: - `thin` thin disk - `eagerzeroedthick` eagerzeroedthick disk - `thick` thick disk Default: `thick` thick disk, no eagerzero. - `datastore` (string): Name of datastore or datastore cluster to be used for the disk. - `autoselect_datastore` (bool): Select the less used datastore. Specify only if `datastore` is not specified. - `scsi_controller` (integer): SCSI controller number. Valid value range from 0 to 3. Only 4 SCSI controllers are allowed per VM. Care should be taken while specifying `scsi_controller` is 0 and `unit_number` as 0 as this disk may contain OS. - `unit_number` (integer): Disk Unit Number. Valid value range from 0 to 15. Only 15 disks are allowed per SCSI Controller. - `scsi_type` (string): Type of SCSI controller. This value is required only for the first occurrence of SCSI Controller. This value is ignored, if SCSI Controller is already present or `state` is `absent`. Valid values are `buslogic`, `lsilogic`, `lsilogicsas` and `paravirtual`. `paravirtual` is default value for this parameter. - `state` (string): State of disk. This is either "absent" or "present". If `state` is set to `absent`, disk will be removed permanently from virtual machine configuration and from VMware storage. If `state` is set to `present`, disk will be added if not present at given SCSI Controller and Unit Number. If `state` is set to `present` and disk exists with different size, disk size is increased. Reducing disk size is not allowed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestDisk.disk_status | unknown | metadata about the virtual machine's disks after managing them | 




### vmware-guest-disk-info
***
Gather info about disks of given virtual machine
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_disk_info_module.html


#### Base Command

`vmware-guest-disk-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine. This is required parameter, if parameter `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to gather information if known, this is VMware's unique identifier. This is required parameter, if parameter `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is required parameter, only if multiple VMs are found with same name. The folder should include the datacenter. ESX's datacenter is ha-datacenter Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | The datacenter name to which virtual machine belongs to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestDiskInfo.guest_disk_info | unknown | metadata about the virtual machine's disks | 


#### Command Example
```!vmware-guest-disk-info datacenter="DC1" name="test_vm_0001" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestDiskInfo": [
            {
                "changed": false,
                "guest_disk_info": {
                    "0": {
                        "backing_datastore": "datastore1",
                        "backing_disk_mode": "persistent",
                        "backing_diskmode": "persistent",
                        "backing_eagerlyscrub": false,
                        "backing_filename": "[datastore1] test_vm_0001/test_vm_0001.vmdk",
                        "backing_thinprovisioned": true,
                        "backing_type": "FlatVer2",
                        "backing_uuid": "6000C294-3cd2-f966-9fb7-556870ae6bdf",
                        "backing_writethrough": false,
                        "capacity_in_bytes": 1073741824,
                        "capacity_in_kb": 1048576,
                        "controller_bus_number": 0,
                        "controller_key": 1000,
                        "controller_type": "paravirtual",
                        "key": 2000,
                        "label": "Hard disk 1",
                        "summary": "1,048,576 KB",
                        "unit_number": 0
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Guest_Disk_Info
>    * ### 0
>      * backing_datastore: datastore1
>      * backing_disk_mode: persistent
>      * backing_diskmode: persistent
>      * backing_eagerlyscrub: False
>      * backing_filename: [datastore1] test_vm_0001/test_vm_0001.vmdk
>      * backing_thinprovisioned: True
>      * backing_type: FlatVer2
>      * backing_uuid: 6000C294-3cd2-f966-9fb7-556870ae6bdf
>      * backing_writethrough: False
>      * capacity_in_bytes: 1073741824
>      * capacity_in_kb: 1048576
>      * controller_bus_number: 0
>      * controller_key: 1000
>      * controller_type: paravirtual
>      * key: 2000
>      * label: Hard disk 1
>      * summary: 1,048,576 KB
>      * unit_number: 0


### vmware-guest-find
***
Find the folder path(s) for a virtual machine by name or UUID
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_find_module.html


#### Base Command

`vmware-guest-find`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VM to work with. This is required if `uuid` parameter is not supplied. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's BIOS UUID by default. This is required if `name` parameter is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| datacenter | Destination datacenter for the find operation. Deprecated in 2.5, will be removed in 2.9 release. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestFind.folders | unknown | List of folders for user specified virtual machine | 


#### Command Example
```!vmware-guest-find name="test_vm_0001" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestFind": [
            {
                "changed": false,
                "folders": [
                    "/DC1/vm"
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Folders
>    * 0: /DC1/vm


### vmware-guest-info
***
Gather info about a single VM
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_info_module.html


#### Base Command

`vmware-guest-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VM to work with This is required if `uuid` or `moid` is not supplied. | Optional | 
| name_match | If multiple VMs matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's unique identifier. This is required if `name` or `moid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is required if name is supplied. The folder should include the datacenter. ESX's datacenter is ha-datacenter Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | Destination datacenter for the deploy operation. | Required | 
| tags | Whether to show tags or not. If set `True`, shows tag information. If set `False`, hides tags information. vSphere Automation SDK and vCloud Suite SDK is required. Default is no. | Optional | 
| schema | Specify the output schema desired. The 'summary' output schema is the legacy output from the module The 'vsphere' output schema is the vSphere API class definition which requires pyvmomi&gt;6.7.1. Possible values are: summary, vsphere. Default is summary. | Optional | 
| properties | Specify the properties to retrieve. If not specified, all properties are retrieved (deeply). Results are returned in a structure identical to the vsphere API. Example: properties: [ "config.hardware.memoryMB", "config.hardware.numCPU", "guest.disk", "overallStatus" ] Only valid when `schema` is `vsphere`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestInfo.instance | unknown | metadata about the virtual machine | 


#### Command Example
```!vmware-guest-info datacenter="DC1" name="test_vm_0001" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestInfo": [
            {
                "changed": false,
                "instance": {
                    "annotation": "",
                    "current_snapshot": null,
                    "customvalues": {},
                    "guest_consolidation_needed": false,
                    "guest_question": null,
                    "guest_tools_status": "guestToolsNotRunning",
                    "guest_tools_version": "0",
                    "hw_cluster": "cluster",
                    "hw_cores_per_socket": 1,
                    "hw_datastores": [
                        "datastore1"
                    ],
                    "hw_esxi_host": "esxi01",
                    "hw_eth0": {
                        "addresstype": "manual",
                        "ipaddresses": null,
                        "label": "Network adapter 1",
                        "macaddress": "aa:bb:dd:aa:00:14",
                        "macaddress_dash": "aa-bb-dd-aa-00-14",
                        "portgroup_key": null,
                        "portgroup_portkey": null,
                        "summary": "VM Network"
                    },
                    "hw_files": [
                        "[datastore1] test_vm_0001/test_vm_0001.vmx",
                        "[datastore1] test_vm_0001/test_vm_0001.vmsd",
                        "[datastore1] test_vm_0001/test_vm_0001.vmdk"
                    ],
                    "hw_folder": "/DC1/vm",
                    "hw_guest_full_name": null,
                    "hw_guest_ha_state": null,
                    "hw_guest_id": null,
                    "hw_interfaces": [
                        "eth0"
                    ],
                    "hw_is_template": false,
                    "hw_memtotal_mb": 512,
                    "hw_name": "test_vm_0001",
                    "hw_power_status": "poweredOff",
                    "hw_processor_count": 4,
                    "hw_product_uuid": "42166c31-2bd1-6ac0-1ebb-a6db907f529e",
                    "hw_version": "vmx-13",
                    "instance_uuid": "5016ea58-ccce-5688-f16b-82ca0b25e513",
                    "ipv4": null,
                    "ipv6": null,
                    "module_hw": true,
                    "moid": "vm-21",
                    "snapshots": [],
                    "vimref": "vim.VirtualMachine:vm-21",
                    "vnc": {}
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Instance
>    * annotation: 
>    * current_snapshot: None
>    * guest_consolidation_needed: False
>    * guest_question: None
>    * guest_tools_status: guestToolsNotRunning
>    * guest_tools_version: 0
>    * hw_cluster: cluster
>    * hw_cores_per_socket: 1
>    * hw_esxi_host: esxi01
>    * hw_folder: /DC1/vm
>    * hw_guest_full_name: None
>    * hw_guest_ha_state: None
>    * hw_guest_id: None
>    * hw_is_template: False
>    * hw_memtotal_mb: 512
>    * hw_name: test_vm_0001
>    * hw_power_status: poweredOff
>    * hw_processor_count: 4
>    * hw_product_uuid: 42166c31-2bd1-6ac0-1ebb-a6db907f529e
>    * hw_version: vmx-13
>    * instance_uuid: 5016ea58-ccce-5688-f16b-82ca0b25e513
>    * ipv4: None
>    * ipv6: None
>    * module_hw: True
>    * moid: vm-21
>    * vimref: vim.VirtualMachine:vm-21
>    * ### Customvalues
>    * ### Hw_Datastores
>      * 0: datastore1
>    * ### Hw_Eth0
>      * addresstype: manual
>      * ipaddresses: None
>      * label: Network adapter 1
>      * macaddress: aa:bb:dd:aa:00:14
>      * macaddress_dash: aa-bb-dd-aa-00-14
>      * portgroup_key: None
>      * portgroup_portkey: None
>      * summary: VM Network
>    * ### Hw_Files
>      * 0: [datastore1] test_vm_0001/test_vm_0001.vmx
>      * 1: [datastore1] test_vm_0001/test_vm_0001.vmsd
>      * 2: [datastore1] test_vm_0001/test_vm_0001.vmdk
>    * ### Hw_Interfaces
>      * 0: eth0
>    * ### Snapshots
>    * ### Vnc

### vmware-guest-move
***
Moves virtual machines in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_move_module.html


#### Base Command

`vmware-guest-move`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the existing virtual machine to move. This is required if `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the virtual machine to manage if known, this is VMware's unique identifier. This is required if `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| dest_folder | Absolute path to move an existing guest The dest_folder should include the datacenter. ESX's datacenter is ha-datacenter. This parameter is case sensitive. Examples: dest_folder: /ha-datacenter/vm dest_folder: ha-datacenter/vm dest_folder: /datacenter1/vm dest_folder: datacenter1/vm dest_folder: /datacenter1/vm/folder1 dest_folder: datacenter1/vm/folder1 dest_folder: /folder1/datacenter1/vm dest_folder: folder1/datacenter1/vm dest_folder: /folder1/datacenter1/vm/folder2. | Required | 
| datacenter | Destination datacenter for the move operation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestMove.instance | unknown | metadata about the virtual machine | 


#### Command Example
```!vmware-guest-move datacenter="DC1" name="test_vm_0001" dest_folder="/DC1/vm" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestMove": [
            {
                "changed": false,
                "instance": {
                    "annotation": "",
                    "current_snapshot": null,
                    "customvalues": {},
                    "guest_consolidation_needed": false,
                    "guest_question": null,
                    "guest_tools_status": "guestToolsNotRunning",
                    "guest_tools_version": "0",
                    "hw_cluster": "cluster",
                    "hw_cores_per_socket": 1,
                    "hw_datastores": [
                        "datastore1"
                    ],
                    "hw_esxi_host": "esxi01",
                    "hw_eth0": {
                        "addresstype": "manual",
                        "ipaddresses": null,
                        "label": "Network adapter 1",
                        "macaddress": "aa:bb:dd:aa:00:14",
                        "macaddress_dash": "aa-bb-dd-aa-00-14",
                        "portgroup_key": null,
                        "portgroup_portkey": null,
                        "summary": "VM Network"
                    },
                    "hw_files": [
                        "[datastore1] test_vm_0001/test_vm_0001.vmx",
                        "[datastore1] test_vm_0001/test_vm_0001.vmsd",
                        "[datastore1] test_vm_0001/test_vm_0001.vmdk"
                    ],
                    "hw_folder": "/DC1/vm",
                    "hw_guest_full_name": null,
                    "hw_guest_ha_state": null,
                    "hw_guest_id": null,
                    "hw_interfaces": [
                        "eth0"
                    ],
                    "hw_is_template": false,
                    "hw_memtotal_mb": 512,
                    "hw_name": "test_vm_0001",
                    "hw_power_status": "poweredOff",
                    "hw_processor_count": 4,
                    "hw_product_uuid": "42166c31-2bd1-6ac0-1ebb-a6db907f529e",
                    "hw_version": "vmx-13",
                    "instance_uuid": "5016ea58-ccce-5688-f16b-82ca0b25e513",
                    "ipv4": null,
                    "ipv6": null,
                    "module_hw": true,
                    "moid": "vm-21",
                    "snapshots": [],
                    "vimref": "vim.VirtualMachine:vm-21",
                    "vnc": {}
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Instance
>    * annotation: 
>    * current_snapshot: None
>    * guest_consolidation_needed: False
>    * guest_question: None
>    * guest_tools_status: guestToolsNotRunning
>    * guest_tools_version: 0
>    * hw_cluster: cluster
>    * hw_cores_per_socket: 1
>    * hw_esxi_host: esxi01
>    * hw_folder: /DC1/vm
>    * hw_guest_full_name: None
>    * hw_guest_ha_state: None
>    * hw_guest_id: None
>    * hw_is_template: False
>    * hw_memtotal_mb: 512
>    * hw_name: test_vm_0001
>    * hw_power_status: poweredOff
>    * hw_processor_count: 4
>    * hw_product_uuid: 42166c31-2bd1-6ac0-1ebb-a6db907f529e
>    * hw_version: vmx-13
>    * instance_uuid: 5016ea58-ccce-5688-f16b-82ca0b25e513
>    * ipv4: None
>    * ipv6: None
>    * module_hw: True
>    * moid: vm-21
>    * vimref: vim.VirtualMachine:vm-21
>    * ### Customvalues
>    * ### Hw_Datastores
>      * 0: datastore1
>    * ### Hw_Eth0
>      * addresstype: manual
>      * ipaddresses: None
>      * label: Network adapter 1
>      * macaddress: aa:bb:dd:aa:00:14
>      * macaddress_dash: aa-bb-dd-aa-00-14
>      * portgroup_key: None
>      * portgroup_portkey: None
>      * summary: VM Network
>    * ### Hw_Files
>      * 0: [datastore1] test_vm_0001/test_vm_0001.vmx
>      * 1: [datastore1] test_vm_0001/test_vm_0001.vmsd
>      * 2: [datastore1] test_vm_0001/test_vm_0001.vmdk
>    * ### Hw_Interfaces
>      * 0: eth0
>    * ### Snapshots
>    * ### Vnc


### vmware-guest-network
***
Manage network adapters of specified virtual machine in given vCenter infrastructure
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_network_module.html


#### Base Command

`vmware-guest-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine. This is a required parameter, if parameter `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to gather info if known, this is VMware's unique identifier. This is a required parameter, if parameter `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is a required parameter, only if multiple VMs are found with same name. The folder should include the datacenter. ESXi server's datacenter is ha-datacenter. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| cluster | The name of cluster where the virtual machine will run. This is a required parameter, if `esxi_hostname` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. | Optional | 
| esxi_hostname | The ESXi hostname where the virtual machine will run. This is a required parameter, if `cluster` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. | Optional | 
| datacenter | The datacenter name to which virtual machine belongs to. Default is ha-datacenter. | Optional | 
| gather_network_info | If set to `True`, return settings of all network adapters, other parameters are ignored. If set to `False`, will add, reconfigure or remove network adapters according to the parameters in `networks`. Possible values are: Yes, No. Default is No. | Optional | 
| networks | A list of network adapters. `mac` or `label` or `device_type` is required to reconfigure or remove an existing network adapter. If there are multiple network adapters with the same `device_type`, you should set `label` or `mac` to match one of them, or will apply changes on all network adapters with the `device_type` specified. `mac`, `label`, `device_type` is the order of precedence from greatest to least if all set. Valid attributes are: - `mac` (string): MAC address of the existing network adapter to be reconfigured or removed. - `label` (string): Label of the existing network adapter to be reconfigured or removed, e.g., "Network adapter 1". - `device_type` (string): Valid virtual network device types are: `e1000`, `e1000e`, `pcnet32`, `vmxnet2`, `vmxnet3` (default), `sriov`. Used to add new network adapter, reconfigure or remove the existing network adapter with this type. If `mac` and `label` not specified or not find network adapter by `mac` or `label` will use this parameter. - `name` (string): Name of the portgroup or distributed virtual portgroup for this interface. When specifying distributed virtual portgroup make sure given `esxi_hostname` or `cluster` is associated with it. - `vlan` (integer): VLAN number for this interface. - `dvswitch_name` (string): Name of the distributed vSwitch. This value is required if multiple distributed portgroups exists with the same name. - `state` (string): State of the network adapter. If set to `present`, then will do reconfiguration for the specified network adapter. If set to `new`, then will add the specified network adapter. If set to `absent`, then will remove this network adapter. - `manual_mac` (string): Manual specified MAC address of the network adapter when creating, or reconfiguring. If not specified when creating new network adapter, mac address will be generated automatically. When reconfigure MAC address, VM should be in powered off state. - `connected` (bool): Indicates that virtual network adapter connects to the associated virtual machine. - `start_connected` (bool): Indicates that virtual network adapter starts with associated virtual machine powers on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestNetwork.network_data | unknown | metadata about the virtual machine's network adapter after managing them | 




### vmware-guest-powerstate
***
Manages power states of virtual machines in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_powerstate_module.html


#### Base Command

`vmware-guest-powerstate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Set the state of the virtual machine. Possible values are: powered-off, powered-on, reboot-guest, restarted, shutdown-guest, suspended, present. Default is present. | Optional | 
| name | Name of the virtual machine to work with. Virtual machine names in vCenter are not necessarily unique, which may be problematic, see `name_match`. | Optional | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's unique identifier. This is required if `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. The folder should include the datacenter. ESX's datacenter is ha-datacenter Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| scheduled_at | Date and time in string format at which specified task needs to be performed. The required format for date and time - 'dd/mm/yyyy hh:mm'. Scheduling task requires vCenter server. A standalone ESXi server does not support this option. | Optional | 
| schedule_task_name | Name of schedule task. Valid only if `scheduled_at` is specified. | Optional | 
| schedule_task_description | Description of schedule task. Valid only if `scheduled_at` is specified. | Optional | 
| schedule_task_enabled | Flag to indicate whether the scheduled task is enabled or disabled. Possible values are: Yes, No. Default is Yes. | Optional | 
| force | Ignore warnings and complete the actions. This parameter is useful while forcing virtual machine state. Possible values are: Yes, No. Default is No. | Optional | 
| state_change_timeout | If the `state` is set to `shutdown-guest`, by default the module will return immediately after sending the shutdown signal. If this argument is set to a positive integer, the module will instead wait for the VM to reach the poweredoff state. The value sets a timeout in seconds for the module to wait for the state change. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-guest-screenshot
***
Create a screenshot of the Virtual Machine console.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_screenshot_module.html


#### Base Command

`vmware-guest-screenshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine. This is a required parameter, if parameter `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to gather facts if known, this is VMware's unique identifier. This is a required parameter, if parameter `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is a required parameter, only if multiple VMs are found with same name. The folder should include the datacenter. ESXi server's datacenter is ha-datacenter. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| cluster | The name of cluster where the virtual machine is running. This is a required parameter, if `esxi_hostname` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. | Optional | 
| esxi_hostname | The ESXi hostname where the virtual machine is running. This is a required parameter, if `cluster` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. | Optional | 
| datacenter | The datacenter name to which virtual machine belongs to. | Optional | 
| local_path | If `local_path` is not set, the created screenshot file will be kept in the directory of the virtual machine on ESXi host. If `local_path` is set to a valid path on local machine, then the screenshot file will be downloaded from ESXi host to the local directory. If not download screenshot file to local machine, you can open it through the returned file URL in screenshot facts manually. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestScreenshot.screenshot_info | unknown | display the facts of captured virtual machine screenshot file | 




### vmware-guest-sendkey
***
Send USB HID codes to the Virtual Machine's keyboard.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_sendkey_module.html


#### Base Command

`vmware-guest-sendkey`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine. This is a required parameter, if parameter `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to gather facts if known, this is VMware's unique identifier. This is a required parameter, if parameter `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is a required parameter, only if multiple VMs are found with same name. The folder should include the datacenter. ESXi server's datacenter is ha-datacenter. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| cluster | The name of cluster where the virtual machine is running. This is a required parameter, if `esxi_hostname` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. | Optional | 
| esxi_hostname | The ESXi hostname where the virtual machine is running. This is a required parameter, if `cluster` is not set. `esxi_hostname` and `cluster` are mutually exclusive parameters. | Optional | 
| datacenter | The datacenter name to which virtual machine belongs to. | Optional | 
| string_send | The string will be sent to the virtual machine. This string can contain valid special character, alphabet and digit on the keyboard. | Optional | 
| keys_send | The list of the keys will be sent to the virtual machine. Valid values are `ENTER`, `ESC`, `BACKSPACE`, `TAB`, `SPACE`, `CAPSLOCK`, `DELETE`, `CTRL_ALT_DEL`, `CTRL_C` and `F1` to `F12`, `RIGHTARROW`, `LEFTARROW`, `DOWNARROW`, `UPARROW`. If both `keys_send` and `string_send` are specified, keys in `keys_send` list will be sent in front of the `string_send`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestSendkey.sendkey_info | unknown | display the keys and the number of keys sent to the virtual machine | 




### vmware-guest-snapshot
***
Manages virtual machines snapshots in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_snapshot_module.html


#### Base Command

`vmware-guest-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Manage snapshot(s) attached to a specific virtual machine. If set to `present` and snapshot absent, then will create a new snapshot with the given name. If set to `present` and snapshot present, then no changes are made. If set to `absent` and snapshot present, then snapshot with the given name is removed. If set to `absent` and snapshot absent, then no changes are made. If set to `revert` and snapshot present, then virtual machine state is reverted to the given snapshot. If set to `revert` and snapshot absent, then no changes are made. If set to `remove_all` and snapshot(s) present, then all snapshot(s) will be removed. If set to `remove_all` and snapshot(s) absent, then no changes are made. Possible values are: present, absent, revert, remove_all. Default is present. | Required | 
| name | Name of the virtual machine to work with. This is required parameter, if `uuid` or `moid` is not supplied. | Optional | 
| name_match | If multiple VMs matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's BIOS UUID by default. This is required if `name` or `moid` parameter is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is required parameter, if `name` is supplied. The folder should include the datacenter. ESX's datacenter is ha-datacenter. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | Destination datacenter for the deploy operation. | Required | 
| snapshot_name | Sets the snapshot name to manage. This param is required only if state is not `remove_all`. | Optional | 
| description | Define an arbitrary description to attach to snapshot. | Optional | 
| quiesce | If set to `true` and virtual machine is powered on, it will quiesce the file system in virtual machine. Note that VMware Tools are required for this flag. If virtual machine is powered off or VMware Tools are not available, then this flag is set to `false`. If virtual machine does not provide capability to take quiesce snapshot, then this flag is set to `false`. Possible values are: Yes, No. Default is No. | Optional | 
| memory_dump | If set to `true`, memory dump of virtual machine is also included in snapshot. Note that memory snapshots take time and resources, this will take longer time to create. If virtual machine does not provide capability to take memory snapshot, then this flag is set to `false`. Possible values are: Yes, No. Default is No. | Optional | 
| remove_children | If set to `true` and state is set to `absent`, then entire snapshot subtree is set for removal. Possible values are: Yes, No. Default is No. | Optional | 
| new_snapshot_name | Value to rename the existing snapshot to. | Optional | 
| new_description | Value to change the description of an existing snapshot to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestSnapshot.snapshot_results | unknown | metadata about the virtual machine snapshots | 


#### Command Example
```!vmware-guest-snapshot datacenter="DC1" folder="/DC1/vm/" name="test_vm_0001" state="present" snapshot_name="snap1" description="snap1_description" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestSnapshot": [
            {
                "changed": true,
                "snapshot_results": {
                    "current_snapshot": {
                        "creation_time": "2021-07-11T17:02:28.131433+00:00",
                        "description": "snap1_description",
                        "id": 1,
                        "name": "snap1",
                        "state": "poweredOff"
                    },
                    "snapshots": [
                        {
                            "creation_time": "2021-07-11T17:02:28.131433+00:00",
                            "description": "snap1_description",
                            "id": 1,
                            "name": "snap1",
                            "state": "poweredOff"
                        }
                    ]
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Snapshot_Results
>    * ### Current_Snapshot
>      * creation_time: 2021-07-11T17:02:28.131433+00:00
>      * description: snap1_description
>      * id: 1
>      * name: snap1
>      * state: poweredOff
>    * ### Snapshots
>    * ### Snap1
>      * creation_time: 2021-07-11T17:02:28.131433+00:00
>      * description: snap1_description
>      * id: 1
>      * name: snap1
>      * state: poweredOff

### vmware-guest-snapshot-info
***
Gather info about virtual machine's snapshots in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_snapshot_info_module.html


#### Base Command

`vmware-guest-snapshot-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VM to work with. This is required if `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's BIOS UUID by default. This is required if `name` or `moid` parameter is not supplied. The `folder` is ignored, if `uuid` is provided. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is required only, if multiple virtual machines with same name are found on given vCenter. The folder should include the datacenter. ESX's datacenter is ha-datacenter Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | Name of the datacenter. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestSnapshotInfo.guest_snapshots | unknown | metadata about the snapshot information | 




### vmware-guest-tools-upgrade
***
Module to upgrade VMTools
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_tools_upgrade_module.html


#### Base Command

`vmware-guest-tools-upgrade`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine to work with. This is required if `uuid` or `moid` is not supplied. | Optional | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's unique identifier. This is required if `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is required, if `name` is supplied. The folder should include the datacenter. ESX's datacenter is ha-datacenter Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | Destination datacenter where the virtual machine exists. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-guest-tools-wait
***
Wait for VMware tools to become available
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_tools_wait_module.html


#### Base Command

`vmware-guest-tools-wait`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the VM for which to wait until the tools become available. This is required if `uuid` or `moid` is not supplied. | Optional | 
| name_match | If multiple VMs match the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is required only, if multiple VMs with same `name` is found. The folder should include the datacenter. ESX's datacenter is `ha-datacenter`. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| uuid | UUID of the VM  for which to wait until the tools become available, if known. This is VMware's unique identifier. This is required, if `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestToolsWait.instance | unknown | metadata about the virtual machine | 




### vmware-guest-video
***
Modify video card configurations of specified virtual machine in given vCenter infrastructure
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_video_module.html


#### Base Command

`vmware-guest-video`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the virtual machine. This is a required parameter, if parameter `uuid` or `moid` is not supplied. | Optional | 
| uuid | UUID of the instance to gather facts if known, this is VMware's unique identifier. This is a required parameter, if parameter `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. This is a required parameter, only if multiple VMs are found with same name. The folder should include the datacenter. ESXi server's datacenter is ha-datacenter. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| datacenter | The datacenter name to which virtual machine belongs to. This parameter is case sensitive. Default is ha-datacenter. | Optional | 
| gather_video_facts | If set to True, return settings of the video card, other attributes are ignored. If set to False, will do reconfiguration and return video card settings. Default is no. | Optional | 
| use_auto_detect | If set to True, applies common video settings to the guest operating system, attributes `display_number` and `video_memory_mb` are ignored. If set to False, the number of display and the total video memory will be reconfigured using `display_number` and `video_memory_mb`. | Optional | 
| display_number | The number of display. Valid value from 1 to 10. The maximum display number is 4 on vCenter 6.0, 6.5 web UI. | Optional | 
| video_memory_mb | Valid total MB of video memory range of virtual machine is from 1.172 MB to 256 MB on ESXi 6.7U1, from 1.172 MB to 128 MB on ESXi 6.7 and previous versions. For specific guest OS, supported minimum and maximum video memory are different, please be careful on setting this. | Optional | 
| enable_3D | Enable 3D for guest operating systems on which VMware supports 3D. | Optional | 
| renderer_3D | If set to `automatic`, selects the appropriate option (software or hardware) for this virtual machine automatically. If set to `software`, uses normal CPU processing for 3D calculations. If set to `hardware`, requires graphics hardware (GPU) for faster 3D calculations. Possible values are: automatic, software, hardware. | Optional | 
| memory_3D_mb | The value of 3D Memory must be power of 2 and valid value is from 32 MB to 2048 MB. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestVideo.video_status | unknown | metadata about the virtual machine's video card after managing them | 




### vmware-guest-vnc
***
Manages VNC remote display on virtual machines in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_guest_vnc_module.html


#### Base Command

`vmware-guest-vnc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | Destination datacenter for the deploy operation. This parameter is case sensitive. Default is ha-datacenter. | Optional | 
| state | Set the state of VNC on virtual machine. Possible values are: present, absent. Default is present. | Optional | 
| name | Name of the virtual machine to work with. Virtual machine names in vCenter are not necessarily unique, which may be problematic, see `name_match`. | Optional | 
| name_match | If multiple virtual machines matching the name, use the first or last found. Possible values are: first, last. Default is first. | Optional | 
| uuid | UUID of the instance to manage if known, this is VMware's unique identifier. This is required, if `name` or `moid` is not supplied. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `name` or `uuid` is not supplied. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest. The folder should include the datacenter. ESX's datacenter is ha-datacenter. | Optional | 
| vnc_ip | Sets an IP for VNC on virtual machine. This is required only when `state` is set to present and will be ignored if `state` is absent. Default is 0.0.0.0. | Optional | 
| vnc_port | The port that VNC listens on. Usually a number between 5900 and 7000 depending on your config. This is required only when `state` is set to present and will be ignored if `state` is absent. Default is 0. | Optional | 
| vnc_password | Sets a password for VNC on virtual machine. This is required only when `state` is set to present and will be ignored if `state` is absent. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareGuestVnc.changed | boolean | If anything changed on VM's extraConfig. | 
| VMware.VmwareGuestVnc.failed | boolean | If changes failed. | 
| VMware.VmwareGuestVnc.instance | unknown | Dictionary describing the VM, including VNC info. | 


#### Command Example
```!vmware-guest-vnc folder="/DC1/vm" name="test_vm_0001" vnc_port="5990" vnc_password="vNc5ecr3t" datacenter="DC1" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareGuestVnc": [
            {
                "changed": true,
                "instance": {
                    "annotation": "",
                    "current_snapshot": {
                        "creation_time": "2021-07-11T17:02:28.131433+00:00",
                        "description": "snap1_description",
                        "id": 1,
                        "name": "snap1",
                        "state": "poweredOff"
                    },
                    "customvalues": {},
                    "guest_consolidation_needed": false,
                    "guest_question": null,
                    "guest_tools_status": "guestToolsNotRunning",
                    "guest_tools_version": "0",
                    "hw_cluster": "cluster",
                    "hw_cores_per_socket": 1,
                    "hw_datastores": [
                        "datastore1"
                    ],
                    "hw_esxi_host": "esxi01",
                    "hw_eth0": {
                        "addresstype": "manual",
                        "ipaddresses": null,
                        "label": "Network adapter 1",
                        "macaddress": "aa:bb:dd:aa:00:14",
                        "macaddress_dash": "aa-bb-dd-aa-00-14",
                        "portgroup_key": null,
                        "portgroup_portkey": null,
                        "summary": "VM Network"
                    },
                    "hw_files": [
                        "[datastore1] test_vm_0001/test_vm_0001.vmx",
                        "[datastore1] test_vm_0001/test_vm_0001-Snapshot1.vmsn",
                        "[datastore1] test_vm_0001/test_vm_0001.vmsd",
                        "[datastore1] test_vm_0001/test_vm_0001.vmdk",
                        "[datastore1] test_vm_0001/test_vm_0001-000001.vmdk"
                    ],
                    "hw_folder": "/DC1/vm",
                    "hw_guest_full_name": null,
                    "hw_guest_ha_state": null,
                    "hw_guest_id": null,
                    "hw_interfaces": [
                        "eth0"
                    ],
                    "hw_is_template": false,
                    "hw_memtotal_mb": 512,
                    "hw_name": "test_vm_0001",
                    "hw_power_status": "poweredOff",
                    "hw_processor_count": 4,
                    "hw_product_uuid": "42166c31-2bd1-6ac0-1ebb-a6db907f529e",
                    "hw_version": "vmx-13",
                    "instance_uuid": "5016ea58-ccce-5688-f16b-82ca0b25e513",
                    "ipv4": null,
                    "ipv6": null,
                    "module_hw": true,
                    "moid": "vm-21",
                    "snapshots": [
                        {
                            "creation_time": "2021-07-11T17:02:28.131433+00:00",
                            "description": "snap1_description",
                            "id": 1,
                            "name": "snap1",
                            "state": "poweredOff"
                        }
                    ],
                    "vimref": "vim.VirtualMachine:vm-21",
                    "vnc": {
                        "enabled": "TRUE",
                        "ip": "0.0.0.0",
                        "password": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
                        "port": "5990"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Instance
>    * annotation: 
>    * guest_consolidation_needed: False
>    * guest_question: None
>    * guest_tools_status: guestToolsNotRunning
>    * guest_tools_version: 0
>    * hw_cluster: cluster
>    * hw_cores_per_socket: 1
>    * hw_esxi_host: esxi01
>    * hw_folder: /DC1/vm
>    * hw_guest_full_name: None
>    * hw_guest_ha_state: None
>    * hw_guest_id: None
>    * hw_is_template: False
>    * hw_memtotal_mb: 512
>    * hw_name: test_vm_0001
>    * hw_power_status: poweredOff
>    * hw_processor_count: 4
>    * hw_product_uuid: 42166c31-2bd1-6ac0-1ebb-a6db907f529e
>    * hw_version: vmx-13
>    * instance_uuid: 5016ea58-ccce-5688-f16b-82ca0b25e513
>    * ipv4: None
>    * ipv6: None
>    * module_hw: True
>    * moid: vm-21
>    * vimref: vim.VirtualMachine:vm-21
>    * ### Current_Snapshot
>      * creation_time: 2021-07-11T17:02:28.131433+00:00
>      * description: snap1_description
>      * id: 1
>      * name: snap1
>      * state: poweredOff
>    * ### Customvalues
>    * ### Hw_Datastores
>      * 0: datastore1
>    * ### Hw_Eth0
>      * addresstype: manual
>      * ipaddresses: None
>      * label: Network adapter 1
>      * macaddress: aa:bb:dd:aa:00:14
>      * macaddress_dash: aa-bb-dd-aa-00-14
>      * portgroup_key: None
>      * portgroup_portkey: None
>      * summary: VM Network
>    * ### Hw_Files
>      * 0: [datastore1] test_vm_0001/test_vm_0001.vmx
>      * 1: [datastore1] test_vm_0001/test_vm_0001-Snapshot1.vmsn
>      * 2: [datastore1] test_vm_0001/test_vm_0001.vmsd
>      * 3: [datastore1] test_vm_0001/test_vm_0001.vmdk
>      * 4: [datastore1] test_vm_0001/test_vm_0001-000001.vmdk
>    * ### Hw_Interfaces
>      * 0: eth0
>    * ### Snapshots
>    * ### Snap1
>      * creation_time: 2021-07-11T17:02:28.131433+00:00
>      * description: snap1_description
>      * id: 1
>      * name: snap1
>      * state: poweredOff
>    * ### Vnc
>      * enabled: TRUE
>      * ip: 0.0.0.0
>      * password: VALUE_SPECIFIED_IN_NO_LOG_PARAMETER
>      * port: 5990

### vmware-host
***
Add, remove, or move an ESXi host to, from, or within vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_module.html


#### Base Command

`vmware-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter_name | Name of the datacenter to add the host. Aliases added in version 2.6. | Required | 
| cluster_name | Name of the cluster to add the host. If `folder` is not set, then this parameter is required. Aliases added in version 2.6. | Optional | 
| folder | Name of the folder under which host to add. If `cluster_name` is not set, then this parameter is required. For example, if there is a datacenter 'dc1' under folder called 'Site1' then, this value will be '/Site1/dc1/host'. Here 'host' is an invisible folder under VMware Web Client. Another example, if there is a nested folder structure like '/myhosts/india/pune' under datacenter 'dc2', then `folder` value will be '/dc2/host/myhosts/india/pune'. Other Examples: - '/Site2/dc2/Asia-Cluster/host' - '/dc3/Asia-Cluster/host'. | Optional | 
| add_connected | If set to `True`, then the host should be connected as soon as it is added. This parameter is ignored if state is set to a value other than `present`. Possible values are: Yes, No. Default is Yes. | Optional | 
| esxi_hostname | ESXi hostname to manage. | Required | 
| esxi_username | ESXi username. Required for adding a host. Optional for reconnect. If both `esxi_username` and `esxi_password` are used Unused for removing. No longer a required parameter from version 2.5. | Optional | 
| esxi_password | ESXi password. Required for adding a host. Optional for reconnect. Unused for removing. No longer a required parameter from version 2.5. | Optional | 
| state | If set to `present`, add the host if host is absent. If set to `present`, update the location of the host if host already exists. If set to `absent`, remove the host if host is present. If set to `absent`, do nothing if host already does not exists. If set to `add_or_reconnect`, add the host if it's absent else reconnect it and update the location. If set to `reconnect`, then reconnect the host if it's present and update the location. Possible values are: present, absent, add_or_reconnect, reconnect. Default is present. | Optional | 
| esxi_ssl_thumbprint | Specifying the hostsystem certificate's thumbprint. Use following command to get hostsystem certificate's thumbprint - # openssl x509 -in /etc/vmware/ssl/rui.crt -fingerprint -sha1 -noout Only used if `fetch_thumbprint` isn't set to `true`. | Optional | 
| fetch_ssl_thumbprint | Fetch the thumbprint of the host's SSL certificate. This basically disables the host certificate verification (check if it was signed by a recognized CA). Disable this option if you want to allow only hosts with valid certificates to be added to vCenter. If this option is set to `false` and the certificate can't be verified, an add or reconnect will fail. Unused when `esxi_ssl_thumbprint` is set. Optional for reconnect, but only used if `esxi_username` and `esxi_password` are used. Unused for removing. Possible values are: Yes, No. Default is Yes. | Optional | 
| force_connection | Force the connection if the host is already being managed by another vCenter server. Possible values are: Yes, No. Default is Yes. | Optional | 
| reconnect_disconnected | Reconnect disconnected hosts. This is only used if `state` is set to `present` and if the host already exists. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHost.result | string | metadata about the new host system added | 


#### Command Example
```!vmware-host datacenter_name="DC1" cluster_name="cluster" esxi_hostname="esxi01" esxi_username="root" esxi_password="PASSWORD" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHost": [
            {
                "changed": false,
                "result": "Host already connected to vCenter 'vcenter' in cluster 'cluster'",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * result: Host already connected to vCenter 'vcenter' in cluster 'cluster'


### vmware-host-acceptance
***
Manage the host acceptance level of an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_acceptance_module.html


#### Base Command

`vmware-host-acceptance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Acceptance level of all ESXi host system in the given cluster will be managed. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. Acceptance level of this ESXi host system will be managed. If `cluster_name` is not given, this parameter is required. | Optional | 
| state | Set or list acceptance level of the given ESXi host. If set to `list`, then will return current acceptance level of given host system/s. If set to `present`, then will set given acceptance level. Possible values are: list, present. Default is list. | Optional | 
| acceptance_level | Name of acceptance level. If set to `partner`, then accept only partner and VMware signed and certified VIBs. If set to `vmware_certified`, then accept only VIBs that are signed and certified by VMware. If set to `vmware_accepted`, then accept VIBs that have been accepted by VMware. If set to `community`, then accept all VIBs, even those that are not signed. Possible values are: community, partner, vmware_accepted, vmware_certified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostAcceptance.facts | unknown | dict with hostname as key and dict with acceptance level facts, error as value | 


#### Command Example
```!vmware-host-acceptance cluster_name="cluster" acceptance_level="community" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostAcceptance": [
            {
                "changed": true,
                "facts": {
                    "esxi01": {
                        "error": "NA",
                        "level": "community"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Facts
>    * ### esxi01
>      * error: NA
>      * level: community


### vmware-host-active-directory
***
Joins an ESXi host system to an Active Directory domain or leaves it
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_active_directory_module.html


#### Base Command

`vmware-host-active-directory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ad_domain | AD Domain to join. | Optional | 
| ad_user | Username for AD domain join. | Optional | 
| ad_password | Password for AD domain join. | Optional | 
| ad_state | Whether the ESXi host is joined to an AD domain or not. Possible values are: present, absent. Default is absent. | Optional | 
| esxi_hostname | Name of the host system to work with. This parameter is required if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. This parameter is required if `esxi_hostname` is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostActiveDirectory.results | unknown | metadata about host system's AD domain join state | 




### vmware-host-capability-info
***
Gathers info about an ESXi host's capability information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_capability_info_module.html


#### Base Command

`vmware-host-capability-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster from all host systems to be used for information gathering. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostCapabilityInfo.hosts_capability_info | unknown | metadata about host's capability info | 


#### Command Example
```!vmware-host-capability-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostCapabilityInfo": [
            {
                "changed": false,
                "hosts_capability_info": {
                    "esxi01": {
                        "accel3dSupported": false,
                        "backgroundSnapshotsSupported": false,
                        "checkpointFtCompatibilityIssues": [
                            "haAgentIssue",
                            "missingFTLoggingNic",
                            "missingVMotionNic"
                        ],
                        "checkpointFtSupported": false,
                        "cloneFromSnapshotSupported": true,
                        "cpuHwMmuSupported": true,
                        "cpuMemoryResourceConfigurationSupported": true,
                        "cryptoSupported": true,
                        "datastorePrincipalSupported": false,
                        "deltaDiskBackingsSupported": true,
                        "eightPlusHostVmfsSharedAccessSupported": true,
                        "encryptedVMotionSupported": true,
                        "encryptionCBRCSupported": false,
                        "encryptionChangeOnAddRemoveSupported": false,
                        "encryptionFaultToleranceSupported": false,
                        "encryptionHBRSupported": false,
                        "encryptionHotOperationSupported": false,
                        "encryptionMemorySaveSupported": false,
                        "encryptionRDMSupported": false,
                        "encryptionVFlashSupported": false,
                        "encryptionWithSnapshotsSupported": false,
                        "featureCapabilitiesSupported": true,
                        "firewallIpRulesSupported": true,
                        "ftCompatibilityIssues": [
                            "haAgentIssue",
                            "incompatibleCpu",
                            "missingFTLoggingNic",
                            "missingVMotionNic"
                        ],
                        "ftSupported": false,
                        "gatewayOnNicSupported": true,
                        "hbrNicSelectionSupported": true,
                        "highGuestMemSupported": true,
                        "hostAccessManagerSupported": true,
                        "interVMCommunicationThroughVMCISupported": false,
                        "ipmiSupported": true,
                        "iscsiSupported": true,
                        "latencySensitivitySupported": true,
                        "localSwapDatastoreSupported": true,
                        "loginBySSLThumbprintSupported": true,
                        "maintenanceModeSupported": true,
                        "markAsLocalSupported": true,
                        "markAsSsdSupported": true,
                        "maxHostRunningVms": 19,
                        "maxHostSupportedVcpus": 64,
                        "maxNumDisksSVMotion": 248,
                        "maxRegisteredVMs": 76,
                        "maxRunningVMs": 0,
                        "maxSupportedVMs": null,
                        "maxSupportedVcpus": null,
                        "maxVcpusPerFtVm": 4,
                        "messageBusProxySupported": true,
                        "multipleNetworkStackInstanceSupported": true,
                        "nestedHVSupported": true,
                        "nfs41Krb5iSupported": true,
                        "nfs41Supported": true,
                        "nfsSupported": true,
                        "nicTeamingSupported": true,
                        "oneKVolumeAPIsSupported": true,
                        "perVMNetworkTrafficShapingSupported": false,
                        "perVmSwapFiles": true,
                        "preAssignedPCIUnitNumbersSupported": true,
                        "provisioningNicSelectionSupported": true,
                        "rebootSupported": true,
                        "recordReplaySupported": false,
                        "recursiveResourcePoolsSupported": true,
                        "reliableMemoryAware": true,
                        "replayCompatibilityIssues": [],
                        "replayUnsupportedReason": "incompatibleCpu",
                        "restrictedSnapshotRelocateSupported": true,
                        "sanSupported": true,
                        "scaledScreenshotSupported": true,
                        "scheduledHardwareUpgradeSupported": true,
                        "screenshotSupported": true,
                        "servicePackageInfoSupported": true,
                        "shutdownSupported": true,
                        "smartCardAuthenticationSupported": true,
                        "smpFtCompatibilityIssues": [
                            "haAgentIssue",
                            "missingFTLoggingNic",
                            "missingVMotionNic"
                        ],
                        "smpFtSupported": false,
                        "snapshotRelayoutSupported": true,
                        "standbySupported": true,
                        "storageIORMSupported": true,
                        "storagePolicySupported": true,
                        "storageVMotionSupported": true,
                        "supportedVmfsMajorVersion": [
                            5,
                            6
                        ],
                        "suspendedRelocateSupported": true,
                        "tpmSupported": false,
                        "turnDiskLocatorLedSupported": true,
                        "unsharedSwapVMotionSupported": true,
                        "upitSupported": null,
                        "vFlashSupported": true,
                        "vPMCSupported": false,
                        "vStorageCapable": true,
                        "virtualExecUsageSupported": true,
                        "virtualVolumeDatastoreSupported": true,
                        "vlanTaggingSupported": true,
                        "vmDirectPathGen2Supported": false,
                        "vmDirectPathGen2UnsupportedReason": [
                            "hostNptIncompatibleHardware"
                        ],
                        "vmDirectPathGen2UnsupportedReasonExtended": null,
                        "vmfsDatastoreMountCapable": true,
                        "vmotionAcrossNetworkSupported": true,
                        "vmotionSupported": true,
                        "vmotionWithStorageVMotionSupported": true,
                        "vrNfcNicSelectionSupported": true,
                        "vsanSupported": true
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Capability_Info
>    * ### esxi01
>      * accel3dSupported: False
>      * backgroundSnapshotsSupported: False
>      * checkpointFtSupported: False
>      * cloneFromSnapshotSupported: True
>      * cpuHwMmuSupported: True
>      * cpuMemoryResourceConfigurationSupported: True
>      * cryptoSupported: True
>      * datastorePrincipalSupported: False
>      * deltaDiskBackingsSupported: True
>      * eightPlusHostVmfsSharedAccessSupported: True
>      * encryptedVMotionSupported: True
>      * encryptionCBRCSupported: False
>      * encryptionChangeOnAddRemoveSupported: False
>      * encryptionFaultToleranceSupported: False
>      * encryptionHBRSupported: False
>      * encryptionHotOperationSupported: False
>      * encryptionMemorySaveSupported: False
>      * encryptionRDMSupported: False
>      * encryptionVFlashSupported: False
>      * encryptionWithSnapshotsSupported: False
>      * featureCapabilitiesSupported: True
>      * firewallIpRulesSupported: True
>      * ftSupported: False
>      * gatewayOnNicSupported: True
>      * hbrNicSelectionSupported: True
>      * highGuestMemSupported: True
>      * hostAccessManagerSupported: True
>      * interVMCommunicationThroughVMCISupported: False
>      * ipmiSupported: True
>      * iscsiSupported: True
>      * latencySensitivitySupported: True
>      * localSwapDatastoreSupported: True
>      * loginBySSLThumbprintSupported: True
>      * maintenanceModeSupported: True
>      * markAsLocalSupported: True
>      * markAsSsdSupported: True
>      * maxHostRunningVms: 19
>      * maxHostSupportedVcpus: 64
>      * maxNumDisksSVMotion: 248
>      * maxRegisteredVMs: 76
>      * maxRunningVMs: 0
>      * maxSupportedVMs: None
>      * maxSupportedVcpus: None
>      * maxVcpusPerFtVm: 4
>      * messageBusProxySupported: True
>      * multipleNetworkStackInstanceSupported: True
>      * nestedHVSupported: True
>      * nfs41Krb5iSupported: True
>      * nfs41Supported: True
>      * nfsSupported: True
>      * nicTeamingSupported: True
>      * oneKVolumeAPIsSupported: True
>      * perVMNetworkTrafficShapingSupported: False
>      * perVmSwapFiles: True
>      * preAssignedPCIUnitNumbersSupported: True
>      * provisioningNicSelectionSupported: True
>      * rebootSupported: True
>      * recordReplaySupported: False
>      * recursiveResourcePoolsSupported: True
>      * reliableMemoryAware: True
>      * replayUnsupportedReason: incompatibleCpu
>      * restrictedSnapshotRelocateSupported: True
>      * sanSupported: True
>      * scaledScreenshotSupported: True
>      * scheduledHardwareUpgradeSupported: True
>      * screenshotSupported: True
>      * servicePackageInfoSupported: True
>      * shutdownSupported: True
>      * smartCardAuthenticationSupported: True
>      * smpFtSupported: False
>      * snapshotRelayoutSupported: True
>      * standbySupported: True
>      * storageIORMSupported: True
>      * storagePolicySupported: True
>      * storageVMotionSupported: True
>      * suspendedRelocateSupported: True
>      * tpmSupported: False
>      * turnDiskLocatorLedSupported: True
>      * unsharedSwapVMotionSupported: True
>      * upitSupported: None
>      * vFlashSupported: True
>      * vPMCSupported: False
>      * vStorageCapable: True
>      * virtualExecUsageSupported: True
>      * virtualVolumeDatastoreSupported: True
>      * vlanTaggingSupported: True
>      * vmDirectPathGen2Supported: False
>      * vmDirectPathGen2UnsupportedReasonExtended: None
>      * vmfsDatastoreMountCapable: True
>      * vmotionAcrossNetworkSupported: True
>      * vmotionSupported: True
>      * vmotionWithStorageVMotionSupported: True
>      * vrNfcNicSelectionSupported: True
>      * vsanSupported: True
>      * #### Checkpointftcompatibilityissues
>        * 0: haAgentIssue
>        * 1: missingFTLoggingNic
>        * 2: missingVMotionNic
>      * #### Ftcompatibilityissues
>        * 0: haAgentIssue
>        * 1: incompatibleCpu
>        * 2: missingFTLoggingNic
>        * 3: missingVMotionNic
>      * #### Replaycompatibilityissues
>      * #### Smpftcompatibilityissues
>        * 0: haAgentIssue
>        * 1: missingFTLoggingNic
>        * 2: missingVMotionNic
>      * #### Supportedvmfsmajorversion
>        * 0: 5
>        * 1: 6
>      * #### Vmdirectpathgen2Unsupportedreason
>        * 0: hostNptIncompatibleHardware


### vmware-host-config-info
***
Gathers info about an ESXi host's advance configuration information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_config_info_module.html


#### Base Command

`vmware-host-config-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster from which the ESXi host belong to. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostConfigInfo.hosts_info | unknown | dict with hostname as key and dict with host config information | 


#### Command Example
```!vmware-host-config-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostConfigInfo": [
            {
                "changed": false,
                "hosts_info": {
                    "esxi01": {
                        "Annotations.WelcomeMessage": "",
                        "BufferCache.FlushInterval": 30000,
                        "BufferCache.HardMaxDirty": 95,
                        "BufferCache.PerFileHardMaxDirty": 50,
                        "BufferCache.SoftMaxDirty": 15,
                        "CBRC.DCacheMemReserved": 400,
                        "CBRC.DCacheSize": 32768,
                        "CBRC.DigestJournalBootInterval": 10,
                        "CBRC.Enable": false,
                        "COW.COWMaxHeapSizeMB": 192,
                        "COW.COWMaxREPageCacheszMB": 256,
                        "COW.COWMinREPageCacheszMB": 0,
                        "COW.COWREPageCacheEviction": 1,
                        "Config.Defaults.cpuidMask.mode.0.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.0.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.0.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.0.edx": "disable",
                        "Config.Defaults.cpuidMask.mode.1.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.1.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.1.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.1.edx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000000.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.80000000.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000000.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000000.edx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000001.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.80000001.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000001.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000001.edx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000008.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.80000008.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000008.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.80000008.edx": "disable",
                        "Config.Defaults.cpuidMask.mode.8000000A.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.8000000A.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.8000000A.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.8000000A.edx": "disable",
                        "Config.Defaults.cpuidMask.mode.d.eax": "disable",
                        "Config.Defaults.cpuidMask.mode.d.ebx": "disable",
                        "Config.Defaults.cpuidMask.mode.d.ecx": "disable",
                        "Config.Defaults.cpuidMask.mode.d.edx": "disable",
                        "Config.Defaults.cpuidMask.val.0.eax": "",
                        "Config.Defaults.cpuidMask.val.0.ebx": "",
                        "Config.Defaults.cpuidMask.val.0.ecx": "",
                        "Config.Defaults.cpuidMask.val.0.edx": "",
                        "Config.Defaults.cpuidMask.val.1.eax": "",
                        "Config.Defaults.cpuidMask.val.1.ebx": "",
                        "Config.Defaults.cpuidMask.val.1.ecx": "",
                        "Config.Defaults.cpuidMask.val.1.edx": "",
                        "Config.Defaults.cpuidMask.val.80000000.eax": "",
                        "Config.Defaults.cpuidMask.val.80000000.ebx": "",
                        "Config.Defaults.cpuidMask.val.80000000.ecx": "",
                        "Config.Defaults.cpuidMask.val.80000000.edx": "",
                        "Config.Defaults.cpuidMask.val.80000001.eax": "",
                        "Config.Defaults.cpuidMask.val.80000001.ebx": "",
                        "Config.Defaults.cpuidMask.val.80000001.ecx": "",
                        "Config.Defaults.cpuidMask.val.80000001.edx": "",
                        "Config.Defaults.cpuidMask.val.80000008.eax": "",
                        "Config.Defaults.cpuidMask.val.80000008.ebx": "",
                        "Config.Defaults.cpuidMask.val.80000008.ecx": "",
                        "Config.Defaults.cpuidMask.val.80000008.edx": "",
                        "Config.Defaults.cpuidMask.val.8000000A.eax": "",
                        "Config.Defaults.cpuidMask.val.8000000A.ebx": "",
                        "Config.Defaults.cpuidMask.val.8000000A.ecx": "",
                        "Config.Defaults.cpuidMask.val.8000000A.edx": "",
                        "Config.Defaults.cpuidMask.val.d.eax": "",
                        "Config.Defaults.cpuidMask.val.d.ebx": "",
                        "Config.Defaults.cpuidMask.val.d.ecx": "",
                        "Config.Defaults.cpuidMask.val.d.edx": "",
                        "Config.Defaults.security.host.ruissl": true,
                        "Config.Defaults.vGPU.consolidation": false,
                        "Config.Etc.issue": "",
                        "Config.Etc.motd": "The time and date of this login have been sent to the system logs.\n\nWARNING:\n   All commands run on the ESXi shell are logged and may be included in\n   support bundles. Do not provide passwords directly on the command line.\n   Most tools can prompt for secrets or accept them from standard input.\n\n%1b[00mVMware offers supported, powerful system administration tools.  Please\nsee www.vmware.com/go/sysadmintools for details.\n\nThe ESXi Shell can be disabled by an administrative user. See the\nvSphere Security documentation for more information.\n",
                        "Config.GlobalSettings.guest.commands.sharedPolicyRefCount": 0,
                        "Config.HostAgent.level[Hbrsvc].logLevel": "",
                        "Config.HostAgent.level[Hostsvc].logLevel": "",
                        "Config.HostAgent.level[Proxysvc].logLevel": "",
                        "Config.HostAgent.level[Snmpsvc].logLevel": "",
                        "Config.HostAgent.level[Statssvc].logLevel": "",
                        "Config.HostAgent.level[Vcsvc].logLevel": "",
                        "Config.HostAgent.level[Vimsvc].logLevel": "",
                        "Config.HostAgent.level[Vmsvc].logLevel": "",
                        "Config.HostAgent.log.level": "info",
                        "Config.HostAgent.plugins.hostsvc.esxAdminsGroup": "ESX Admins",
                        "Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd": true,
                        "Config.HostAgent.plugins.hostsvc.esxAdminsGroupUpdateInterval": 1,
                        "Config.HostAgent.plugins.solo.enableMob": false,
                        "Config.HostAgent.plugins.solo.webServer.enableWebscriptLauncher": true,
                        "Config.HostAgent.plugins.vimsvc.authValidateInterval": 1440,
                        "Config.HostAgent.plugins.vimsvc.userSearch.maxResults": 100,
                        "Config.HostAgent.plugins.vimsvc.userSearch.maxTimeSeconds": 20,
                        "Config.HostAgent.plugins.vmsvc.enforceMaxRegisteredVms": true,
                        "Config.HostAgent.plugins.vmsvc.productLockerWatchInterval": 300,
                        "Cpu.ActionLoadThreshold": 10,
                        "Cpu.AllowWideVsmp": 0,
                        "Cpu.BoundLagQuanta": 8,
                        "Cpu.CommRateThreshold": 500,
                        "Cpu.CoschedCostartThreshold": 2000,
                        "Cpu.CoschedCostopThreshold": 3000,
                        "Cpu.CoschedCrossCall": 1,
                        "Cpu.CoschedExclusiveAffinity": 0,
                        "Cpu.CoschedHandoffLLC": 1,
                        "Cpu.CoschedHandoffSkip": 10,
                        "Cpu.CoschedPollUsec": 1000,
                        "Cpu.CreditAgePeriod": 3000,
                        "Cpu.FairnessRebalancePcpus": 4,
                        "Cpu.HTRebalancePeriod": 5,
                        "Cpu.HTStolenAgeThreshold": 8,
                        "Cpu.HTWholeCoreThreshold": 800,
                        "Cpu.HostRebalancePeriod": 100,
                        "Cpu.L2RebalancePeriod": 10,
                        "Cpu.L3RebalancePeriod": 20,
                        "Cpu.LimitEnforcementThreshold": 200,
                        "Cpu.MaxSampleRateLg": 7,
                        "Cpu.MoveCurrentRunnerPcpus": 4,
                        "Cpu.NonTimerWakeupRate": 500,
                        "Cpu.PackageRebalancePeriod": 20,
                        "Cpu.PcpuMigrateIdlePcpus": 4,
                        "Cpu.Quantum": 200,
                        "Cpu.UseMwait": 2,
                        "Cpu.VMAdmitCheckPerVcpuMin": 1,
                        "Cpu.WakeupMigrateIdlePcpus": 4,
                        "DCUI.Access": "root",
                        "DataMover.HardwareAcceleratedInit": 1,
                        "DataMover.HardwareAcceleratedMove": 1,
                        "DataMover.MaxHeapSize": 64,
                        "Digest.AlgoType": 1,
                        "Digest.BlockSize": 1,
                        "Digest.CollisionEnabled": 0,
                        "Digest.JournalCoverage": 8,
                        "Digest.UpdateOnClose": 0,
                        "DirentryCache.MaxDentryPerObj": 15000,
                        "Disk.AllowUsbClaimedAsSSD": 0,
                        "Disk.ApdTokenRetryCount": 25,
                        "Disk.AutoremoveOnPDL": 1,
                        "Disk.BandwidthCap": 4294967294,
                        "Disk.DelayOnBusy": 400,
                        "Disk.DeviceReclaimTime": 300,
                        "Disk.DisableVSCSIPollInBH": 1,
                        "Disk.DiskDelayPDLHelper": 10,
                        "Disk.DiskMaxIOSize": 32767,
                        "Disk.DiskReservationThreshold": 45,
                        "Disk.DiskRetryPeriod": 2000,
                        "Disk.DumpMaxRetries": 10,
                        "Disk.DumpPollDelay": 1000,
                        "Disk.DumpPollMaxRetries": 10000,
                        "Disk.EnableNaviReg": 1,
                        "Disk.FailDiskRegistration": 0,
                        "Disk.FastPathRestoreInterval": 100,
                        "Disk.IdleCredit": 32,
                        "Disk.MaxLUN": 1024,
                        "Disk.MaxResetLatency": 2000,
                        "Disk.NmpMaxCmdExtension": 0,
                        "Disk.PathEvalTime": 300,
                        "Disk.PreventVMFSOverwrite": 1,
                        "Disk.QFullSampleSize": 0,
                        "Disk.QFullThreshold": 8,
                        "Disk.ReqCallThreshold": 8,
                        "Disk.ResetLatency": 1000,
                        "Disk.ResetMaxRetries": 0,
                        "Disk.ResetOverdueLogPeriod": 60,
                        "Disk.ResetPeriod": 30,
                        "Disk.ResetThreadExpires": 1800,
                        "Disk.ResetThreadMax": 16,
                        "Disk.ResetThreadMin": 1,
                        "Disk.RetryUnitAttention": 1,
                        "Disk.ReturnCCForNoSpace": 0,
                        "Disk.SchedCostUnit": 32768,
                        "Disk.SchedQCleanupInterval": 300,
                        "Disk.SchedQControlSeqReqs": 128,
                        "Disk.SchedQControlVMSwitches": 6,
                        "Disk.SchedQPriorityPercentage": 80,
                        "Disk.SchedQuantum": 8,
                        "Disk.SchedReservationBurst": 1,
                        "Disk.SchedulerWithReservation": 1,
                        "Disk.SectorMaxDiff": 2000,
                        "Disk.SharesHigh": 2000,
                        "Disk.SharesLow": 500,
                        "Disk.SharesNormal": 1000,
                        "Disk.SupportSparseLUN": 1,
                        "Disk.ThroughputCap": 4294967294,
                        "Disk.UseDeviceReset": 1,
                        "Disk.UseIOWorlds": 1,
                        "Disk.UseIoPool": 0,
                        "Disk.UseLunReset": 1,
                        "Disk.UseReportLUN": 1,
                        "Disk.VSCSICoalesceCount": 1000,
                        "Disk.VSCSIPollPeriod": 1000,
                        "Disk.VSCSIResvCmdRetryInSecs": 1,
                        "Disk.VSCSIWriteSameBurstSize": 4,
                        "FSS.FSSLightWeightProbe": 1,
                        "FT.AckIntervalMax": 1000000,
                        "FT.AckIntervalMin": 0,
                        "FT.BackupConnectTimeout": 8000,
                        "FT.BackupExtraTimeout": 100,
                        "FT.BadExecLatency": 800,
                        "FT.BindToVmknic": 0,
                        "FT.ChargeVMXForFlush": 1,
                        "FT.CheckFCPathState": 1,
                        "FT.CheckForProgress": 0,
                        "FT.CoreDumpNoProgressMS": 0,
                        "FT.ExecLatencyKill": 0,
                        "FT.ExtraLogTimeout": 10000,
                        "FT.FTCptConcurrentSend": 1,
                        "FT.FTCptDelayCheckpoint": 2,
                        "FT.FTCptDiffCap": 100,
                        "FT.FTCptDiffThreads": 6,
                        "FT.FTCptDisableFailover": 0,
                        "FT.FTCptDiskWriteTimeout": 3000,
                        "FT.FTCptDontDelayPkts": 0,
                        "FT.FTCptDontSendPages": 0,
                        "FT.FTCptEpochList": "5,10,20,100",
                        "FT.FTCptEpochSample": 1000,
                        "FT.FTCptEpochWait": 8000,
                        "FT.FTCptIORetryExtraInterval": 200,
                        "FT.FTCptIORetryInterval": 10,
                        "FT.FTCptIORetryTimes": 15,
                        "FT.FTCptLogTimeout": 8000,
                        "FT.FTCptMaxPktsDelay": 0,
                        "FT.FTCptMinInterval": 4,
                        "FT.FTCptNetDelayNoCpt": 0,
                        "FT.FTCptNumConnections": 2,
                        "FT.FTCptNumaIndex": 0,
                        "FT.FTCptPagePolicy": 65538,
                        "FT.FTCptPoweroff": 0,
                        "FT.FTCptRcvBufSize": 562140,
                        "FT.FTCptSndBufSize": 562140,
                        "FT.FTCptStartTimeout": 90000,
                        "FT.FTCptStatsInterval": 30,
                        "FT.FTCptThreadPolicy": 65536,
                        "FT.FTCptVcpuMinUsage": 40,
                        "FT.FTCptWaitOnSocket": 1,
                        "FT.FillAffinity": 1,
                        "FT.FillWorldlet": 1,
                        "FT.FlushReservationMax": 25,
                        "FT.FlushReservationMin": 5,
                        "FT.FlushSleep": 0,
                        "FT.FlushWorldlet": 1,
                        "FT.GlobalFlushWorld": 0,
                        "FT.GoodExecLatency": 200,
                        "FT.HeartbeatCount": 10,
                        "FT.HostTimeout": 2000,
                        "FT.IORetryExtraInterval": 200,
                        "FT.IORetryInterval": 10,
                        "FT.IORetryTimes": 15,
                        "FT.LogBufferStallSleep": 1,
                        "FT.LogTimeout": 8000,
                        "FT.LongFlushDebugMS": 500,
                        "FT.MaxFlushInterval": 0,
                        "FT.MinWriteSize": 0,
                        "FT.NoWaitOnSocket": 0,
                        "FT.PanicNoProgressMS": 0,
                        "FT.PrimaryConnectTimeout": 8000,
                        "FT.ShortFlushDebugMS": 100,
                        "FT.TCPNoDelayBackup": 1,
                        "FT.TCPNoDelayPrimary": 1,
                        "FT.TCPPersistTimer": 500,
                        "FT.TCPRcvBufSize": 131072,
                        "FT.TCPSndBufSize": 131072,
                        "FT.UseHostMonitor": 0,
                        "FT.Vmknic": "",
                        "FT.XmitSyncQueueLen": 64,
                        "FT.adjDownInt": 10,
                        "FT.adjDownPct": 10,
                        "FT.adjUpInt": 200,
                        "FT.adjUpPct": 10,
                        "FT.execLatExtra": 500,
                        "FT.maxLowerBound": 20,
                        "FT.slowdownPctMax": 60,
                        "FT.slowdownTimeMax": 600,
                        "HBR.ChecksumIoSize": 8,
                        "HBR.ChecksumMaxIo": 8,
                        "HBR.ChecksumPerSlice": 2,
                        "HBR.ChecksumRegionSize": 256,
                        "HBR.ChecksumUseAllocInfo": 1,
                        "HBR.ChecksumUseChecksumInfo": 1,
                        "HBR.ChecksumZoneSize": 32768,
                        "HBR.CopySnapDiskMaxExtentCount": 16,
                        "HBR.CopySnapFidHashBuckets": 256,
                        "HBR.DemandlogCompletedHashBuckets": 8,
                        "HBR.DemandlogExtentHashBuckets": 512,
                        "HBR.DemandlogIoTimeoutSecs": 120,
                        "HBR.DemandlogReadRetries": 20,
                        "HBR.DemandlogRetryDelayMs": 10,
                        "HBR.DemandlogSendHashBuckets": 8,
                        "HBR.DemandlogTransferIoSize": 8,
                        "HBR.DemandlogTransferMaxIo": 4,
                        "HBR.DemandlogTransferMaxNetwork": 8,
                        "HBR.DemandlogTransferPerSlice": 2,
                        "HBR.DemandlogWriteRetries": 20,
                        "HBR.DisableChecksumOffload": 0,
                        "HBR.DisconnectedEventDelayMs": 60000,
                        "HBR.ErrThrottleChecksumIO": 1,
                        "HBR.ErrThrottleDceRead": 1,
                        "HBR.HbrBitmapAllocTimeoutMS": 3000,
                        "HBR.HbrBitmapVMMaxStorageGB": 65536,
                        "HBR.HbrBitmapVMMinStorageGB": 500,
                        "HBR.HbrDemandLogIOPerVM": 64,
                        "HBR.HbrDisableNetCompression": 1,
                        "HBR.HbrLowerExtentBreakGB": 8192,
                        "HBR.HbrLowerExtentSizeKB": 16,
                        "HBR.HbrMaxExtentSizeKB": 64,
                        "HBR.HbrMaxGuestXferWhileDeltaMB": 1024,
                        "HBR.HbrMaxUnmapExtents": 10,
                        "HBR.HbrMaxUnmapsInFlight": 128,
                        "HBR.HbrMinExtentBreakGB": 2048,
                        "HBR.HbrMinExtentSizeKB": 8,
                        "HBR.HbrOptimizeFullSync": 1,
                        "HBR.HbrResourceHeapPerVMSizeKB": 128,
                        "HBR.HbrResourceHeapSizeMB": 2,
                        "HBR.HbrResourceHeapUtilization": 95,
                        "HBR.HbrResourceMaxDiskContexts": 512,
                        "HBR.HbrRuntimeHeapMaxBaseMB": 1,
                        "HBR.HbrRuntimeHeapMinBaseMB": 1,
                        "HBR.HbrStaticHeapMaxBaseMB": 1,
                        "HBR.HbrStaticHeapMinBaseMB": 1,
                        "HBR.HbrUpperExtentBreakGB": 32768,
                        "HBR.HbrUpperExtentSizeKB": 32,
                        "HBR.HelperQueueMaxRequests": 8192,
                        "HBR.HelperQueueMaxWorlds": 8,
                        "HBR.LocalReadIoTimeoutSecs": 120,
                        "HBR.MigrateFlushTimerSecs": 3,
                        "HBR.NetworkUseCubic": 1,
                        "HBR.NetworkerRecvHashBuckets": 64,
                        "HBR.OpportunisticBlockListSize": 4000,
                        "HBR.ProgressReportIntervalMs": 5000,
                        "HBR.PsfIoTimeoutSecs": 300,
                        "HBR.ReconnectFailureDelaySecs": 10,
                        "HBR.ReconnectMaxDelaySecs": 90,
                        "HBR.ResourceServerHashBuckets": 8,
                        "HBR.RetryMaxDelaySecs": 60,
                        "HBR.RetryMinDelaySecs": 1,
                        "HBR.SyncTransferRetrySleepSecs": 5,
                        "HBR.TransferDiskMaxIo": 32,
                        "HBR.TransferDiskMaxNetwork": 64,
                        "HBR.TransferDiskPerSlice": 16,
                        "HBR.TransferFileExtentSize": 8192,
                        "HBR.TransferMaxContExtents": 8,
                        "HBR.WireChecksum": 1,
                        "HBR.XferBitmapCheckIntervalSecs": 10,
                        "ISCSI.MaxIoSizeKB": 128,
                        "Irq.BestVcpuRouting": 0,
                        "Irq.IRQActionAffinityWeight": 5,
                        "Irq.IRQAvoidExclusive": 1,
                        "Irq.IRQBHConflictWeight": 5,
                        "Irq.IRQRebalancePeriod": 50,
                        "Irq.IRQVcpuConflictWeight": 3,
                        "LPage.LPageAlwaysTryForNPT": 1,
                        "LPage.LPageDefragEnable": 1,
                        "LPage.LPageMarkLowNodes": 1,
                        "LPage.MaxSharedPages": 512,
                        "LPage.MaxSwappedPagesInitVal": 10,
                        "LPage.freePagesThresholdForRemote": 2048,
                        "LSOM.blkAttrCacheSizePercent": 0,
                        "Mem.AllocGuestLargePage": 1,
                        "Mem.CtlMaxPercent": 65,
                        "Mem.IdleTax": 75,
                        "Mem.IdleTaxType": 1,
                        "Mem.MemDefragClientsPerDir": 2,
                        "Mem.MemMinFreePct": 0,
                        "Mem.MemZipEnable": 1,
                        "Mem.MemZipMaxAllocPct": 50,
                        "Mem.MemZipMaxPct": 10,
                        "Mem.SampleActivePctMin": 1,
                        "Mem.SampleDirtiedPctMin": 0,
                        "Mem.ShareForceSalting": 2,
                        "Mem.ShareRateMax": 1024,
                        "Mem.ShareScanGHz": 4,
                        "Mem.ShareScanTime": 60,
                        "Mem.VMOverheadGrowthLimit": 4294967295,
                        "Migrate.AutoBindVmknic": 1,
                        "Migrate.BindToVmknic": 3,
                        "Migrate.CptCacheMaxSizeMB": 544,
                        "Migrate.DebugChecksumMismatch": 0,
                        "Migrate.DetectZeroPages": 1,
                        "Migrate.DisableResumeDuringPageIn": 0,
                        "Migrate.DiskOpsChunkSize": 131072,
                        "Migrate.DiskOpsEnabled": 0,
                        "Migrate.DiskOpsMaxRetries": 20,
                        "Migrate.DiskOpsStreamChunks": 40,
                        "Migrate.Enabled": 1,
                        "Migrate.GetPageSysAlertThresholdMS": 10000,
                        "Migrate.LowBandwidthSysAlertThreshold": 0,
                        "Migrate.LowMemWaitSysAlertThresholdMS": 10000,
                        "Migrate.MigrateCpuMinPctDefault": 30,
                        "Migrate.MigrateCpuPctPerGb": 10,
                        "Migrate.MigrateCpuSharesHighPriority": 60000,
                        "Migrate.MigrateCpuSharesRegular": 30000,
                        "Migrate.MonActionWaitSysAlertThresholdMS": 2000,
                        "Migrate.NetExpectedLineRateMBps": 133,
                        "Migrate.NetLatencyModeThreshold": 4,
                        "Migrate.NetTimeout": 20,
                        "Migrate.OutstandingReadKBMax": 128,
                        "Migrate.PanicOnChecksumMismatch": 0,
                        "Migrate.PreCopyCountDelay": 10,
                        "Migrate.PreCopyMinProgressPerc": 130,
                        "Migrate.PreCopyPagesPerSend": 32,
                        "Migrate.PreCopySwitchoverTimeGoal": 500,
                        "Migrate.PreallocLPages": 1,
                        "Migrate.ProhibitFork": 0,
                        "Migrate.RcvBufSize": 562540,
                        "Migrate.RdpiTransitionTimeMs": 1,
                        "Migrate.SdpsDynamicDelaySec": 30,
                        "Migrate.SdpsEnabled": 2,
                        "Migrate.SdpsTargetRate": 500,
                        "Migrate.SndBufSize": 562540,
                        "Migrate.TSMaster": 0,
                        "Migrate.TcpTsoDeferTx": 0,
                        "Migrate.TryToUseDefaultHeap": 1,
                        "Migrate.VASpaceReserveCount": 128,
                        "Migrate.VASpaceReserveSize": 768,
                        "Migrate.VMotionLatencySensitivity": 1,
                        "Migrate.VMotionResolveSwapType": 1,
                        "Migrate.VMotionStreamDisable": 0,
                        "Migrate.VMotionStreamHelpers": 0,
                        "Migrate.Vmknic": "",
                        "Misc.APDHandlingEnable": 1,
                        "Misc.APDTimeout": 140,
                        "Misc.BHTimeout": 0,
                        "Misc.BhTimeBound": 2000,
                        "Misc.BlueScreenTimeout": 0,
                        "Misc.ConsolePort": "none",
                        "Misc.DebugBuddyEnable": 0,
                        "Misc.DebugLogToSerial": 0,
                        "Misc.DefaultHardwareVersion": "",
                        "Misc.DsNsMgrTimeout": 1200000,
                        "Misc.EnableHighDMA": 1,
                        "Misc.GDBPort": "none",
                        "Misc.GuestLibAllowHostInfo": 0,
                        "Misc.HeapMgrGuardPages": 1,
                        "Misc.HeapPanicDestroyNonEmpty": 0,
                        "Misc.HeartbeatInterval": 1000,
                        "Misc.HeartbeatPanicTimeout": 900,
                        "Misc.HeartbeatTimeout": 90,
                        "Misc.HordeEnabled": 0,
                        "Misc.HostAgentUpdateLevel": "3",
                        "Misc.IntTimeout": 0,
                        "Misc.IoFilterWatchdogTimeout": 120,
                        "Misc.LogPort": "none",
                        "Misc.LogTimestampUptime": 0,
                        "Misc.LogToFile": 1,
                        "Misc.LogToSerial": 1,
                        "Misc.LogWldPrefix": 1,
                        "Misc.MCEMonitorInterval": 250,
                        "Misc.MetadataUpdateTimeoutMsec": 30000,
                        "Misc.MinimalPanic": 0,
                        "Misc.NMILint1IntAction": 0,
                        "Misc.PowerButton": 1,
                        "Misc.PowerOffEnable": 1,
                        "Misc.PreferredHostName": "",
                        "Misc.ProcVerbose": "",
                        "Misc.SIOControlFlag1": 0,
                        "Misc.SIOControlFlag2": 0,
                        "Misc.SIOControlLoglevel": 0,
                        "Misc.SIOControlOptions": "",
                        "Misc.ScreenSaverDelay": 0,
                        "Misc.ShaperStatsEnabled": 1,
                        "Misc.ShellPort": "none",
                        "Misc.TimerMaxHardPeriod": 500000,
                        "Misc.TimerTolerance": 2000,
                        "Misc.UsbArbitratorAutoStartDisabled": 0,
                        "Misc.UserDuctDynBufferSize": 16384,
                        "Misc.UserSocketUnixMaxBufferSize": 65536,
                        "Misc.WatchdogBacktrace": 0,
                        "Misc.WorldletActivationUS": 500,
                        "Misc.WorldletActivationsLimit": 8,
                        "Misc.WorldletGreedySampleMCycles": 10,
                        "Misc.WorldletGreedySampleRun": 256,
                        "Misc.WorldletIRQPenalty": 10,
                        "Misc.WorldletLoadThreshold": 90,
                        "Misc.WorldletLoadType": "medium",
                        "Misc.WorldletLocalityBonus": 10,
                        "Misc.WorldletLoosePenalty": 30,
                        "Misc.WorldletMigOverheadLLC": 4,
                        "Misc.WorldletMigOverheadRemote": 16,
                        "Misc.WorldletPreemptOverhead": 30,
                        "Misc.WorldletRemoteActivateOverhead": 0,
                        "Misc.WorldletWorldOverheadLLC": 0,
                        "Misc.WorldletWorldOverheadRemote": 10,
                        "Misc.vmmDisableL1DFlush": 0,
                        "Misc.vsanWitnessVirtualAppliance": 0,
                        "NFS.ApdStartCount": 3,
                        "NFS.DiskFileLockUpdateFreq": 10,
                        "NFS.HeartbeatDelta": 5,
                        "NFS.HeartbeatFrequency": 12,
                        "NFS.HeartbeatMaxFailures": 10,
                        "NFS.HeartbeatTimeout": 5,
                        "NFS.LockRenewMaxFailureNumber": 3,
                        "NFS.LockUpdateTimeout": 5,
                        "NFS.LogNfsStat3": 0,
                        "NFS.MaxQueueDepth": 4294967295,
                        "NFS.MaxVolumes": 8,
                        "NFS.ReceiveBufferSize": 1024,
                        "NFS.SendBufferSize": 1024,
                        "NFS.SyncRetries": 25,
                        "NFS.VolumeRemountFrequency": 30,
                        "NFS41.EOSDelay": 30,
                        "NFS41.IOTaskRetry": 25,
                        "NFS41.MaxRead": 4294967295,
                        "NFS41.MaxVolumes": 8,
                        "NFS41.MaxWrite": 4294967295,
                        "NFS41.MountTimeout": 30,
                        "NFS41.RecvBufSize": 1024,
                        "NFS41.SendBufSize": 1024,
                        "Net.AdvertisementDuration": 60,
                        "Net.AllowPT": 1,
                        "Net.BlockGuestBPDU": 0,
                        "Net.CoalesceDefaultOn": 1,
                        "Net.CoalesceFavorNoVmmVmkTx": 1,
                        "Net.CoalesceFineTimeoutCPU": 2,
                        "Net.CoalesceFineTxTimeout": 1000,
                        "Net.CoalesceFlexMrq": 1,
                        "Net.CoalesceLowRxRate": 4,
                        "Net.CoalesceLowTxRate": 4,
                        "Net.CoalesceMatchedQs": 1,
                        "Net.CoalesceMrqLt": 1,
                        "Net.CoalesceMrqMetricAllowTxOnly": 1,
                        "Net.CoalesceMrqMetricRxOnly": 0,
                        "Net.CoalesceMrqOverallStop": 0,
                        "Net.CoalesceMrqRatioMetric": 1,
                        "Net.CoalesceMrqTriggerReCalib": 1,
                        "Net.CoalesceMultiRxQCalib": 1,
                        "Net.CoalesceNoVmmVmkTx": 1,
                        "Net.CoalesceParams": "",
                        "Net.CoalesceRBCRate": 4000,
                        "Net.CoalesceRxLtStopCalib": 0,
                        "Net.CoalesceRxQDepthCap": 40,
                        "Net.CoalesceScheme": "rbc",
                        "Net.CoalesceTimeoutType": 2,
                        "Net.CoalesceTxAlwaysPoll": 1,
                        "Net.CoalesceTxQDepthCap": 40,
                        "Net.CoalesceTxTimeout": 4000,
                        "Net.DCBEnable": 1,
                        "Net.DVFilterBindIpAddress": "",
                        "Net.DVFilterPriorityRdLockEnable": 1,
                        "Net.DVSLargeHeapMaxSize": 80,
                        "Net.DontOffloadInnerIPv6": 0,
                        "Net.E1000IntrCoalesce": 1,
                        "Net.E1000TxCopySize": 2048,
                        "Net.E1000TxZeroCopy": 1,
                        "Net.EnableDMASgCons": 1,
                        "Net.EnableOuterCsum": 1,
                        "Net.EtherswitchAllowFastPath": 0,
                        "Net.EtherswitchHashSize": 1,
                        "Net.EtherswitchHeapMax": 512,
                        "Net.EtherswitchNumPerPCPUDispatchData": 3,
                        "Net.FollowHardwareMac": 1,
                        "Net.GuestIPHack": 0,
                        "Net.GuestTxCopyBreak": 64,
                        "Net.IGMPQueries": 2,
                        "Net.IGMPQueryInterval": 125,
                        "Net.IGMPRouterIP": "0.0.0.0",
                        "Net.IGMPV3MaxSrcIPNum": 10,
                        "Net.IGMPVersion": 3,
                        "Net.IOControlPnicOptOut": "",
                        "Net.LRODefBackoffPeriod": 8,
                        "Net.LRODefMaxLength": 65535,
                        "Net.LRODefThreshold": 4000,
                        "Net.LRODefUseRatioDenom": 3,
                        "Net.LRODefUseRatioNumer": 1,
                        "Net.LinkFlappingThreshold": 60,
                        "Net.LinkStatePollTimeout": 500,
                        "Net.MLDRouterIP": "FE80::FFFF:FFFF:FFFF:FFFF",
                        "Net.MLDV2MaxSrcIPNum": 10,
                        "Net.MLDVersion": 2,
                        "Net.MaxBeaconVlans": 100,
                        "Net.MaxBeaconsAtOnce": 100,
                        "Net.MaxGlobalRxQueueCount": 100000,
                        "Net.MaxNetifTxQueueLen": 2000,
                        "Net.MaxPageInQueueLen": 75,
                        "Net.MaxPktRxListQueue": 3500,
                        "Net.MaxPortRxQueueLen": 80,
                        "Net.MinEtherLen": 60,
                        "Net.NcpLlcSap": 0,
                        "Net.NetBHRxStormThreshold": 320,
                        "Net.NetDebugRARPTimerInter": 30000,
                        "Net.NetDeferTxCompletion": 1,
                        "Net.NetDiscUpdateIntrvl": 300,
                        "Net.NetEnableSwCsumForLro": 1,
                        "Net.NetEsxfwPassOutboundGRE": 1,
                        "Net.NetInStressTest": 0,
                        "Net.NetLatencyAwareness": 1,
                        "Net.NetMaxRarpsPerInterval": 128,
                        "Net.NetNetqMaxDefQueueFilters": 4096,
                        "Net.NetNetqNumaIOCpuPinThreshold": 0,
                        "Net.NetNetqRxRebalRSSLoadThresholdPerc": 10,
                        "Net.NetNetqTxPackKpps": 300,
                        "Net.NetNetqTxUnpackKpps": 600,
                        "Net.NetNiocAllowOverCommit": 1,
                        "Net.NetPTMgrWakeupInterval": 6,
                        "Net.NetPktAllocTries": 5,
                        "Net.NetPktSlabFreePercentThreshold": 2,
                        "Net.NetPortFlushIterLimit": 2,
                        "Net.NetPortFlushPktLimit": 64,
                        "Net.NetPortTrackTxRace": 0,
                        "Net.NetRmDistMacFilter": 1,
                        "Net.NetRmDistSamplingRate": 0,
                        "Net.NetRxCopyInTx": 0,
                        "Net.NetSchedCoalesceTxUsecs": 33,
                        "Net.NetSchedDefaultResPoolSharesPct": 5,
                        "Net.NetSchedDefaultSchedName": "fifo",
                        "Net.NetSchedECNEnabled": 1,
                        "Net.NetSchedECNThreshold": 70,
                        "Net.NetSchedHClkLeafQueueDepthPkt": 500,
                        "Net.NetSchedHClkMQ": 0,
                        "Net.NetSchedHClkMaxHwQueue": 2,
                        "Net.NetSchedHeapMaxSizeMB": 64,
                        "Net.NetSchedInFlightMaxBytesDefault": 20000,
                        "Net.NetSchedInFlightMaxBytesInsane": 1500000,
                        "Net.NetSchedMaxPktSend": 256,
                        "Net.NetSchedQoSSchedName": "hclk",
                        "Net.NetSchedSpareBasedShares": 1,
                        "Net.NetSendRARPOnPortEnablement": 1,
                        "Net.NetShaperQueuePerL3L4Flow": 1,
                        "Net.NetSplitRxMode": 1,
                        "Net.NetTraceEnable": 0,
                        "Net.NetTuneHostMode": "default",
                        "Net.NetTuneInterval": 60,
                        "Net.NetTuneThreshold": "1n 2n 50",
                        "Net.NetTxDontClusterSize": 0,
                        "Net.NetVMTxType": 2,
                        "Net.NetVmxnet3TxHangTimeout": 0,
                        "Net.NetpollSwLRO": 1,
                        "Net.NoLocalCSum": 0,
                        "Net.NotifySwitch": 1,
                        "Net.PTSwitchingTimeout": 20000,
                        "Net.PVRDMAVmknic": "",
                        "Net.PortDisableTimeout": 5000,
                        "Net.ReversePathFwdCheck": 1,
                        "Net.ReversePathFwdCheckPromisc": 0,
                        "Net.TcpipCopySmallTx": 1,
                        "Net.TcpipDefLROEnabled": 1,
                        "Net.TcpipDefLROMaxLength": 32768,
                        "Net.TcpipDgramRateLimiting": 1,
                        "Net.TcpipEnableABC": 1,
                        "Net.TcpipEnableFlowtable": 1,
                        "Net.TcpipEnableSendScaling": 1,
                        "Net.TcpipHWLRONoDelayAck": 1,
                        "Net.TcpipHeapMax": 1024,
                        "Net.TcpipHeapSize": 0,
                        "Net.TcpipIGMPDefaultVersion": 3,
                        "Net.TcpipIGMPRejoinInterval": 60,
                        "Net.TcpipLODispatchQueueMaxLen": 128,
                        "Net.TcpipLRONoDelayAck": 1,
                        "Net.TcpipLogPackets": 0,
                        "Net.TcpipLogPacketsCount": 24570,
                        "Net.TcpipMaxNetstackInstances": 48,
                        "Net.TcpipNoBcopyRx": 1,
                        "Net.TcpipPendPktSocketFreeTimeout": 300,
                        "Net.TcpipRxDispatchQueueMaxLen": 2000,
                        "Net.TcpipRxDispatchQueues": 1,
                        "Net.TcpipRxDispatchQuota": 200,
                        "Net.TcpipRxVmknicWorldletAffinityType": 0,
                        "Net.TcpipTxDispatchQuota": 100,
                        "Net.TcpipTxqBackoffTimeoutMs": 70,
                        "Net.TcpipTxqMaxUsageThreshold": 80,
                        "Net.TeamPolicyUpDelay": 100,
                        "Net.TrafficFilterIpAddress": "",
                        "Net.TsoDumpPkt": 0,
                        "Net.UplinkAbortDisconnectTimeout": 5000,
                        "Net.UplinkKillAsyncTimeout": 10000,
                        "Net.UplinkTxQueuesDispEnabled": 1,
                        "Net.UseHwCsumForIPv6Csum": 1,
                        "Net.UseHwIPv6Csum": 1,
                        "Net.UseHwTSO": 1,
                        "Net.UseHwTSO6": 1,
                        "Net.UseLegacyProc": 0,
                        "Net.UseProc": 0,
                        "Net.VLANMTUCheckMode": 1,
                        "Net.VmklnxLROEnabled": 0,
                        "Net.VmklnxLROMaxAggr": 6,
                        "Net.VmknicDoLroSplit": 0,
                        "Net.VmknicLroSplitBnd": 12,
                        "Net.Vmxnet2HwLRO": 1,
                        "Net.Vmxnet2PinRxBuf": 0,
                        "Net.Vmxnet2SwLRO": 1,
                        "Net.Vmxnet3HwLRO": 1,
                        "Net.Vmxnet3PageInBound": 32,
                        "Net.Vmxnet3RSSHashCache": 1,
                        "Net.Vmxnet3RxPollBound": 256,
                        "Net.Vmxnet3SwLRO": 1,
                        "Net.Vmxnet3WinIntrHints": 1,
                        "Net.Vmxnet3usePNICHash": 0,
                        "Net.VmxnetBiDirNeedsTsoTx": 1,
                        "Net.VmxnetBiDirNoTsoSplit": 1,
                        "Net.VmxnetCopyTxRunLimit": 16,
                        "Net.VmxnetDoLroSplit": 1,
                        "Net.VmxnetDoTsoSplit": 1,
                        "Net.VmxnetLROBackoffPeriod": 8,
                        "Net.VmxnetLROMaxLength": 32000,
                        "Net.VmxnetLROThreshold": 4000,
                        "Net.VmxnetLROUseRatioDenom": 3,
                        "Net.VmxnetLROUseRatioNumer": 2,
                        "Net.VmxnetLroSplitBnd": 64,
                        "Net.VmxnetPromDisableLro": 1,
                        "Net.VmxnetSwLROSL": 1,
                        "Net.VmxnetTsoSplitBnd": 12,
                        "Net.VmxnetTsoSplitSize": 17500,
                        "Net.VmxnetTxCopySize": 256,
                        "Net.VmxnetWinCopyTxRunLimit": 65535,
                        "Net.VmxnetWinUDPTxFullCopy": 1,
                        "Net.vNicNumDeferredReset": 12,
                        "Net.vNicTxPollBound": 192,
                        "Net.vmxnetThroughputWeight": 0,
                        "Nmp.NmpPReservationCmdRetryTime": 1,
                        "Nmp.NmpSatpAluaCmdRetryTime": 10,
                        "Numa.CoreCapRatioPct": 90,
                        "Numa.CostopSkewAdjust": 1,
                        "Numa.FollowCoresPerSocket": 0,
                        "Numa.LTermFairnessInterval": 5,
                        "Numa.LTermMigImbalThreshold": 10,
                        "Numa.LargeInterleave": 1,
                        "Numa.LocalityWeightActionAffinity": 130,
                        "Numa.LocalityWeightMem": 1,
                        "Numa.MigImbalanceThreshold": 10,
                        "Numa.MigPreventLTermThresh": 0,
                        "Numa.MigThrashThreshold": 50,
                        "Numa.MigThreshold": 2,
                        "Numa.MonMigEnable": 1,
                        "Numa.PageMigEnable": 1,
                        "Numa.PageMigLinearRun": 95,
                        "Numa.PageMigRandomRun": 5,
                        "Numa.PageMigRateMax": 8000,
                        "Numa.PreferHT": 0,
                        "Numa.RebalanceCoresNode": 2,
                        "Numa.RebalanceCoresTotal": 4,
                        "Numa.RebalanceEnable": 1,
                        "Numa.RebalancePeriod": 2000,
                        "Numa.SwapConsiderPeriod": 15,
                        "Numa.SwapInterval": 3,
                        "Numa.SwapLoadEnable": 1,
                        "Numa.SwapLocalityEnable": 1,
                        "Numa.SwapMigrateOnly": 2,
                        "Power.CStateMaxLatency": 500,
                        "Power.CStatePredictionCoef": 110479,
                        "Power.CStateResidencyCoef": 5,
                        "Power.ChargeMemoryPct": 20,
                        "Power.MaxCpuLoad": 60,
                        "Power.MaxFreqPct": 100,
                        "Power.MinFreqPct": 0,
                        "Power.PerfBias": 17,
                        "Power.PerfBiasEnable": 1,
                        "Power.TimerHz": 100,
                        "Power.UseCStates": 1,
                        "Power.UsePStates": 1,
                        "RdmFilter.HbaIsShared": true,
                        "ScratchConfig.ConfiguredScratchLocation": "",
                        "ScratchConfig.CurrentScratchLocation": "/tmp/scratch",
                        "Scsi.ChangeQErrSetting": 1,
                        "Scsi.CompareLUNNumber": 1,
                        "Scsi.ExtendAPDCondition": 0,
                        "Scsi.FailVMIOonAPD": 0,
                        "Scsi.LogCmdErrors": 1,
                        "Scsi.LogCmdRCErrorsFreq": 0,
                        "Scsi.LogMPCmdErrors": 1,
                        "Scsi.LogScsiAborts": 0,
                        "Scsi.LunCleanupInterval": 7,
                        "Scsi.MaxReserveBacktrace": 0,
                        "Scsi.MaxReserveTime": 200,
                        "Scsi.MaxReserveTotalTime": 250,
                        "Scsi.PassthroughLocking": 1,
                        "Scsi.ReserveBacktrace": 0,
                        "Scsi.SCSIEnableDescToFixedConv": 1,
                        "Scsi.SCSIEnableIOLatencyMsgs": 0,
                        "Scsi.SCSIStrictSPCVersionChecksForPEs": 0,
                        "Scsi.SCSITimeout_ReabortTime": 5000,
                        "Scsi.SCSITimeout_ScanTime": 1000,
                        "Scsi.SCSIioTraceBufSizeMB": 1,
                        "Scsi.ScanOnDriverLoad": 1,
                        "Scsi.ScanSync": 0,
                        "Scsi.ScsiRestartStalledQueueLatency": 500,
                        "Scsi.ScsiVVolPESNRO": 128,
                        "Scsi.TimeoutTMThreadExpires": 1800,
                        "Scsi.TimeoutTMThreadLatency": 2000,
                        "Scsi.TimeoutTMThreadMax": 16,
                        "Scsi.TimeoutTMThreadMin": 1,
                        "Scsi.TimeoutTMThreadRetry": 2000,
                        "Scsi.TransFailLogPct": 20,
                        "Scsi.UseAdaptiveRetries": 1,
                        "Security.AccountLockFailures": 5,
                        "Security.AccountUnlockTime": 900,
                        "Security.PasswordQualityControl": "retry=3 min=disabled,disabled,disabled,7,7",
                        "SunRPC.MaxConnPerIP": 4,
                        "SunRPC.SendLowat": 25,
                        "SunRPC.WorldletAffinity": 2,
                        "SvMotion.SvMotionAvgDisksPerVM": 8,
                        "Syslog.global.defaultRotate": 8,
                        "Syslog.global.defaultSize": 1024,
                        "Syslog.global.logDir": "[] /scratch/log",
                        "Syslog.global.logDirUnique": false,
                        "Syslog.global.logHost": "192.168.1.200",
                        "Syslog.loggers.Xorg.rotate": 8,
                        "Syslog.loggers.Xorg.size": 1024,
                        "Syslog.loggers.auth.rotate": 8,
                        "Syslog.loggers.auth.size": 1024,
                        "Syslog.loggers.clomd.rotate": 8,
                        "Syslog.loggers.clomd.size": 1024,
                        "Syslog.loggers.cmmdsTimeMachine.rotate": 8,
                        "Syslog.loggers.cmmdsTimeMachine.size": 1024,
                        "Syslog.loggers.cmmdsTimeMachineDump.rotate": 20,
                        "Syslog.loggers.cmmdsTimeMachineDump.size": 10240,
                        "Syslog.loggers.ddecomd.rotate": 8,
                        "Syslog.loggers.ddecomd.size": 1024,
                        "Syslog.loggers.dhclient.rotate": 8,
                        "Syslog.loggers.dhclient.size": 1024,
                        "Syslog.loggers.epd.rotate": 8,
                        "Syslog.loggers.epd.size": 1024,
                        "Syslog.loggers.esxupdate.rotate": 8,
                        "Syslog.loggers.esxupdate.size": 1024,
                        "Syslog.loggers.fdm.rotate": 8,
                        "Syslog.loggers.fdm.size": 1024,
                        "Syslog.loggers.hbrca.rotate": 8,
                        "Syslog.loggers.hbrca.size": 1024,
                        "Syslog.loggers.hostd-probe.rotate": 8,
                        "Syslog.loggers.hostd-probe.size": 1024,
                        "Syslog.loggers.hostd.rotate": 8,
                        "Syslog.loggers.hostd.size": 1024,
                        "Syslog.loggers.hostdCgiServer.rotate": 8,
                        "Syslog.loggers.hostdCgiServer.size": 1024,
                        "Syslog.loggers.hostprofiletrace.rotate": 8,
                        "Syslog.loggers.hostprofiletrace.size": 1024,
                        "Syslog.loggers.iofiltervpd.rotate": 8,
                        "Syslog.loggers.iofiltervpd.size": 1024,
                        "Syslog.loggers.lacp.rotate": 8,
                        "Syslog.loggers.lacp.size": 1024,
                        "Syslog.loggers.nfcd.rotate": 8,
                        "Syslog.loggers.nfcd.size": 1024,
                        "Syslog.loggers.osfsd.rotate": 8,
                        "Syslog.loggers.osfsd.size": 1024,
                        "Syslog.loggers.rabbitmqproxy.rotate": 8,
                        "Syslog.loggers.rabbitmqproxy.size": 1024,
                        "Syslog.loggers.rhttpproxy.rotate": 8,
                        "Syslog.loggers.rhttpproxy.size": 1024,
                        "Syslog.loggers.sdrsInjector.rotate": 8,
                        "Syslog.loggers.sdrsInjector.size": 1024,
                        "Syslog.loggers.shell.rotate": 8,
                        "Syslog.loggers.shell.size": 1024,
                        "Syslog.loggers.storageRM.rotate": 8,
                        "Syslog.loggers.storageRM.size": 1024,
                        "Syslog.loggers.swapobjd.rotate": 8,
                        "Syslog.loggers.swapobjd.size": 1024,
                        "Syslog.loggers.syslog.rotate": 8,
                        "Syslog.loggers.syslog.size": 1024,
                        "Syslog.loggers.upitd.rotate": 8,
                        "Syslog.loggers.upitd.size": 1024,
                        "Syslog.loggers.usb.rotate": 8,
                        "Syslog.loggers.usb.size": 1024,
                        "Syslog.loggers.vitd.rotate": 8,
                        "Syslog.loggers.vitd.size": 10240,
                        "Syslog.loggers.vmauthd.rotate": 8,
                        "Syslog.loggers.vmauthd.size": 1024,
                        "Syslog.loggers.vmkdevmgr.rotate": 8,
                        "Syslog.loggers.vmkdevmgr.size": 1024,
                        "Syslog.loggers.vmkernel.rotate": 8,
                        "Syslog.loggers.vmkernel.size": 1024,
                        "Syslog.loggers.vmkeventd.rotate": 8,
                        "Syslog.loggers.vmkeventd.size": 1024,
                        "Syslog.loggers.vmksummary.rotate": 8,
                        "Syslog.loggers.vmksummary.size": 1024,
                        "Syslog.loggers.vmkwarning.rotate": 8,
                        "Syslog.loggers.vmkwarning.size": 1024,
                        "Syslog.loggers.vobd.rotate": 8,
                        "Syslog.loggers.vobd.size": 1024,
                        "Syslog.loggers.vprobe.rotate": 8,
                        "Syslog.loggers.vprobe.size": 1024,
                        "Syslog.loggers.vpxa.rotate": 8,
                        "Syslog.loggers.vpxa.size": 1024,
                        "Syslog.loggers.vsanSoapServer.rotate": 8,
                        "Syslog.loggers.vsanSoapServer.size": 5120,
                        "Syslog.loggers.vsanmgmt.rotate": 8,
                        "Syslog.loggers.vsanmgmt.size": 10240,
                        "Syslog.loggers.vsansystem.rotate": 10,
                        "Syslog.loggers.vsansystem.size": 10240,
                        "Syslog.loggers.vsantraceUrgent.rotate": 8,
                        "Syslog.loggers.vsantraceUrgent.size": 1024,
                        "Syslog.loggers.vvold.rotate": 16,
                        "Syslog.loggers.vvold.size": 8192,
                        "User.PTEDisableNX": 0,
                        "User.ReaddirRetries": 10,
                        "UserVars.ActiveDirectoryPreferredDomainControllers": "",
                        "UserVars.ActiveDirectoryVerifyCAMCertificate": 1,
                        "UserVars.DcuiTimeOut": 600,
                        "UserVars.ESXiShellInteractiveTimeOut": 0,
                        "UserVars.ESXiShellTimeOut": 0,
                        "UserVars.ESXiVPsAllowedCiphers": "!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES",
                        "UserVars.ESXiVPsDisabledProtocols": "sslv3",
                        "UserVars.EsximageNetRateLimit": 0,
                        "UserVars.EsximageNetRetries": 10,
                        "UserVars.EsximageNetTimeout": 60,
                        "UserVars.HardwareHealthIgnoredSensors": "",
                        "UserVars.HardwareHealthSyncTime": 360,
                        "UserVars.HostClientCEIPOptIn": 2,
                        "UserVars.HostClientDefaultConsole": "webmks",
                        "UserVars.HostClientEnableMOTDNotification": 1,
                        "UserVars.HostClientEnableVisualEffects": 1,
                        "UserVars.HostClientSessionTimeout": 900,
                        "UserVars.HostClientShowOnlyRecentObjects": 1,
                        "UserVars.HostClientWelcomeMessage": "Welcome to {{hostname}}",
                        "UserVars.HostdStatsstoreRamdiskSize": 0,
                        "UserVars.ProductLockerLocation": "/locker/packages/6.5.0/",
                        "UserVars.SuppressCoredumpWarning": 0,
                        "UserVars.SuppressHyperthreadWarning": 0,
                        "UserVars.SuppressShellWarning": 1,
                        "UserVars.ToolsRamdisk": 0,
                        "UserVars.vGhettoSetup": 1,
                        "VFLASH.CacheStatsEnable": 1,
                        "VFLASH.CacheStatsFromVFC": 1,
                        "VFLASH.MaxCacheFileSizeMB": 409600,
                        "VFLASH.MaxDiskFileSizeGB": 16384,
                        "VFLASH.MaxHeapSizeMB": 32,
                        "VFLASH.MaxResourceGBForVmCache": 2048,
                        "VFLASH.ResourceUsageThreshold": 80,
                        "VMFS.UnresolvedVolumeLiveCheck": true,
                        "VMFS3.EnableBlockDelete": 0,
                        "VMFS3.FailVolumeOpenIfAPD": 0,
                        "VMFS3.HardwareAcceleratedLocking": 1,
                        "VMFS3.LFBCSlabSizeMaxMB": 8,
                        "VMFS3.MaxAddressableSpaceTB": 32,
                        "VMFS3.MaxHeapSizeMB": 256,
                        "VMFS3.MaxextendedTxnsUsingfs3Heap": 20,
                        "VMFS3.MinAddressableSpaceTB": 0,
                        "VMFS3.OpenWithoutJournal": 1,
                        "VMFS3.PBCapMissRatioIntervalSec": 60,
                        "VMFS3.StAtExclLockEnd": 0,
                        "VMFS3.UseATSForHBOnVMFS5": 1,
                        "VMkernel.Boot.allowNonNX": false,
                        "VMkernel.Boot.autoCreateDumpFile": true,
                        "VMkernel.Boot.autoPartition": false,
                        "VMkernel.Boot.autoPartitionCreateUSBCoreDumpPartition": false,
                        "VMkernel.Boot.autoPartitionDiskDumpPartitionSize": 2560,
                        "VMkernel.Boot.bootDeviceRescanTimeout": 1,
                        "VMkernel.Boot.busSpeedMayVary": false,
                        "VMkernel.Boot.cacheFlushImmOnAllHalt": false,
                        "VMkernel.Boot.checkCPUIDLimit": true,
                        "VMkernel.Boot.checkPages": false,
                        "VMkernel.Boot.com1_baud": 115200,
                        "VMkernel.Boot.com2_baud": 115200,
                        "VMkernel.Boot.coresPerPkg": 0,
                        "VMkernel.Boot.debugBreak": false,
                        "VMkernel.Boot.debugLogToSerial": 2,
                        "VMkernel.Boot.disableACSCheck": false,
                        "VMkernel.Boot.disableCFOH": false,
                        "VMkernel.Boot.disableHwrng": false,
                        "VMkernel.Boot.diskDumpSlotSize": 0,
                        "VMkernel.Boot.dmaEngineExposeIdentityMapping": true,
                        "VMkernel.Boot.dmaMapperPolicy": "disabled",
                        "VMkernel.Boot.enableACSCheckForRP": false,
                        "VMkernel.Boot.execInstalledOnly": false,
                        "VMkernel.Boot.fsCheck": false,
                        "VMkernel.Boot.gdbPort": "default",
                        "VMkernel.Boot.generalCriticalMemory": 0,
                        "VMkernel.Boot.heapCheckTimerInterval": 10,
                        "VMkernel.Boot.heapFreeOwnerCheck": false,
                        "VMkernel.Boot.heapFreePoisonByte": 255,
                        "VMkernel.Boot.heapMetaPoisonByte": 90,
                        "VMkernel.Boot.heapMetadataProtect": false,
                        "VMkernel.Boot.heapMgrTotalVASpaceGB": 512,
                        "VMkernel.Boot.heapPoisonFreeMem": false,
                        "VMkernel.Boot.heapPoisonTimerChecks": false,
                        "VMkernel.Boot.hyperthreading": true,
                        "VMkernel.Boot.hyperthreadingMitigation": false,
                        "VMkernel.Boot.ignoreMsrFaults": false,
                        "VMkernel.Boot.intrBalancingEnabled": true,
                        "VMkernel.Boot.ioAbilityChecks": false,
                        "VMkernel.Boot.iovDisableIR": false,
                        "VMkernel.Boot.ipmiEnabled": true,
                        "VMkernel.Boot.isPerFileSchedModelActive": true,
                        "VMkernel.Boot.leaveWakeGPEsDisabled": true,
                        "VMkernel.Boot.logPort": "default",
                        "VMkernel.Boot.maxLogEntries": 0,
                        "VMkernel.Boot.maxPCPUS": 576,
                        "VMkernel.Boot.maxPCPUsNUMAInterleaving": true,
                        "VMkernel.Boot.maxVMs": 0,
                        "VMkernel.Boot.memCheckEveryWord": false,
                        "VMkernel.Boot.memLowReservedMB": 0,
                        "VMkernel.Boot.memmapMaxEarlyPoisonMemMB": 65536,
                        "VMkernel.Boot.memmapMaxPhysicalMemMB": 16777216,
                        "VMkernel.Boot.memmapMaxRAMMB": 12582912,
                        "VMkernel.Boot.microcodeUpdate": true,
                        "VMkernel.Boot.microcodeUpdateForce": false,
                        "VMkernel.Boot.netCoalesceTimerHdlrPcpu": 0,
                        "VMkernel.Boot.netGPHeapMaxMBPerGB": 4,
                        "VMkernel.Boot.netMaxPktsToProcess": 64,
                        "VMkernel.Boot.netNetqueueEnabled": true,
                        "VMkernel.Boot.netPagePoolLimitCap": 98304,
                        "VMkernel.Boot.netPagePoolLimitPerGB": 5120,
                        "VMkernel.Boot.netPagePoolResvCap": 0,
                        "VMkernel.Boot.netPagePoolResvPerGB": 0,
                        "VMkernel.Boot.netPktHeapMaxMBPerGB": 6,
                        "VMkernel.Boot.netPktHeapMinMBPerGB": 0,
                        "VMkernel.Boot.netPktPoolMaxMBPerGB": 75,
                        "VMkernel.Boot.netPktPoolMinMBPerGB": 0,
                        "VMkernel.Boot.netPreemptionEnabled": false,
                        "VMkernel.Boot.nmiAction": 0,
                        "VMkernel.Boot.numaLatencyRemoteThresholdPct": 10,
                        "VMkernel.Boot.overrideDuplicateImageDetection": false,
                        "VMkernel.Boot.pciBarAllocPolicy": 0,
                        "VMkernel.Boot.pcipDisablePciErrReporting": true,
                        "VMkernel.Boot.poisonMarker": -6148914691236517000,
                        "VMkernel.Boot.poisonPagePool": false,
                        "VMkernel.Boot.preferVmklinux": false,
                        "VMkernel.Boot.preventFreePageMapping": false,
                        "VMkernel.Boot.rdmaRoceIPBasedGidGeneration": true,
                        "VMkernel.Boot.rtcEnableEFI": true,
                        "VMkernel.Boot.rtcEnableLegacy": true,
                        "VMkernel.Boot.rtcEnableTAD": true,
                        "VMkernel.Boot.scrubIgnoredPages": false,
                        "VMkernel.Boot.scrubMemoryAfterModuleLoad": false,
                        "VMkernel.Boot.serialUntrusted": true,
                        "VMkernel.Boot.skipPartitioningSsds": false,
                        "VMkernel.Boot.storageHeapMaxSize": 0,
                        "VMkernel.Boot.storageHeapMinSize": 0,
                        "VMkernel.Boot.storageMaxDevices": 512,
                        "VMkernel.Boot.storageMaxPaths": 2048,
                        "VMkernel.Boot.storageMaxVMsPerDevice": 32,
                        "VMkernel.Boot.terminateVMOnPDL": false,
                        "VMkernel.Boot.timerEnableACPI": true,
                        "VMkernel.Boot.timerEnableHPET": true,
                        "VMkernel.Boot.timerEnableTSC": true,
                        "VMkernel.Boot.timerForceTSC": false,
                        "VMkernel.Boot.tscSpeedMayVary": false,
                        "VMkernel.Boot.tty1Port": "default",
                        "VMkernel.Boot.tty2Port": "default",
                        "VMkernel.Boot.updateBusIRQ": false,
                        "VMkernel.Boot.useNUMAInfo": true,
                        "VMkernel.Boot.useReliableMem": true,
                        "VMkernel.Boot.useSLIT": true,
                        "VMkernel.Boot.vmkATKeyboard": false,
                        "VMkernel.Boot.vmkacEnable": 1,
                        "VMkernel.Boot.vtdSuperPages": true,
                        "VSAN-iSCSI.iscsiPingTimeout": 5,
                        "VSAN.AutoTerminateGhostVm": 1,
                        "VSAN.ClomMaxComponentSizeGB": 255,
                        "VSAN.ClomMaxDiskUsageRepairComps": 95,
                        "VSAN.ClomRebalanceThreshold": 80,
                        "VSAN.ClomRepairDelay": 60,
                        "VSAN.DedupScope": 0,
                        "VSAN.DefaultHostDecommissionMode": "ensureAccessibility",
                        "VSAN.DomBriefIoTraces": 0,
                        "VSAN.DomFullIoTraces": 0,
                        "VSAN.DomLongOpTraceMS": 1000,
                        "VSAN.DomLongOpUrgentTraceMS": 10000,
                        "VSAN.ObjectScrubsPerYear": 1,
                        "VSAN.PerTraceBandwidthLimit": 0,
                        "VSAN.PerTraceBandwidthLimitPeriodMs": 10000,
                        "VSAN.PerTraceMaxRolloverPeriods": 360,
                        "VSAN.SwapThickProvisionDisabled": 1,
                        "VSAN.TraceEnableCmmds": 1,
                        "VSAN.TraceEnableDom": 1,
                        "VSAN.TraceEnableDomIo": 0,
                        "VSAN.TraceEnableLchk": 1,
                        "VSAN.TraceEnableLsom": 1,
                        "VSAN.TraceEnablePlog": 1,
                        "VSAN.TraceEnableRdt": 1,
                        "VSAN.TraceEnableSsdLog": 1,
                        "VSAN.TraceEnableVirsto": 1,
                        "VSAN.TraceEnableVsanSparse": 1,
                        "VSAN.TraceEnableVsanSparseIO": 0,
                        "VSAN.TraceEnableVsanSparseVerbose": 0,
                        "VSAN.TraceGlobalBandwidthLimit": 0,
                        "VSAN.TraceGlobalBandwidthLimitPeriodMs": 10000,
                        "VSAN.TraceGlobalMaxRolloverPeriods": 360,
                        "VSAN.VsanSparseCacheOverEvict": 5,
                        "VSAN.VsanSparseCacheThreshold": 1024,
                        "VSAN.VsanSparseEnabled": 1,
                        "VSAN.VsanSparseHeapSize": 65536,
                        "VSAN.VsanSparseMaxExtentsPrefetch": 64,
                        "VSAN.VsanSparseParallelLookup": 1,
                        "VSAN.VsanSparseRetainCacheOnSnapshots": 1,
                        "VSAN.VsanSparseRetainCacheTTL": 20,
                        "VSAN.VsanSparseSpeculativePrefetch": 4194304,
                        "Virsto.DiskFormatVersion": 5,
                        "Virsto.Enabled": 1,
                        "Virsto.FlusherRegistryThreshold": 50,
                        "Virsto.GweFetchExtentsFactor": 3,
                        "Virsto.InstanceHeapLimit": 130,
                        "Virsto.MapBlocksFlushThreshold": 90,
                        "Virsto.MapBlocksMin": 16384,
                        "Virsto.MaxMFRetryCount": 3,
                        "Virsto.MsecBeforeMetaFlush": 10000,
                        "Virsto.RecordsPerFormatWrite": 16,
                        "Virsto.SharedHeapLimit": 4,
                        "Vpx.Vpxa.config.httpNfc.accessMode": "proxyAuto",
                        "Vpx.Vpxa.config.httpNfc.enabled": "true",
                        "Vpx.Vpxa.config.level[SoapAdapter.HTTPService.HttpConnection].logLevel": "info",
                        "Vpx.Vpxa.config.level[SoapAdapter.HTTPService.HttpConnection].logName": "SoapAdapter.HTTPService.HttpConnection",
                        "Vpx.Vpxa.config.level[SoapAdapter.HTTPService].logLevel": "info",
                        "Vpx.Vpxa.config.level[SoapAdapter.HTTPService].logName": "SoapAdapter.HTTPService",
                        "Vpx.Vpxa.config.log.level": "verbose",
                        "Vpx.Vpxa.config.log.maxFileNum": "10",
                        "Vpx.Vpxa.config.log.maxFileSize": "1048576",
                        "Vpx.Vpxa.config.log.memoryLevel": "verbose",
                        "Vpx.Vpxa.config.log.outputToConsole": "false",
                        "Vpx.Vpxa.config.log.outputToFiles": "false",
                        "Vpx.Vpxa.config.log.outputToSyslog": "true",
                        "Vpx.Vpxa.config.log.syslog.facility": "local4",
                        "Vpx.Vpxa.config.log.syslog.ident": "Vpxa",
                        "Vpx.Vpxa.config.log.syslog.logHeaderFile": "/var/run/vmware/vpxaLogHeader.txt",
                        "Vpx.Vpxa.config.nfc.loglevel": "error",
                        "Vpx.Vpxa.config.task.completedMaxEntries": "1000",
                        "Vpx.Vpxa.config.task.maxThreads": "98",
                        "Vpx.Vpxa.config.task.minCompletedLifetime": "120",
                        "Vpx.Vpxa.config.trace.mutex.profiledMutexes": "InvtLock",
                        "Vpx.Vpxa.config.trace.vmomi.calls": "false",
                        "Vpx.Vpxa.config.vmacore.http.defaultClientPoolConnectionsPerServer": "300",
                        "Vpx.Vpxa.config.vmacore.soap.sessionTimeout": "1440",
                        "Vpx.Vpxa.config.vmacore.ssl.doVersionCheck": "false",
                        "Vpx.Vpxa.config.vmacore.threadPool.IoMax": "9",
                        "Vpx.Vpxa.config.vmacore.threadPool.TaskMax": "4",
                        "Vpx.Vpxa.config.vmacore.threadPool.ThreadStackSizeKb": "128",
                        "Vpx.Vpxa.config.vmacore.threadPool.threadNamePrefix": "vpxa",
                        "Vpx.Vpxa.config.vpxa.bundleVersion": "1000000",
                        "Vpx.Vpxa.config.vpxa.datastorePrincipal": "root",
                        "Vpx.Vpxa.config.vpxa.hostIp": "esxi01",
                        "Vpx.Vpxa.config.vpxa.hostPort": "443",
                        "Vpx.Vpxa.config.vpxa.licenseExpiryNotificationThreshold": "15",
                        "Vpx.Vpxa.config.vpxa.memoryCheckerTimeInSecs": "30",
                        "Vpx.Vpxa.config.workingDir": "/var/log/vmware/vpx",
                        "XvMotion.VMFSOptimizations": 1
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Info
>    * ### esxi01
>      * Annotations.WelcomeMessage: 
>      * BufferCache.FlushInterval: 30000
>      * BufferCache.HardMaxDirty: 95
>      * BufferCache.PerFileHardMaxDirty: 50
>      * BufferCache.SoftMaxDirty: 15
>      * CBRC.DCacheMemReserved: 400
>      * CBRC.DCacheSize: 32768
>      * CBRC.DigestJournalBootInterval: 10
>      * CBRC.Enable: False
>      * COW.COWMaxHeapSizeMB: 192
>      * COW.COWMaxREPageCacheszMB: 256
>      * COW.COWMinREPageCacheszMB: 0
>      * COW.COWREPageCacheEviction: 1
>      * Config.Defaults.cpuidMask.mode.0.eax: disable
>      * Config.Defaults.cpuidMask.mode.0.ebx: disable
>      * Config.Defaults.cpuidMask.mode.0.ecx: disable
>      * Config.Defaults.cpuidMask.mode.0.edx: disable
>      * Config.Defaults.cpuidMask.mode.1.eax: disable
>      * Config.Defaults.cpuidMask.mode.1.ebx: disable
>      * Config.Defaults.cpuidMask.mode.1.ecx: disable
>      * Config.Defaults.cpuidMask.mode.1.edx: disable
>      * Config.Defaults.cpuidMask.mode.80000000.eax: disable
>      * Config.Defaults.cpuidMask.mode.80000000.ebx: disable
>      * Config.Defaults.cpuidMask.mode.80000000.ecx: disable
>      * Config.Defaults.cpuidMask.mode.80000000.edx: disable
>      * Config.Defaults.cpuidMask.mode.80000001.eax: disable
>      * Config.Defaults.cpuidMask.mode.80000001.ebx: disable
>      * Config.Defaults.cpuidMask.mode.80000001.ecx: disable
>      * Config.Defaults.cpuidMask.mode.80000001.edx: disable
>      * Config.Defaults.cpuidMask.mode.80000008.eax: disable
>      * Config.Defaults.cpuidMask.mode.80000008.ebx: disable
>      * Config.Defaults.cpuidMask.mode.80000008.ecx: disable
>      * Config.Defaults.cpuidMask.mode.80000008.edx: disable
>      * Config.Defaults.cpuidMask.mode.8000000A.eax: disable
>      * Config.Defaults.cpuidMask.mode.8000000A.ebx: disable
>      * Config.Defaults.cpuidMask.mode.8000000A.ecx: disable
>      * Config.Defaults.cpuidMask.mode.8000000A.edx: disable
>      * Config.Defaults.cpuidMask.mode.d.eax: disable
>      * Config.Defaults.cpuidMask.mode.d.ebx: disable
>      * Config.Defaults.cpuidMask.mode.d.ecx: disable
>      * Config.Defaults.cpuidMask.mode.d.edx: disable
>      * Config.Defaults.cpuidMask.val.0.eax: 
>      * Config.Defaults.cpuidMask.val.0.ebx: 
>      * Config.Defaults.cpuidMask.val.0.ecx: 
>      * Config.Defaults.cpuidMask.val.0.edx: 
>      * Config.Defaults.cpuidMask.val.1.eax: 
>      * Config.Defaults.cpuidMask.val.1.ebx: 
>      * Config.Defaults.cpuidMask.val.1.ecx: 
>      * Config.Defaults.cpuidMask.val.1.edx: 
>      * Config.Defaults.cpuidMask.val.80000000.eax: 
>      * Config.Defaults.cpuidMask.val.80000000.ebx: 
>      * Config.Defaults.cpuidMask.val.80000000.ecx: 
>      * Config.Defaults.cpuidMask.val.80000000.edx: 
>      * Config.Defaults.cpuidMask.val.80000001.eax: 
>      * Config.Defaults.cpuidMask.val.80000001.ebx: 
>      * Config.Defaults.cpuidMask.val.80000001.ecx: 
>      * Config.Defaults.cpuidMask.val.80000001.edx: 
>      * Config.Defaults.cpuidMask.val.80000008.eax: 
>      * Config.Defaults.cpuidMask.val.80000008.ebx: 
>      * Config.Defaults.cpuidMask.val.80000008.ecx: 
>      * Config.Defaults.cpuidMask.val.80000008.edx: 
>      * Config.Defaults.cpuidMask.val.8000000A.eax: 
>      * Config.Defaults.cpuidMask.val.8000000A.ebx: 
>      * Config.Defaults.cpuidMask.val.8000000A.ecx: 
>      * Config.Defaults.cpuidMask.val.8000000A.edx: 
>      * Config.Defaults.cpuidMask.val.d.eax: 
>      * Config.Defaults.cpuidMask.val.d.ebx: 
>      * Config.Defaults.cpuidMask.val.d.ecx: 
>      * Config.Defaults.cpuidMask.val.d.edx: 
>      * Config.Defaults.security.host.ruissl: True
>      * Config.Defaults.vGPU.consolidation: False
>      * Config.Etc.issue: 
>      * Config.Etc.motd: The time and date of this login have been sent to the system logs.
>
>WARNING:
>   All commands run on the ESXi shell are logged and may be included in
>   support bundles. Do not provide passwords directly on the command line.
>   Most tools can prompt for secrets or accept them from standard input.
>
>%1b[00mVMware offers supported, powerful system administration tools.  Please
>see www.vmware.com/go/sysadmintools for details.
>
>The ESXi Shell can be disabled by an administrative user. See the
>vSphere Security documentation for more information.
>
>      * Config.GlobalSettings.guest.commands.sharedPolicyRefCount: 0
>      * Config.HostAgent.level[Hbrsvc].logLevel: 
>      * Config.HostAgent.level[Hostsvc].logLevel: 
>      * Config.HostAgent.level[Proxysvc].logLevel: 
>      * Config.HostAgent.level[Snmpsvc].logLevel: 
>      * Config.HostAgent.level[Statssvc].logLevel: 
>      * Config.HostAgent.level[Vcsvc].logLevel: 
>      * Config.HostAgent.level[Vimsvc].logLevel: 
>      * Config.HostAgent.level[Vmsvc].logLevel: 
>      * Config.HostAgent.log.level: info
>      * Config.HostAgent.plugins.hostsvc.esxAdminsGroup: ESX Admins
>      * Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd: True
>      * Config.HostAgent.plugins.hostsvc.esxAdminsGroupUpdateInterval: 1
>      * Config.HostAgent.plugins.solo.enableMob: False
>      * Config.HostAgent.plugins.solo.webServer.enableWebscriptLauncher: True
>      * Config.HostAgent.plugins.vimsvc.authValidateInterval: 1440
>      * Config.HostAgent.plugins.vimsvc.userSearch.maxResults: 100
>      * Config.HostAgent.plugins.vimsvc.userSearch.maxTimeSeconds: 20
>      * Config.HostAgent.plugins.vmsvc.enforceMaxRegisteredVms: True
>      * Config.HostAgent.plugins.vmsvc.productLockerWatchInterval: 300
>      * Cpu.ActionLoadThreshold: 10
>      * Cpu.AllowWideVsmp: 0
>      * Cpu.BoundLagQuanta: 8
>      * Cpu.CommRateThreshold: 500
>      * Cpu.CoschedCostartThreshold: 2000
>      * Cpu.CoschedCostopThreshold: 3000
>      * Cpu.CoschedCrossCall: 1
>      * Cpu.CoschedExclusiveAffinity: 0
>      * Cpu.CoschedHandoffLLC: 1
>      * Cpu.CoschedHandoffSkip: 10
>      * Cpu.CoschedPollUsec: 1000
>      * Cpu.CreditAgePeriod: 3000
>      * Cpu.FairnessRebalancePcpus: 4
>      * Cpu.HTRebalancePeriod: 5
>      * Cpu.HTStolenAgeThreshold: 8
>      * Cpu.HTWholeCoreThreshold: 800
>      * Cpu.HostRebalancePeriod: 100
>      * Cpu.L2RebalancePeriod: 10
>      * Cpu.L3RebalancePeriod: 20
>      * Cpu.LimitEnforcementThreshold: 200
>      * Cpu.MaxSampleRateLg: 7
>      * Cpu.MoveCurrentRunnerPcpus: 4
>      * Cpu.NonTimerWakeupRate: 500
>      * Cpu.PackageRebalancePeriod: 20
>      * Cpu.PcpuMigrateIdlePcpus: 4
>      * Cpu.Quantum: 200
>      * Cpu.UseMwait: 2
>      * Cpu.VMAdmitCheckPerVcpuMin: 1
>      * Cpu.WakeupMigrateIdlePcpus: 4
>      * DCUI.Access: root
>      * DataMover.HardwareAcceleratedInit: 1
>      * DataMover.HardwareAcceleratedMove: 1
>      * DataMover.MaxHeapSize: 64
>      * Digest.AlgoType: 1
>      * Digest.BlockSize: 1
>      * Digest.CollisionEnabled: 0
>      * Digest.JournalCoverage: 8
>      * Digest.UpdateOnClose: 0
>      * DirentryCache.MaxDentryPerObj: 15000
>      * Disk.AllowUsbClaimedAsSSD: 0
>      * Disk.ApdTokenRetryCount: 25
>      * Disk.AutoremoveOnPDL: 1
>      * Disk.BandwidthCap: 4294967294
>      * Disk.DelayOnBusy: 400
>      * Disk.DeviceReclaimTime: 300
>      * Disk.DisableVSCSIPollInBH: 1
>      * Disk.DiskDelayPDLHelper: 10
>      * Disk.DiskMaxIOSize: 32767
>      * Disk.DiskReservationThreshold: 45
>      * Disk.DiskRetryPeriod: 2000
>      * Disk.DumpMaxRetries: 10
>      * Disk.DumpPollDelay: 1000
>      * Disk.DumpPollMaxRetries: 10000
>      * Disk.EnableNaviReg: 1
>      * Disk.FailDiskRegistration: 0
>      * Disk.FastPathRestoreInterval: 100
>      * Disk.IdleCredit: 32
>      * Disk.MaxLUN: 1024
>      * Disk.MaxResetLatency: 2000
>      * Disk.NmpMaxCmdExtension: 0
>      * Disk.PathEvalTime: 300
>      * Disk.PreventVMFSOverwrite: 1
>      * Disk.QFullSampleSize: 0
>      * Disk.QFullThreshold: 8
>      * Disk.ReqCallThreshold: 8
>      * Disk.ResetLatency: 1000
>      * Disk.ResetMaxRetries: 0
>      * Disk.ResetOverdueLogPeriod: 60
>      * Disk.ResetPeriod: 30
>      * Disk.ResetThreadExpires: 1800
>      * Disk.ResetThreadMax: 16
>      * Disk.ResetThreadMin: 1
>      * Disk.RetryUnitAttention: 1
>      * Disk.ReturnCCForNoSpace: 0
>      * Disk.SchedCostUnit: 32768
>      * Disk.SchedQCleanupInterval: 300
>      * Disk.SchedQControlSeqReqs: 128
>      * Disk.SchedQControlVMSwitches: 6
>      * Disk.SchedQPriorityPercentage: 80
>      * Disk.SchedQuantum: 8
>      * Disk.SchedReservationBurst: 1
>      * Disk.SchedulerWithReservation: 1
>      * Disk.SectorMaxDiff: 2000
>      * Disk.SharesHigh: 2000
>      * Disk.SharesLow: 500
>      * Disk.SharesNormal: 1000
>      * Disk.SupportSparseLUN: 1
>      * Disk.ThroughputCap: 4294967294
>      * Disk.UseDeviceReset: 1
>      * Disk.UseIOWorlds: 1
>      * Disk.UseIoPool: 0
>      * Disk.UseLunReset: 1
>      * Disk.UseReportLUN: 1
>      * Disk.VSCSICoalesceCount: 1000
>      * Disk.VSCSIPollPeriod: 1000
>      * Disk.VSCSIResvCmdRetryInSecs: 1
>      * Disk.VSCSIWriteSameBurstSize: 4
>      * FSS.FSSLightWeightProbe: 1
>      * FT.AckIntervalMax: 1000000
>      * FT.AckIntervalMin: 0
>      * FT.BackupConnectTimeout: 8000
>      * FT.BackupExtraTimeout: 100
>      * FT.BadExecLatency: 800
>      * FT.BindToVmknic: 0
>      * FT.ChargeVMXForFlush: 1
>      * FT.CheckFCPathState: 1
>      * FT.CheckForProgress: 0
>      * FT.CoreDumpNoProgressMS: 0
>      * FT.ExecLatencyKill: 0
>      * FT.ExtraLogTimeout: 10000
>      * FT.FTCptConcurrentSend: 1
>      * FT.FTCptDelayCheckpoint: 2
>      * FT.FTCptDiffCap: 100
>      * FT.FTCptDiffThreads: 6
>      * FT.FTCptDisableFailover: 0
>      * FT.FTCptDiskWriteTimeout: 3000
>      * FT.FTCptDontDelayPkts: 0
>      * FT.FTCptDontSendPages: 0
>      * FT.FTCptEpochList: 5,10,20,100
>      * FT.FTCptEpochSample: 1000
>      * FT.FTCptEpochWait: 8000
>      * FT.FTCptIORetryExtraInterval: 200
>      * FT.FTCptIORetryInterval: 10
>      * FT.FTCptIORetryTimes: 15
>      * FT.FTCptLogTimeout: 8000
>      * FT.FTCptMaxPktsDelay: 0
>      * FT.FTCptMinInterval: 4
>      * FT.FTCptNetDelayNoCpt: 0
>      * FT.FTCptNumConnections: 2
>      * FT.FTCptNumaIndex: 0
>      * FT.FTCptPagePolicy: 65538
>      * FT.FTCptPoweroff: 0
>      * FT.FTCptRcvBufSize: 562140
>      * FT.FTCptSndBufSize: 562140
>      * FT.FTCptStartTimeout: 90000
>      * FT.FTCptStatsInterval: 30
>      * FT.FTCptThreadPolicy: 65536
>      * FT.FTCptVcpuMinUsage: 40
>      * FT.FTCptWaitOnSocket: 1
>      * FT.FillAffinity: 1
>      * FT.FillWorldlet: 1
>      * FT.FlushReservationMax: 25
>      * FT.FlushReservationMin: 5
>      * FT.FlushSleep: 0
>      * FT.FlushWorldlet: 1
>      * FT.GlobalFlushWorld: 0
>      * FT.GoodExecLatency: 200
>      * FT.HeartbeatCount: 10
>      * FT.HostTimeout: 2000
>      * FT.IORetryExtraInterval: 200
>      * FT.IORetryInterval: 10
>      * FT.IORetryTimes: 15
>      * FT.LogBufferStallSleep: 1
>      * FT.LogTimeout: 8000
>      * FT.LongFlushDebugMS: 500
>      * FT.MaxFlushInterval: 0
>      * FT.MinWriteSize: 0
>      * FT.NoWaitOnSocket: 0
>      * FT.PanicNoProgressMS: 0
>      * FT.PrimaryConnectTimeout: 8000
>      * FT.ShortFlushDebugMS: 100
>      * FT.TCPNoDelayBackup: 1
>      * FT.TCPNoDelayPrimary: 1
>      * FT.TCPPersistTimer: 500
>      * FT.TCPRcvBufSize: 131072
>      * FT.TCPSndBufSize: 131072
>      * FT.UseHostMonitor: 0
>      * FT.Vmknic: 
>      * FT.XmitSyncQueueLen: 64
>      * FT.adjDownInt: 10
>      * FT.adjDownPct: 10
>      * FT.adjUpInt: 200
>      * FT.adjUpPct: 10
>      * FT.execLatExtra: 500
>      * FT.maxLowerBound: 20
>      * FT.slowdownPctMax: 60
>      * FT.slowdownTimeMax: 600
>      * HBR.ChecksumIoSize: 8
>      * HBR.ChecksumMaxIo: 8
>      * HBR.ChecksumPerSlice: 2
>      * HBR.ChecksumRegionSize: 256
>      * HBR.ChecksumUseAllocInfo: 1
>      * HBR.ChecksumUseChecksumInfo: 1
>      * HBR.ChecksumZoneSize: 32768
>      * HBR.CopySnapDiskMaxExtentCount: 16
>      * HBR.CopySnapFidHashBuckets: 256
>      * HBR.DemandlogCompletedHashBuckets: 8
>      * HBR.DemandlogExtentHashBuckets: 512
>      * HBR.DemandlogIoTimeoutSecs: 120
>      * HBR.DemandlogReadRetries: 20
>      * HBR.DemandlogRetryDelayMs: 10
>      * HBR.DemandlogSendHashBuckets: 8
>      * HBR.DemandlogTransferIoSize: 8
>      * HBR.DemandlogTransferMaxIo: 4
>      * HBR.DemandlogTransferMaxNetwork: 8
>      * HBR.DemandlogTransferPerSlice: 2
>      * HBR.DemandlogWriteRetries: 20
>      * HBR.DisableChecksumOffload: 0
>      * HBR.DisconnectedEventDelayMs: 60000
>      * HBR.ErrThrottleChecksumIO: 1
>      * HBR.ErrThrottleDceRead: 1
>      * HBR.HbrBitmapAllocTimeoutMS: 3000
>      * HBR.HbrBitmapVMMaxStorageGB: 65536
>      * HBR.HbrBitmapVMMinStorageGB: 500
>      * HBR.HbrDemandLogIOPerVM: 64
>      * HBR.HbrDisableNetCompression: 1
>      * HBR.HbrLowerExtentBreakGB: 8192
>      * HBR.HbrLowerExtentSizeKB: 16
>      * HBR.HbrMaxExtentSizeKB: 64
>      * HBR.HbrMaxGuestXferWhileDeltaMB: 1024
>      * HBR.HbrMaxUnmapExtents: 10
>      * HBR.HbrMaxUnmapsInFlight: 128
>      * HBR.HbrMinExtentBreakGB: 2048
>      * HBR.HbrMinExtentSizeKB: 8
>      * HBR.HbrOptimizeFullSync: 1
>      * HBR.HbrResourceHeapPerVMSizeKB: 128
>      * HBR.HbrResourceHeapSizeMB: 2
>      * HBR.HbrResourceHeapUtilization: 95
>      * HBR.HbrResourceMaxDiskContexts: 512
>      * HBR.HbrRuntimeHeapMaxBaseMB: 1
>      * HBR.HbrRuntimeHeapMinBaseMB: 1
>      * HBR.HbrStaticHeapMaxBaseMB: 1
>      * HBR.HbrStaticHeapMinBaseMB: 1
>      * HBR.HbrUpperExtentBreakGB: 32768
>      * HBR.HbrUpperExtentSizeKB: 32
>      * HBR.HelperQueueMaxRequests: 8192
>      * HBR.HelperQueueMaxWorlds: 8
>      * HBR.LocalReadIoTimeoutSecs: 120
>      * HBR.MigrateFlushTimerSecs: 3
>      * HBR.NetworkUseCubic: 1
>      * HBR.NetworkerRecvHashBuckets: 64
>      * HBR.OpportunisticBlockListSize: 4000
>      * HBR.ProgressReportIntervalMs: 5000
>      * HBR.PsfIoTimeoutSecs: 300
>      * HBR.ReconnectFailureDelaySecs: 10
>      * HBR.ReconnectMaxDelaySecs: 90
>      * HBR.ResourceServerHashBuckets: 8
>      * HBR.RetryMaxDelaySecs: 60
>      * HBR.RetryMinDelaySecs: 1
>      * HBR.SyncTransferRetrySleepSecs: 5
>      * HBR.TransferDiskMaxIo: 32
>      * HBR.TransferDiskMaxNetwork: 64
>      * HBR.TransferDiskPerSlice: 16
>      * HBR.TransferFileExtentSize: 8192
>      * HBR.TransferMaxContExtents: 8
>      * HBR.WireChecksum: 1
>      * HBR.XferBitmapCheckIntervalSecs: 10
>      * ISCSI.MaxIoSizeKB: 128
>      * Irq.BestVcpuRouting: 0
>      * Irq.IRQActionAffinityWeight: 5
>      * Irq.IRQAvoidExclusive: 1
>      * Irq.IRQBHConflictWeight: 5
>      * Irq.IRQRebalancePeriod: 50
>      * Irq.IRQVcpuConflictWeight: 3
>      * LPage.LPageAlwaysTryForNPT: 1
>      * LPage.LPageDefragEnable: 1
>      * LPage.LPageMarkLowNodes: 1
>      * LPage.MaxSharedPages: 512
>      * LPage.MaxSwappedPagesInitVal: 10
>      * LPage.freePagesThresholdForRemote: 2048
>      * LSOM.blkAttrCacheSizePercent: 0
>      * Mem.AllocGuestLargePage: 1
>      * Mem.CtlMaxPercent: 65
>      * Mem.IdleTax: 75
>      * Mem.IdleTaxType: 1
>      * Mem.MemDefragClientsPerDir: 2
>      * Mem.MemMinFreePct: 0
>      * Mem.MemZipEnable: 1
>      * Mem.MemZipMaxAllocPct: 50
>      * Mem.MemZipMaxPct: 10
>      * Mem.SampleActivePctMin: 1
>      * Mem.SampleDirtiedPctMin: 0
>      * Mem.ShareForceSalting: 2
>      * Mem.ShareRateMax: 1024
>      * Mem.ShareScanGHz: 4
>      * Mem.ShareScanTime: 60
>      * Mem.VMOverheadGrowthLimit: 4294967295
>      * Migrate.AutoBindVmknic: 1
>      * Migrate.BindToVmknic: 3
>      * Migrate.CptCacheMaxSizeMB: 544
>      * Migrate.DebugChecksumMismatch: 0
>      * Migrate.DetectZeroPages: 1
>      * Migrate.DisableResumeDuringPageIn: 0
>      * Migrate.DiskOpsChunkSize: 131072
>      * Migrate.DiskOpsEnabled: 0
>      * Migrate.DiskOpsMaxRetries: 20
>      * Migrate.DiskOpsStreamChunks: 40
>      * Migrate.Enabled: 1
>      * Migrate.GetPageSysAlertThresholdMS: 10000
>      * Migrate.LowBandwidthSysAlertThreshold: 0
>      * Migrate.LowMemWaitSysAlertThresholdMS: 10000
>      * Migrate.MigrateCpuMinPctDefault: 30
>      * Migrate.MigrateCpuPctPerGb: 10
>      * Migrate.MigrateCpuSharesHighPriority: 60000
>      * Migrate.MigrateCpuSharesRegular: 30000
>      * Migrate.MonActionWaitSysAlertThresholdMS: 2000
>      * Migrate.NetExpectedLineRateMBps: 133
>      * Migrate.NetLatencyModeThreshold: 4
>      * Migrate.NetTimeout: 20
>      * Migrate.OutstandingReadKBMax: 128
>      * Migrate.PanicOnChecksumMismatch: 0
>      * Migrate.PreCopyCountDelay: 10
>      * Migrate.PreCopyMinProgressPerc: 130
>      * Migrate.PreCopyPagesPerSend: 32
>      * Migrate.PreCopySwitchoverTimeGoal: 500
>      * Migrate.PreallocLPages: 1
>      * Migrate.ProhibitFork: 0
>      * Migrate.RcvBufSize: 562540
>      * Migrate.RdpiTransitionTimeMs: 1
>      * Migrate.SdpsDynamicDelaySec: 30
>      * Migrate.SdpsEnabled: 2
>      * Migrate.SdpsTargetRate: 500
>      * Migrate.SndBufSize: 562540
>      * Migrate.TSMaster: 0
>      * Migrate.TcpTsoDeferTx: 0
>      * Migrate.TryToUseDefaultHeap: 1
>      * Migrate.VASpaceReserveCount: 128
>      * Migrate.VASpaceReserveSize: 768
>      * Migrate.VMotionLatencySensitivity: 1
>      * Migrate.VMotionResolveSwapType: 1
>      * Migrate.VMotionStreamDisable: 0
>      * Migrate.VMotionStreamHelpers: 0
>      * Migrate.Vmknic: 
>      * Misc.APDHandlingEnable: 1
>      * Misc.APDTimeout: 140
>      * Misc.BHTimeout: 0
>      * Misc.BhTimeBound: 2000
>      * Misc.BlueScreenTimeout: 0
>      * Misc.ConsolePort: none
>      * Misc.DebugBuddyEnable: 0
>      * Misc.DebugLogToSerial: 0
>      * Misc.DefaultHardwareVersion: 
>      * Misc.DsNsMgrTimeout: 1200000
>      * Misc.EnableHighDMA: 1
>      * Misc.GDBPort: none
>      * Misc.GuestLibAllowHostInfo: 0
>      * Misc.HeapMgrGuardPages: 1
>      * Misc.HeapPanicDestroyNonEmpty: 0
>      * Misc.HeartbeatInterval: 1000
>      * Misc.HeartbeatPanicTimeout: 900
>      * Misc.HeartbeatTimeout: 90
>      * Misc.HordeEnabled: 0
>      * Misc.HostAgentUpdateLevel: 3
>      * Misc.IntTimeout: 0
>      * Misc.IoFilterWatchdogTimeout: 120
>      * Misc.LogPort: none
>      * Misc.LogTimestampUptime: 0
>      * Misc.LogToFile: 1
>      * Misc.LogToSerial: 1
>      * Misc.LogWldPrefix: 1
>      * Misc.MCEMonitorInterval: 250
>      * Misc.MetadataUpdateTimeoutMsec: 30000
>      * Misc.MinimalPanic: 0
>      * Misc.NMILint1IntAction: 0
>      * Misc.PowerButton: 1
>      * Misc.PowerOffEnable: 1
>      * Misc.PreferredHostName: 
>      * Misc.ProcVerbose: 
>      * Misc.SIOControlFlag1: 0
>      * Misc.SIOControlFlag2: 0
>      * Misc.SIOControlLoglevel: 0
>      * Misc.SIOControlOptions: 
>      * Misc.ScreenSaverDelay: 0
>      * Misc.ShaperStatsEnabled: 1
>      * Misc.ShellPort: none
>      * Misc.TimerMaxHardPeriod: 500000
>      * Misc.TimerTolerance: 2000
>      * Misc.UsbArbitratorAutoStartDisabled: 0
>      * Misc.UserDuctDynBufferSize: 16384
>      * Misc.UserSocketUnixMaxBufferSize: 65536
>      * Misc.WatchdogBacktrace: 0
>      * Misc.WorldletActivationUS: 500
>      * Misc.WorldletActivationsLimit: 8
>      * Misc.WorldletGreedySampleMCycles: 10
>      * Misc.WorldletGreedySampleRun: 256
>      * Misc.WorldletIRQPenalty: 10
>      * Misc.WorldletLoadThreshold: 90
>      * Misc.WorldletLoadType: medium
>      * Misc.WorldletLocalityBonus: 10
>      * Misc.WorldletLoosePenalty: 30
>      * Misc.WorldletMigOverheadLLC: 4
>      * Misc.WorldletMigOverheadRemote: 16
>      * Misc.WorldletPreemptOverhead: 30
>      * Misc.WorldletRemoteActivateOverhead: 0
>      * Misc.WorldletWorldOverheadLLC: 0
>      * Misc.WorldletWorldOverheadRemote: 10
>      * Misc.vmmDisableL1DFlush: 0
>      * Misc.vsanWitnessVirtualAppliance: 0
>      * NFS.ApdStartCount: 3
>      * NFS.DiskFileLockUpdateFreq: 10
>      * NFS.HeartbeatDelta: 5
>      * NFS.HeartbeatFrequency: 12
>      * NFS.HeartbeatMaxFailures: 10
>      * NFS.HeartbeatTimeout: 5
>      * NFS.LockRenewMaxFailureNumber: 3
>      * NFS.LockUpdateTimeout: 5
>      * NFS.LogNfsStat3: 0
>      * NFS.MaxQueueDepth: 4294967295
>      * NFS.MaxVolumes: 8
>      * NFS.ReceiveBufferSize: 1024
>      * NFS.SendBufferSize: 1024
>      * NFS.SyncRetries: 25
>      * NFS.VolumeRemountFrequency: 30
>      * NFS41.EOSDelay: 30
>      * NFS41.IOTaskRetry: 25
>      * NFS41.MaxRead: 4294967295
>      * NFS41.MaxVolumes: 8
>      * NFS41.MaxWrite: 4294967295
>      * NFS41.MountTimeout: 30
>      * NFS41.RecvBufSize: 1024
>      * NFS41.SendBufSize: 1024
>      * Net.AdvertisementDuration: 60
>      * Net.AllowPT: 1
>      * Net.BlockGuestBPDU: 0
>      * Net.CoalesceDefaultOn: 1
>      * Net.CoalesceFavorNoVmmVmkTx: 1
>      * Net.CoalesceFineTimeoutCPU: 2
>      * Net.CoalesceFineTxTimeout: 1000
>      * Net.CoalesceFlexMrq: 1
>      * Net.CoalesceLowRxRate: 4
>      * Net.CoalesceLowTxRate: 4
>      * Net.CoalesceMatchedQs: 1
>      * Net.CoalesceMrqLt: 1
>      * Net.CoalesceMrqMetricAllowTxOnly: 1
>      * Net.CoalesceMrqMetricRxOnly: 0
>      * Net.CoalesceMrqOverallStop: 0
>      * Net.CoalesceMrqRatioMetric: 1
>      * Net.CoalesceMrqTriggerReCalib: 1
>      * Net.CoalesceMultiRxQCalib: 1
>      * Net.CoalesceNoVmmVmkTx: 1
>      * Net.CoalesceParams: 
>      * Net.CoalesceRBCRate: 4000
>      * Net.CoalesceRxLtStopCalib: 0
>      * Net.CoalesceRxQDepthCap: 40
>      * Net.CoalesceScheme: rbc
>      * Net.CoalesceTimeoutType: 2
>      * Net.CoalesceTxAlwaysPoll: 1
>      * Net.CoalesceTxQDepthCap: 40
>      * Net.CoalesceTxTimeout: 4000
>      * Net.DCBEnable: 1
>      * Net.DVFilterBindIpAddress: 
>      * Net.DVFilterPriorityRdLockEnable: 1
>      * Net.DVSLargeHeapMaxSize: 80
>      * Net.DontOffloadInnerIPv6: 0
>      * Net.E1000IntrCoalesce: 1
>      * Net.E1000TxCopySize: 2048
>      * Net.E1000TxZeroCopy: 1
>      * Net.EnableDMASgCons: 1
>      * Net.EnableOuterCsum: 1
>      * Net.EtherswitchAllowFastPath: 0
>      * Net.EtherswitchHashSize: 1
>      * Net.EtherswitchHeapMax: 512
>      * Net.EtherswitchNumPerPCPUDispatchData: 3
>      * Net.FollowHardwareMac: 1
>      * Net.GuestIPHack: 0
>      * Net.GuestTxCopyBreak: 64
>      * Net.IGMPQueries: 2
>      * Net.IGMPQueryInterval: 125
>      * Net.IGMPRouterIP: 0.0.0.0
>      * Net.IGMPV3MaxSrcIPNum: 10
>      * Net.IGMPVersion: 3
>      * Net.IOControlPnicOptOut: 
>      * Net.LRODefBackoffPeriod: 8
>      * Net.LRODefMaxLength: 65535
>      * Net.LRODefThreshold: 4000
>      * Net.LRODefUseRatioDenom: 3
>      * Net.LRODefUseRatioNumer: 1
>      * Net.LinkFlappingThreshold: 60
>      * Net.LinkStatePollTimeout: 500
>      * Net.MLDRouterIP: FE80::FFFF:FFFF:FFFF:FFFF
>      * Net.MLDV2MaxSrcIPNum: 10
>      * Net.MLDVersion: 2
>      * Net.MaxBeaconVlans: 100
>      * Net.MaxBeaconsAtOnce: 100
>      * Net.MaxGlobalRxQueueCount: 100000
>      * Net.MaxNetifTxQueueLen: 2000
>      * Net.MaxPageInQueueLen: 75
>      * Net.MaxPktRxListQueue: 3500
>      * Net.MaxPortRxQueueLen: 80
>      * Net.MinEtherLen: 60
>      * Net.NcpLlcSap: 0
>      * Net.NetBHRxStormThreshold: 320
>      * Net.NetDebugRARPTimerInter: 30000
>      * Net.NetDeferTxCompletion: 1
>      * Net.NetDiscUpdateIntrvl: 300
>      * Net.NetEnableSwCsumForLro: 1
>      * Net.NetEsxfwPassOutboundGRE: 1
>      * Net.NetInStressTest: 0
>      * Net.NetLatencyAwareness: 1
>      * Net.NetMaxRarpsPerInterval: 128
>      * Net.NetNetqMaxDefQueueFilters: 4096
>      * Net.NetNetqNumaIOCpuPinThreshold: 0
>      * Net.NetNetqRxRebalRSSLoadThresholdPerc: 10
>      * Net.NetNetqTxPackKpps: 300
>      * Net.NetNetqTxUnpackKpps: 600
>      * Net.NetNiocAllowOverCommit: 1
>      * Net.NetPTMgrWakeupInterval: 6
>      * Net.NetPktAllocTries: 5
>      * Net.NetPktSlabFreePercentThreshold: 2
>      * Net.NetPortFlushIterLimit: 2
>      * Net.NetPortFlushPktLimit: 64
>      * Net.NetPortTrackTxRace: 0
>      * Net.NetRmDistMacFilter: 1
>      * Net.NetRmDistSamplingRate: 0
>      * Net.NetRxCopyInTx: 0
>      * Net.NetSchedCoalesceTxUsecs: 33
>      * Net.NetSchedDefaultResPoolSharesPct: 5
>      * Net.NetSchedDefaultSchedName: fifo
>      * Net.NetSchedECNEnabled: 1
>      * Net.NetSchedECNThreshold: 70
>      * Net.NetSchedHClkLeafQueueDepthPkt: 500
>      * Net.NetSchedHClkMQ: 0
>      * Net.NetSchedHClkMaxHwQueue: 2
>      * Net.NetSchedHeapMaxSizeMB: 64
>      * Net.NetSchedInFlightMaxBytesDefault: 20000
>      * Net.NetSchedInFlightMaxBytesInsane: 1500000
>      * Net.NetSchedMaxPktSend: 256
>      * Net.NetSchedQoSSchedName: hclk
>      * Net.NetSchedSpareBasedShares: 1
>      * Net.NetSendRARPOnPortEnablement: 1
>      * Net.NetShaperQueuePerL3L4Flow: 1
>      * Net.NetSplitRxMode: 1
>      * Net.NetTraceEnable: 0
>      * Net.NetTuneHostMode: default
>      * Net.NetTuneInterval: 60
>      * Net.NetTuneThreshold: 1n 2n 50
>      * Net.NetTxDontClusterSize: 0
>      * Net.NetVMTxType: 2
>      * Net.NetVmxnet3TxHangTimeout: 0
>      * Net.NetpollSwLRO: 1
>      * Net.NoLocalCSum: 0
>      * Net.NotifySwitch: 1
>      * Net.PTSwitchingTimeout: 20000
>      * Net.PVRDMAVmknic: 
>      * Net.PortDisableTimeout: 5000
>      * Net.ReversePathFwdCheck: 1
>      * Net.ReversePathFwdCheckPromisc: 0
>      * Net.TcpipCopySmallTx: 1
>      * Net.TcpipDefLROEnabled: 1
>      * Net.TcpipDefLROMaxLength: 32768
>      * Net.TcpipDgramRateLimiting: 1
>      * Net.TcpipEnableABC: 1
>      * Net.TcpipEnableFlowtable: 1
>      * Net.TcpipEnableSendScaling: 1
>      * Net.TcpipHWLRONoDelayAck: 1
>      * Net.TcpipHeapMax: 1024
>      * Net.TcpipHeapSize: 0
>      * Net.TcpipIGMPDefaultVersion: 3
>      * Net.TcpipIGMPRejoinInterval: 60
>      * Net.TcpipLODispatchQueueMaxLen: 128
>      * Net.TcpipLRONoDelayAck: 1
>      * Net.TcpipLogPackets: 0
>      * Net.TcpipLogPacketsCount: 24570
>      * Net.TcpipMaxNetstackInstances: 48
>      * Net.TcpipNoBcopyRx: 1
>      * Net.TcpipPendPktSocketFreeTimeout: 300
>      * Net.TcpipRxDispatchQueueMaxLen: 2000
>      * Net.TcpipRxDispatchQueues: 1
>      * Net.TcpipRxDispatchQuota: 200
>      * Net.TcpipRxVmknicWorldletAffinityType: 0
>      * Net.TcpipTxDispatchQuota: 100
>      * Net.TcpipTxqBackoffTimeoutMs: 70
>      * Net.TcpipTxqMaxUsageThreshold: 80
>      * Net.TeamPolicyUpDelay: 100
>      * Net.TrafficFilterIpAddress: 
>      * Net.TsoDumpPkt: 0
>      * Net.UplinkAbortDisconnectTimeout: 5000
>      * Net.UplinkKillAsyncTimeout: 10000
>      * Net.UplinkTxQueuesDispEnabled: 1
>      * Net.UseHwCsumForIPv6Csum: 1
>      * Net.UseHwIPv6Csum: 1
>      * Net.UseHwTSO: 1
>      * Net.UseHwTSO6: 1
>      * Net.UseLegacyProc: 0
>      * Net.UseProc: 0
>      * Net.VLANMTUCheckMode: 1
>      * Net.VmklnxLROEnabled: 0
>      * Net.VmklnxLROMaxAggr: 6
>      * Net.VmknicDoLroSplit: 0
>      * Net.VmknicLroSplitBnd: 12
>      * Net.Vmxnet2HwLRO: 1
>      * Net.Vmxnet2PinRxBuf: 0
>      * Net.Vmxnet2SwLRO: 1
>      * Net.Vmxnet3HwLRO: 1
>      * Net.Vmxnet3PageInBound: 32
>      * Net.Vmxnet3RSSHashCache: 1
>      * Net.Vmxnet3RxPollBound: 256
>      * Net.Vmxnet3SwLRO: 1
>      * Net.Vmxnet3WinIntrHints: 1
>      * Net.Vmxnet3usePNICHash: 0
>      * Net.VmxnetBiDirNeedsTsoTx: 1
>      * Net.VmxnetBiDirNoTsoSplit: 1
>      * Net.VmxnetCopyTxRunLimit: 16
>      * Net.VmxnetDoLroSplit: 1
>      * Net.VmxnetDoTsoSplit: 1
>      * Net.VmxnetLROBackoffPeriod: 8
>      * Net.VmxnetLROMaxLength: 32000
>      * Net.VmxnetLROThreshold: 4000
>      * Net.VmxnetLROUseRatioDenom: 3
>      * Net.VmxnetLROUseRatioNumer: 2
>      * Net.VmxnetLroSplitBnd: 64
>      * Net.VmxnetPromDisableLro: 1
>      * Net.VmxnetSwLROSL: 1
>      * Net.VmxnetTsoSplitBnd: 12
>      * Net.VmxnetTsoSplitSize: 17500
>      * Net.VmxnetTxCopySize: 256
>      * Net.VmxnetWinCopyTxRunLimit: 65535
>      * Net.VmxnetWinUDPTxFullCopy: 1
>      * Net.vNicNumDeferredReset: 12
>      * Net.vNicTxPollBound: 192
>      * Net.vmxnetThroughputWeight: 0
>      * Nmp.NmpPReservationCmdRetryTime: 1
>      * Nmp.NmpSatpAluaCmdRetryTime: 10
>      * Numa.CoreCapRatioPct: 90
>      * Numa.CostopSkewAdjust: 1
>      * Numa.FollowCoresPerSocket: 0
>      * Numa.LTermFairnessInterval: 5
>      * Numa.LTermMigImbalThreshold: 10
>      * Numa.LargeInterleave: 1
>      * Numa.LocalityWeightActionAffinity: 130
>      * Numa.LocalityWeightMem: 1
>      * Numa.MigImbalanceThreshold: 10
>      * Numa.MigPreventLTermThresh: 0
>      * Numa.MigThrashThreshold: 50
>      * Numa.MigThreshold: 2
>      * Numa.MonMigEnable: 1
>      * Numa.PageMigEnable: 1
>      * Numa.PageMigLinearRun: 95
>      * Numa.PageMigRandomRun: 5
>      * Numa.PageMigRateMax: 8000
>      * Numa.PreferHT: 0
>      * Numa.RebalanceCoresNode: 2
>      * Numa.RebalanceCoresTotal: 4
>      * Numa.RebalanceEnable: 1
>      * Numa.RebalancePeriod: 2000
>      * Numa.SwapConsiderPeriod: 15
>      * Numa.SwapInterval: 3
>      * Numa.SwapLoadEnable: 1
>      * Numa.SwapLocalityEnable: 1
>      * Numa.SwapMigrateOnly: 2
>      * Power.CStateMaxLatency: 500
>      * Power.CStatePredictionCoef: 110479
>      * Power.CStateResidencyCoef: 5
>      * Power.ChargeMemoryPct: 20
>      * Power.MaxCpuLoad: 60
>      * Power.MaxFreqPct: 100
>      * Power.MinFreqPct: 0
>      * Power.PerfBias: 17
>      * Power.PerfBiasEnable: 1
>      * Power.TimerHz: 100
>      * Power.UseCStates: 1
>      * Power.UsePStates: 1
>      * RdmFilter.HbaIsShared: True
>      * ScratchConfig.ConfiguredScratchLocation: 
>      * ScratchConfig.CurrentScratchLocation: /tmp/scratch
>      * Scsi.ChangeQErrSetting: 1
>      * Scsi.CompareLUNNumber: 1
>      * Scsi.ExtendAPDCondition: 0
>      * Scsi.FailVMIOonAPD: 0
>      * Scsi.LogCmdErrors: 1
>      * Scsi.LogCmdRCErrorsFreq: 0
>      * Scsi.LogMPCmdErrors: 1
>      * Scsi.LogScsiAborts: 0
>      * Scsi.LunCleanupInterval: 7
>      * Scsi.MaxReserveBacktrace: 0
>      * Scsi.MaxReserveTime: 200
>      * Scsi.MaxReserveTotalTime: 250
>      * Scsi.PassthroughLocking: 1
>      * Scsi.ReserveBacktrace: 0
>      * Scsi.SCSIEnableDescToFixedConv: 1
>      * Scsi.SCSIEnableIOLatencyMsgs: 0
>      * Scsi.SCSIStrictSPCVersionChecksForPEs: 0
>      * Scsi.SCSITimeout_ReabortTime: 5000
>      * Scsi.SCSITimeout_ScanTime: 1000
>      * Scsi.SCSIioTraceBufSizeMB: 1
>      * Scsi.ScanOnDriverLoad: 1
>      * Scsi.ScanSync: 0
>      * Scsi.ScsiRestartStalledQueueLatency: 500
>      * Scsi.ScsiVVolPESNRO: 128
>      * Scsi.TimeoutTMThreadExpires: 1800
>      * Scsi.TimeoutTMThreadLatency: 2000
>      * Scsi.TimeoutTMThreadMax: 16
>      * Scsi.TimeoutTMThreadMin: 1
>      * Scsi.TimeoutTMThreadRetry: 2000
>      * Scsi.TransFailLogPct: 20
>      * Scsi.UseAdaptiveRetries: 1
>      * Security.AccountLockFailures: 5
>      * Security.AccountUnlockTime: 900
>      * Security.PasswordQualityControl: retry=3 min=disabled,disabled,disabled,7,7
>      * SunRPC.MaxConnPerIP: 4
>      * SunRPC.SendLowat: 25
>      * SunRPC.WorldletAffinity: 2
>      * SvMotion.SvMotionAvgDisksPerVM: 8
>      * Syslog.global.defaultRotate: 8
>      * Syslog.global.defaultSize: 1024
>      * Syslog.global.logDir: [] /scratch/log
>      * Syslog.global.logDirUnique: False
>      * Syslog.global.logHost: 192.168.1.200
>      * Syslog.loggers.Xorg.rotate: 8
>      * Syslog.loggers.Xorg.size: 1024
>      * Syslog.loggers.auth.rotate: 8
>      * Syslog.loggers.auth.size: 1024
>      * Syslog.loggers.clomd.rotate: 8
>      * Syslog.loggers.clomd.size: 1024
>      * Syslog.loggers.cmmdsTimeMachine.rotate: 8
>      * Syslog.loggers.cmmdsTimeMachine.size: 1024
>      * Syslog.loggers.cmmdsTimeMachineDump.rotate: 20
>      * Syslog.loggers.cmmdsTimeMachineDump.size: 10240
>      * Syslog.loggers.ddecomd.rotate: 8
>      * Syslog.loggers.ddecomd.size: 1024
>      * Syslog.loggers.dhclient.rotate: 8
>      * Syslog.loggers.dhclient.size: 1024
>      * Syslog.loggers.epd.rotate: 8
>      * Syslog.loggers.epd.size: 1024
>      * Syslog.loggers.esxupdate.rotate: 8
>      * Syslog.loggers.esxupdate.size: 1024
>      * Syslog.loggers.fdm.rotate: 8
>      * Syslog.loggers.fdm.size: 1024
>      * Syslog.loggers.hbrca.rotate: 8
>      * Syslog.loggers.hbrca.size: 1024
>      * Syslog.loggers.hostd-probe.rotate: 8
>      * Syslog.loggers.hostd-probe.size: 1024
>      * Syslog.loggers.hostd.rotate: 8
>      * Syslog.loggers.hostd.size: 1024
>      * Syslog.loggers.hostdCgiServer.rotate: 8
>      * Syslog.loggers.hostdCgiServer.size: 1024
>      * Syslog.loggers.hostprofiletrace.rotate: 8
>      * Syslog.loggers.hostprofiletrace.size: 1024
>      * Syslog.loggers.iofiltervpd.rotate: 8
>      * Syslog.loggers.iofiltervpd.size: 1024
>      * Syslog.loggers.lacp.rotate: 8
>      * Syslog.loggers.lacp.size: 1024
>      * Syslog.loggers.nfcd.rotate: 8
>      * Syslog.loggers.nfcd.size: 1024
>      * Syslog.loggers.osfsd.rotate: 8
>      * Syslog.loggers.osfsd.size: 1024
>      * Syslog.loggers.rabbitmqproxy.rotate: 8
>      * Syslog.loggers.rabbitmqproxy.size: 1024
>      * Syslog.loggers.rhttpproxy.rotate: 8
>      * Syslog.loggers.rhttpproxy.size: 1024
>      * Syslog.loggers.sdrsInjector.rotate: 8
>      * Syslog.loggers.sdrsInjector.size: 1024
>      * Syslog.loggers.shell.rotate: 8
>      * Syslog.loggers.shell.size: 1024
>      * Syslog.loggers.storageRM.rotate: 8
>      * Syslog.loggers.storageRM.size: 1024
>      * Syslog.loggers.swapobjd.rotate: 8
>      * Syslog.loggers.swapobjd.size: 1024
>      * Syslog.loggers.syslog.rotate: 8
>      * Syslog.loggers.syslog.size: 1024
>      * Syslog.loggers.upitd.rotate: 8
>      * Syslog.loggers.upitd.size: 1024
>      * Syslog.loggers.usb.rotate: 8
>      * Syslog.loggers.usb.size: 1024
>      * Syslog.loggers.vitd.rotate: 8
>      * Syslog.loggers.vitd.size: 10240
>      * Syslog.loggers.vmauthd.rotate: 8
>      * Syslog.loggers.vmauthd.size: 1024
>      * Syslog.loggers.vmkdevmgr.rotate: 8
>      * Syslog.loggers.vmkdevmgr.size: 1024
>      * Syslog.loggers.vmkernel.rotate: 8
>      * Syslog.loggers.vmkernel.size: 1024
>      * Syslog.loggers.vmkeventd.rotate: 8
>      * Syslog.loggers.vmkeventd.size: 1024
>      * Syslog.loggers.vmksummary.rotate: 8
>      * Syslog.loggers.vmksummary.size: 1024
>      * Syslog.loggers.vmkwarning.rotate: 8
>      * Syslog.loggers.vmkwarning.size: 1024
>      * Syslog.loggers.vobd.rotate: 8
>      * Syslog.loggers.vobd.size: 1024
>      * Syslog.loggers.vprobe.rotate: 8
>      * Syslog.loggers.vprobe.size: 1024
>      * Syslog.loggers.vpxa.rotate: 8
>      * Syslog.loggers.vpxa.size: 1024
>      * Syslog.loggers.vsanSoapServer.rotate: 8
>      * Syslog.loggers.vsanSoapServer.size: 5120
>      * Syslog.loggers.vsanmgmt.rotate: 8
>      * Syslog.loggers.vsanmgmt.size: 10240
>      * Syslog.loggers.vsansystem.rotate: 10
>      * Syslog.loggers.vsansystem.size: 10240
>      * Syslog.loggers.vsantraceUrgent.rotate: 8
>      * Syslog.loggers.vsantraceUrgent.size: 1024
>      * Syslog.loggers.vvold.rotate: 16
>      * Syslog.loggers.vvold.size: 8192
>      * User.PTEDisableNX: 0
>      * User.ReaddirRetries: 10
>      * UserVars.ActiveDirectoryPreferredDomainControllers: 
>      * UserVars.ActiveDirectoryVerifyCAMCertificate: 1
>      * UserVars.DcuiTimeOut: 600
>      * UserVars.ESXiShellInteractiveTimeOut: 0
>      * UserVars.ESXiShellTimeOut: 0
>      * UserVars.ESXiVPsAllowedCiphers: !aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES
>      * UserVars.ESXiVPsDisabledProtocols: sslv3
>      * UserVars.EsximageNetRateLimit: 0
>      * UserVars.EsximageNetRetries: 10
>      * UserVars.EsximageNetTimeout: 60
>      * UserVars.HardwareHealthIgnoredSensors: 
>      * UserVars.HardwareHealthSyncTime: 360
>      * UserVars.HostClientCEIPOptIn: 2
>      * UserVars.HostClientDefaultConsole: webmks
>      * UserVars.HostClientEnableMOTDNotification: 1
>      * UserVars.HostClientEnableVisualEffects: 1
>      * UserVars.HostClientSessionTimeout: 900
>      * UserVars.HostClientShowOnlyRecentObjects: 1
>      * UserVars.HostClientWelcomeMessage: Welcome to {{hostname}}
>      * UserVars.HostdStatsstoreRamdiskSize: 0
>      * UserVars.ProductLockerLocation: /locker/packages/6.5.0/
>      * UserVars.SuppressCoredumpWarning: 0
>      * UserVars.SuppressHyperthreadWarning: 0
>      * UserVars.SuppressShellWarning: 1
>      * UserVars.ToolsRamdisk: 0
>      * UserVars.vGhettoSetup: 1
>      * VFLASH.CacheStatsEnable: 1
>      * VFLASH.CacheStatsFromVFC: 1
>      * VFLASH.MaxCacheFileSizeMB: 409600
>      * VFLASH.MaxDiskFileSizeGB: 16384
>      * VFLASH.MaxHeapSizeMB: 32
>      * VFLASH.MaxResourceGBForVmCache: 2048
>      * VFLASH.ResourceUsageThreshold: 80
>      * VMFS.UnresolvedVolumeLiveCheck: True
>      * VMFS3.EnableBlockDelete: 0
>      * VMFS3.FailVolumeOpenIfAPD: 0
>      * VMFS3.HardwareAcceleratedLocking: 1
>      * VMFS3.LFBCSlabSizeMaxMB: 8
>      * VMFS3.MaxAddressableSpaceTB: 32
>      * VMFS3.MaxHeapSizeMB: 256
>      * VMFS3.MaxextendedTxnsUsingfs3Heap: 20
>      * VMFS3.MinAddressableSpaceTB: 0
>      * VMFS3.OpenWithoutJournal: 1
>      * VMFS3.PBCapMissRatioIntervalSec: 60
>      * VMFS3.StAtExclLockEnd: 0
>      * VMFS3.UseATSForHBOnVMFS5: 1
>      * VMkernel.Boot.allowNonNX: False
>      * VMkernel.Boot.autoCreateDumpFile: True
>      * VMkernel.Boot.autoPartition: False
>      * VMkernel.Boot.autoPartitionCreateUSBCoreDumpPartition: False
>      * VMkernel.Boot.autoPartitionDiskDumpPartitionSize: 2560
>      * VMkernel.Boot.bootDeviceRescanTimeout: 1
>      * VMkernel.Boot.busSpeedMayVary: False
>      * VMkernel.Boot.cacheFlushImmOnAllHalt: False
>      * VMkernel.Boot.checkCPUIDLimit: True
>      * VMkernel.Boot.checkPages: False
>      * VMkernel.Boot.com1_baud: 115200
>      * VMkernel.Boot.com2_baud: 115200
>      * VMkernel.Boot.coresPerPkg: 0
>      * VMkernel.Boot.debugBreak: False
>      * VMkernel.Boot.debugLogToSerial: 2
>      * VMkernel.Boot.disableACSCheck: False
>      * VMkernel.Boot.disableCFOH: False
>      * VMkernel.Boot.disableHwrng: False
>      * VMkernel.Boot.diskDumpSlotSize: 0
>      * VMkernel.Boot.dmaEngineExposeIdentityMapping: True
>      * VMkernel.Boot.dmaMapperPolicy: disabled
>      * VMkernel.Boot.enableACSCheckForRP: False
>      * VMkernel.Boot.execInstalledOnly: False
>      * VMkernel.Boot.fsCheck: False
>      * VMkernel.Boot.gdbPort: default
>      * VMkernel.Boot.generalCriticalMemory: 0
>      * VMkernel.Boot.heapCheckTimerInterval: 10
>      * VMkernel.Boot.heapFreeOwnerCheck: False
>      * VMkernel.Boot.heapFreePoisonByte: 255
>      * VMkernel.Boot.heapMetaPoisonByte: 90
>      * VMkernel.Boot.heapMetadataProtect: False
>      * VMkernel.Boot.heapMgrTotalVASpaceGB: 512
>      * VMkernel.Boot.heapPoisonFreeMem: False
>      * VMkernel.Boot.heapPoisonTimerChecks: False
>      * VMkernel.Boot.hyperthreading: True
>      * VMkernel.Boot.hyperthreadingMitigation: False
>      * VMkernel.Boot.ignoreMsrFaults: False
>      * VMkernel.Boot.intrBalancingEnabled: True
>      * VMkernel.Boot.ioAbilityChecks: False
>      * VMkernel.Boot.iovDisableIR: False
>      * VMkernel.Boot.ipmiEnabled: True
>      * VMkernel.Boot.isPerFileSchedModelActive: True
>      * VMkernel.Boot.leaveWakeGPEsDisabled: True
>      * VMkernel.Boot.logPort: default
>      * VMkernel.Boot.maxLogEntries: 0
>      * VMkernel.Boot.maxPCPUS: 576
>      * VMkernel.Boot.maxPCPUsNUMAInterleaving: True
>      * VMkernel.Boot.maxVMs: 0
>      * VMkernel.Boot.memCheckEveryWord: False
>      * VMkernel.Boot.memLowReservedMB: 0
>      * VMkernel.Boot.memmapMaxEarlyPoisonMemMB: 65536
>      * VMkernel.Boot.memmapMaxPhysicalMemMB: 16777216
>      * VMkernel.Boot.memmapMaxRAMMB: 12582912
>      * VMkernel.Boot.microcodeUpdate: True
>      * VMkernel.Boot.microcodeUpdateForce: False
>      * VMkernel.Boot.netCoalesceTimerHdlrPcpu: 0
>      * VMkernel.Boot.netGPHeapMaxMBPerGB: 4
>      * VMkernel.Boot.netMaxPktsToProcess: 64
>      * VMkernel.Boot.netNetqueueEnabled: True
>      * VMkernel.Boot.netPagePoolLimitCap: 98304
>      * VMkernel.Boot.netPagePoolLimitPerGB: 5120
>      * VMkernel.Boot.netPagePoolResvCap: 0
>      * VMkernel.Boot.netPagePoolResvPerGB: 0
>      * VMkernel.Boot.netPktHeapMaxMBPerGB: 6
>      * VMkernel.Boot.netPktHeapMinMBPerGB: 0
>      * VMkernel.Boot.netPktPoolMaxMBPerGB: 75
>      * VMkernel.Boot.netPktPoolMinMBPerGB: 0
>      * VMkernel.Boot.netPreemptionEnabled: False
>      * VMkernel.Boot.nmiAction: 0
>      * VMkernel.Boot.numaLatencyRemoteThresholdPct: 10
>      * VMkernel.Boot.overrideDuplicateImageDetection: False
>      * VMkernel.Boot.pciBarAllocPolicy: 0
>      * VMkernel.Boot.pcipDisablePciErrReporting: True
>      * VMkernel.Boot.poisonMarker: -6148914691236517206
>      * VMkernel.Boot.poisonPagePool: False
>      * VMkernel.Boot.preferVmklinux: False
>      * VMkernel.Boot.preventFreePageMapping: False
>      * VMkernel.Boot.rdmaRoceIPBasedGidGeneration: True
>      * VMkernel.Boot.rtcEnableEFI: True
>      * VMkernel.Boot.rtcEnableLegacy: True
>      * VMkernel.Boot.rtcEnableTAD: True
>      * VMkernel.Boot.scrubIgnoredPages: False
>      * VMkernel.Boot.scrubMemoryAfterModuleLoad: False
>      * VMkernel.Boot.serialUntrusted: True
>      * VMkernel.Boot.skipPartitioningSsds: False
>      * VMkernel.Boot.storageHeapMaxSize: 0
>      * VMkernel.Boot.storageHeapMinSize: 0
>      * VMkernel.Boot.storageMaxDevices: 512
>      * VMkernel.Boot.storageMaxPaths: 2048
>      * VMkernel.Boot.storageMaxVMsPerDevice: 32
>      * VMkernel.Boot.terminateVMOnPDL: False
>      * VMkernel.Boot.timerEnableACPI: True
>      * VMkernel.Boot.timerEnableHPET: True
>      * VMkernel.Boot.timerEnableTSC: True
>      * VMkernel.Boot.timerForceTSC: False
>      * VMkernel.Boot.tscSpeedMayVary: False
>      * VMkernel.Boot.tty1Port: default
>      * VMkernel.Boot.tty2Port: default
>      * VMkernel.Boot.updateBusIRQ: False
>      * VMkernel.Boot.useNUMAInfo: True
>      * VMkernel.Boot.useReliableMem: True
>      * VMkernel.Boot.useSLIT: True
>      * VMkernel.Boot.vmkATKeyboard: False
>      * VMkernel.Boot.vmkacEnable: 1
>      * VMkernel.Boot.vtdSuperPages: True
>      * VSAN-iSCSI.iscsiPingTimeout: 5
>      * VSAN.AutoTerminateGhostVm: 1
>      * VSAN.ClomMaxComponentSizeGB: 255
>      * VSAN.ClomMaxDiskUsageRepairComps: 95
>      * VSAN.ClomRebalanceThreshold: 80
>      * VSAN.ClomRepairDelay: 60
>      * VSAN.DedupScope: 0
>      * VSAN.DefaultHostDecommissionMode: ensureAccessibility
>      * VSAN.DomBriefIoTraces: 0
>      * VSAN.DomFullIoTraces: 0
>      * VSAN.DomLongOpTraceMS: 1000
>      * VSAN.DomLongOpUrgentTraceMS: 10000
>      * VSAN.ObjectScrubsPerYear: 1
>      * VSAN.PerTraceBandwidthLimit: 0
>      * VSAN.PerTraceBandwidthLimitPeriodMs: 10000
>      * VSAN.PerTraceMaxRolloverPeriods: 360
>      * VSAN.SwapThickProvisionDisabled: 1
>      * VSAN.TraceEnableCmmds: 1
>      * VSAN.TraceEnableDom: 1
>      * VSAN.TraceEnableDomIo: 0
>      * VSAN.TraceEnableLchk: 1
>      * VSAN.TraceEnableLsom: 1
>      * VSAN.TraceEnablePlog: 1
>      * VSAN.TraceEnableRdt: 1
>      * VSAN.TraceEnableSsdLog: 1
>      * VSAN.TraceEnableVirsto: 1
>      * VSAN.TraceEnableVsanSparse: 1
>      * VSAN.TraceEnableVsanSparseIO: 0
>      * VSAN.TraceEnableVsanSparseVerbose: 0
>      * VSAN.TraceGlobalBandwidthLimit: 0
>      * VSAN.TraceGlobalBandwidthLimitPeriodMs: 10000
>      * VSAN.TraceGlobalMaxRolloverPeriods: 360
>      * VSAN.VsanSparseCacheOverEvict: 5
>      * VSAN.VsanSparseCacheThreshold: 1024
>      * VSAN.VsanSparseEnabled: 1
>      * VSAN.VsanSparseHeapSize: 65536
>      * VSAN.VsanSparseMaxExtentsPrefetch: 64
>      * VSAN.VsanSparseParallelLookup: 1
>      * VSAN.VsanSparseRetainCacheOnSnapshots: 1
>      * VSAN.VsanSparseRetainCacheTTL: 20
>      * VSAN.VsanSparseSpeculativePrefetch: 4194304
>      * Virsto.DiskFormatVersion: 5
>      * Virsto.Enabled: 1
>      * Virsto.FlusherRegistryThreshold: 50
>      * Virsto.GweFetchExtentsFactor: 3
>      * Virsto.InstanceHeapLimit: 130
>      * Virsto.MapBlocksFlushThreshold: 90
>      * Virsto.MapBlocksMin: 16384
>      * Virsto.MaxMFRetryCount: 3
>      * Virsto.MsecBeforeMetaFlush: 10000
>      * Virsto.RecordsPerFormatWrite: 16
>      * Virsto.SharedHeapLimit: 4
>      * Vpx.Vpxa.config.httpNfc.accessMode: proxyAuto
>      * Vpx.Vpxa.config.httpNfc.enabled: true
>      * Vpx.Vpxa.config.level[SoapAdapter.HTTPService.HttpConnection].logLevel: info
>      * Vpx.Vpxa.config.level[SoapAdapter.HTTPService.HttpConnection].logName: SoapAdapter.HTTPService.HttpConnection
>      * Vpx.Vpxa.config.level[SoapAdapter.HTTPService].logLevel: info
>      * Vpx.Vpxa.config.level[SoapAdapter.HTTPService].logName: SoapAdapter.HTTPService
>      * Vpx.Vpxa.config.log.level: verbose
>      * Vpx.Vpxa.config.log.maxFileNum: 10
>      * Vpx.Vpxa.config.log.maxFileSize: 1048576
>      * Vpx.Vpxa.config.log.memoryLevel: verbose
>      * Vpx.Vpxa.config.log.outputToConsole: false
>      * Vpx.Vpxa.config.log.outputToFiles: false
>      * Vpx.Vpxa.config.log.outputToSyslog: true
>      * Vpx.Vpxa.config.log.syslog.facility: local4
>      * Vpx.Vpxa.config.log.syslog.ident: Vpxa
>      * Vpx.Vpxa.config.log.syslog.logHeaderFile: /var/run/vmware/vpxaLogHeader.txt
>      * Vpx.Vpxa.config.nfc.loglevel: error
>      * Vpx.Vpxa.config.task.completedMaxEntries: 1000
>      * Vpx.Vpxa.config.task.maxThreads: 98
>      * Vpx.Vpxa.config.task.minCompletedLifetime: 120
>      * Vpx.Vpxa.config.trace.mutex.profiledMutexes: InvtLock
>      * Vpx.Vpxa.config.trace.vmomi.calls: false
>      * Vpx.Vpxa.config.vmacore.http.defaultClientPoolConnectionsPerServer: 300
>      * Vpx.Vpxa.config.vmacore.soap.sessionTimeout: 1440
>      * Vpx.Vpxa.config.vmacore.ssl.doVersionCheck: false
>      * Vpx.Vpxa.config.vmacore.threadPool.IoMax: 9
>      * Vpx.Vpxa.config.vmacore.threadPool.TaskMax: 4
>      * Vpx.Vpxa.config.vmacore.threadPool.ThreadStackSizeKb: 128
>      * Vpx.Vpxa.config.vmacore.threadPool.threadNamePrefix: vpxa
>      * Vpx.Vpxa.config.vpxa.bundleVersion: 1000000
>      * Vpx.Vpxa.config.vpxa.datastorePrincipal: root
>      * Vpx.Vpxa.config.vpxa.hostIp: esxi01
>      * Vpx.Vpxa.config.vpxa.hostPort: 443
>      * Vpx.Vpxa.config.vpxa.licenseExpiryNotificationThreshold: 15
>      * Vpx.Vpxa.config.vpxa.memoryCheckerTimeInSecs: 30
>      * Vpx.Vpxa.config.workingDir: /var/log/vmware/vpx
>      * XvMotion.VMFSOptimizations: 1


### vmware-host-config-manager
***
Manage advanced system settings of an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_config_manager_module.html


#### Base Command

`vmware-host-config-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Settings are applied to every ESXi host in given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. Settings are applied to this ESXi host. If `cluster_name` is not given, this parameter is required. | Optional | 
| options | A dictionary of advanced system settings. Invalid options will cause module to error. Note that the list of advanced options (with description and values) can be found by running `vim-cmd hostsvc/advopt/options`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-host-config-manager cluster_name="cluster" options="{'Config.HostAgent.log.level': 'info'}" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostConfigManager": [
            {
                "changed": false,
                "msg": "All settings are already configured.",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * msg: All settings are already configured.


### vmware-host-datastore
***
Manage a datastore on ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_datastore_module.html


#### Base Command

`vmware-host-datastore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter_name | Name of the datacenter to add the datastore. The datacenter isn't used by the API to create a datastore. Will be removed in 2.11. | Optional | 
| datastore_name | Name of the datastore to add/remove. | Required | 
| datastore_type | Type of the datastore to configure (nfs/nfs41/vmfs). Possible values are: nfs, nfs41, vmfs. | Required | 
| nfs_server | NFS host serving nfs datastore. Required if datastore type is set to `nfs`/`nfs41` and state is set to `present`, else unused. Two or more servers can be defined if datastore type is set to `nfs41`. | Optional | 
| nfs_path | Resource path on NFS host. Required if datastore type is set to `nfs`/`nfs41` and state is set to `present`, else unused. | Optional | 
| nfs_ro | ReadOnly or ReadWrite mount. Unused if datastore type is not set to `nfs`/`nfs41` and state is not set to `present`. Possible values are: Yes, No. Default is No. | Optional | 
| vmfs_device_name | Name of the device to be used as VMFS datastore. Required for VMFS datastore type and state is set to `present`, else unused. | Optional | 
| vmfs_version | VMFS version to use for datastore creation. Unused if datastore type is not set to `vmfs` and state is not set to `present`. | Optional | 
| esxi_hostname | ESXi hostname to manage the datastore. Required when used with a vcenter. | Optional | 
| state | present: Mount datastore on host if datastore is absent else do nothing. absent: Umount datastore if datastore is present else do nothing. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-host-datastore datastore_name="datastore1" datastore_type="vmfs" vmfs_device_name="naa.6000c29d140dea19fc681e3e1b190c46" vmfs_version="6" esxi_hostname="esxi01" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostDatastore": [
            {
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False

### vmware-host-dns-info
***
Gathers info about an ESXi host's DNS configuration information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_dns_info_module.html


#### Base Command

`vmware-host-dns-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster from which the ESXi host belong to. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostDnsInfo.hosts_dns_info | unknown | metadata about DNS config from given cluster / host system | 


#### Command Example
```!vmware-host-dns-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostDnsInfo": [
            {
                "changed": false,
                "hosts_dns_info": {
                    "esxi01": {
                        "dhcp": false,
                        "domain_name": "",
                        "host_name": "esxi01",
                        "ip_address": [],
                        "search_domain": [
                            "null"
                        ],
                        "virtual_nic_device": null
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Dns_Info
>    * ### esxi01
>      * dhcp: False
>      * domain_name: 
>      * host_name: esxi01
>      * virtual_nic_device: None
>      * #### Ip_Address
>      * #### Search_Domain
>        * 0: null


### vmware-host-facts
***
Gathers facts about remote ESXi hostsystem
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_facts_module.html


#### Base Command

`vmware-host-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | ESXi hostname. Host facts about the specified ESXi server will be returned. By specifying this option, you can select which ESXi hostsystem is returned if connecting to a vCenter. | Optional | 
| show_tag | Tags related to Host are shown if set to `True`. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostFacts.facts | unknown | system info about the host machine | 




### vmware-host-feature-info
***
Gathers info about an ESXi host's feature capability information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_feature_info_module.html


#### Base Command

`vmware-host-feature-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster from all host systems to be used for information gathering. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostFeatureInfo.hosts_feature_info | unknown | metadata about host's feature capability information | 


#### Command Example
```!vmware-host-feature-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostFeatureInfo": [
            {
                "changed": false,
                "hosts_feature_info": {
                    "esxi01": [
                        {
                            "feature_name": "cpuid.3DNOW",
                            "key": "cpuid.3DNOW",
                            "value": "0"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Feature_Info
>    * ### esxi01
>    * ### Cpuid.3Dnow
>      * feature_name: cpuid.3DNOW
>      * key: cpuid.3DNOW
>      * value: 0


### vmware-host-firewall-info
***
Gathers info about an ESXi host's firewall configuration information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_firewall_info_module.html


#### Base Command

`vmware-host-firewall-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster from which the ESXi host belong to. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostFirewallInfo.hosts_firewall_info | unknown | metadata about host's firewall configuration | 


#### Command Example
```!vmware-host-firewall-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostFirewallInfo": [
            {
                "changed": false,
                "hosts_firewall_info": {
                    "esxi01": [
                        {
                            "allowed_hosts": {
                                "all_ip": true,
                                "ip_address": [],
                                "ip_network": []
                            },
                            "enabled": true,
                            "key": "CIMHttpServer",
                            "rule": [
                                {
                                    "direction": "inbound",
                                    "end_port": null,
                                    "port": 5988,
                                    "port_type": "dst",
                                    "protocol": "tcp"
                                }
                            ],
                            "service": "sfcbd-watchdog"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Firewall_Info
>    * ### esxi01
>    * ### List
>      * enabled: True
>      * key: CIMHttpServer
>      * service: sfcbd-watchdog
>      * #### Allowed_Hosts
>        * all_ip: True
>        * ##### Ip_Address
>        * ##### Ip_Network
>      * #### Rule
>      * #### List
>        * direction: inbound
>        * end_port: None
>        * port: 5988
>        * port_type: dst
>        * protocol: tcp
>    * ### List
>      * enabled: True
>      * key: CIMHttpsServer
>      * service: sfcbd-watchdog


### vmware-host-firewall-manager
***
Manage firewall configurations about an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_firewall_manager_module.html


#### Base Command

`vmware-host-firewall-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Firewall settings are applied to every ESXi host system in given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. Firewall settings are applied to this ESXi host system. If `cluster_name` is not given, this parameter is required. | Optional | 
| rules | A list of Rule set which needs to be managed. Each member of list is rule set name and state to be set the rule. Both rule name and rule state are required parameters. Additional IPs and networks can also be specified Please see examples for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostFirewallManager.rule_set_state | unknown | dict with hostname as key and dict with firewall rule set facts as value | 


#### Command Example
```!vmware-host-firewall-manager cluster_name="cluster" rules="{{ [{'name': 'vvold', 'enabled': True}] }}" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostFirewallManager": [
            {
                "changed": true,
                "rule_set_state": {
                    "esxi01": {
                        "vvold": {
                            "allowed_hosts": {
                                "current_allowed_all": false,
                                "current_allowed_ip": [],
                                "current_allowed_networks": [],
                                "desired_allowed_all": false,
                                "desired_allowed_ip": [],
                                "desired_allowed_networks": [],
                                "previous_allowed_all": true,
                                "previous_allowed_ip": [],
                                "previous_allowed_networks": []
                            },
                            "current_state": true,
                            "desired_state": true,
                            "previous_state": false
                        }
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Rule_Set_State
>    * ### esxi01
>      * #### Vvold
>        * current_state: True
>        * desired_state: True
>        * previous_state: False
>        * ##### Allowed_Hosts
>          * current_allowed_all: False
>          * desired_allowed_all: False
>          * previous_allowed_all: True
>          * ###### Current_Allowed_Ip
>          * ###### Current_Allowed_Networks
>          * ###### Desired_Allowed_Ip
>          * ###### Desired_Allowed_Networks
>          * ###### Previous_Allowed_Ip
>          * ###### Previous_Allowed_Networks


### vmware-host-hyperthreading
***
Enables/Disables Hyperthreading optimization for an ESXi host system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_hyperthreading_module.html


#### Base Command

`vmware-host-hyperthreading`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Enable or disable Hyperthreading. You need to reboot the ESXi host if you change the configuration. Make sure that Hyperthreading is enabled in the BIOS. Otherwise, it will be enabled, but never activated. Possible values are: enabled, disabled. Default is enabled. | Optional | 
| esxi_hostname | Name of the host system to work with. This parameter is required if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. This parameter is required if `esxi_hostname` is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostHyperthreading.results | unknown | metadata about host system's Hyperthreading configuration | 


#### Command Example
```!vmware-host-hyperthreading esxi_hostname="esxi01" state="enabled" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostHyperthreading": [
            {
                "changed": true,
                "result": {
                    "esxi01": {
                        "changed": true,
                        "msg": "Hyperthreading is enabled, but not active. A reboot is required!",
                        "state": "enabled",
                        "state_current": "enabled"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Result
>    * ### esxi01
>      * changed: True
>      * msg: Hyperthreading is enabled, but not active. A reboot is required!
>      * state: enabled
>      * state_current: enabled


### vmware-host-ipv6
***
Enables/Disables IPv6 support for an ESXi host system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_ipv6_module.html


#### Base Command

`vmware-host-ipv6`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Enable or disable IPv6 support. You need to reboot the ESXi host if you change the configuration. Possible values are: enabled, disabled. Default is enabled. | Optional | 
| esxi_hostname | Name of the host system to work with. This is required parameter if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. This is required parameter if `esxi_hostname` is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostIpv6.result | unknown | metadata about host system's IPv6 configuration | 


#### Command Example
```!vmware-host-ipv6 esxi_hostname="esxi01" state="enabled" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostIpv6": [
            {
                "changed": false,
                "result": {
                    "esxi01": {
                        "msg": "IPv6 is already enabled and active for host 'esxi01'"
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Result
>    * ### esxi01
>      * msg: IPv6 is already enabled and active for host 'esxi01'


### vmware-host-kernel-manager
***
Manage kernel module options on ESXi hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_kernel_manager_module.html


#### Base Command

`vmware-host-kernel-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | Name of the ESXi host to work on. This parameter is required if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the VMware cluster to work on. All ESXi hosts in this cluster will be configured. This parameter is required if `esxi_hostname` is not specified. | Optional | 
| kernel_module_name | Name of the kernel module to be configured. | Required | 
| kernel_module_option | Specified configurations will be applied to the given module. These values are specified in key=value pairs and separated by a space when there are multiple options. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostKernelManager.results | unknown | dict with information on what was changed, by ESXi host in scope. | 


#### Command Example
```!vmware-host-kernel-manager esxi_hostname="esxi01" kernel_module_name="tcpip4" kernel_module_option="ipv6=0" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostKernelManager": [
            {
                "changed": true,
                "host_kernel_status": {
                    "esxi01": {
                        "changed": true,
                        "configured_options": "ipv6=0",
                        "msg": "Options have been changed on the kernel module",
                        "original_options": "ipv6=1"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Host_Kernel_Status
>    * ### esxi01
>      * changed: True
>      * configured_options: ipv6=0
>      * msg: Options have been changed on the kernel module
>      * original_options: ipv6=1


### vmware-host-lockdown
***
Manage administrator permission for the local administrative account for the ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_lockdown_module.html


#### Base Command

`vmware-host-lockdown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of cluster. All host systems from given cluster used to manage lockdown. Required parameter, if `esxi_hostname` is not set. | Optional | 
| esxi_hostname | List of ESXi hostname to manage lockdown. Required parameter, if `cluster_name` is not set. See examples for specifications. | Optional | 
| state | State of hosts system If set to `present`, all host systems will be set in lockdown mode. If host system is already in lockdown mode and set to `present`, no action will be taken. If set to `absent`, all host systems will be removed from lockdown mode. If host system is already out of lockdown mode and set to `absent`, no action will be taken. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostLockdown.results | unknown | metadata about state of Host system lock down | 


#### Command Example
```!vmware-host-lockdown esxi_hostname="esxi01" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostLockdown": [
            {
                "changed": true,
                "host_lockdown_state": {
                    "esxi01": {
                        "current_state": "present",
                        "desired_state": "present",
                        "previous_state": "absent"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Host_Lockdown_State
>    * ### esxi01
>      * current_state: present
>      * desired_state: present
>      * previous_state: absent


### vmware-host-ntp
***
Manage NTP server configuration of an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_ntp_module.html


#### Base Command

`vmware-host-ntp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | Name of the host system to work with. This parameter is required if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. This parameter is required if `esxi_hostname` is not specified. | Optional | 
| ntp_servers | IP or FQDN of NTP server(s). This accepts a list of NTP servers. For multiple servers, please look at the examples. | Required | 
| state | present: Add NTP server(s), if specified server(s) are absent else do nothing. absent: Remove NTP server(s), if specified server(s) are present else do nothing. Specified NTP server(s) will be configured if `state` isn't specified. Possible values are: present, absent. | Optional | 
| verbose | Verbose output of the configuration change. Explains if an NTP server was added, removed, or if the NTP server sequence was changed. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostNtp.results | unknown | metadata about host system's NTP configuration | 


#### Command Example
```!vmware-host-ntp esxi_hostname="esxi01" ntp_servers="{{ ['0.pool.ntp.org', '1.pool.ntp.org'] }}" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostNtp": [
            {
                "changed": false,
                "host_ntp_status": {
                    "esxi01": {
                        "changed": false,
                        "ntp_servers": [
                            "0.pool.ntp.org",
                            "1.pool.ntp.org"
                        ]
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Host_Ntp_Status
>    * ### esxi01
>      * changed: False
>      * #### Ntp_Servers
>        * 0: 0.pool.ntp.org
>        * 1: 1.pool.ntp.org

### vmware-host-ntp-info
***
Gathers info about NTP configuration on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_ntp_info_module.html


#### Base Command

`vmware-host-ntp-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. NTP config information about each ESXi server will be returned for the given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. NTP config information about this ESXi server will be returned. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostNtpInfo.hosts_ntp_info | unknown | dict with hostname as key and dict with NTP infos as value | 


#### Command Example
```!vmware-host-ntp-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostNtpInfo": [
            {
                "changed": false,
                "hosts_ntp_info": {
                    "esxi01": [
                        {
                            "ntp_servers": [
                                "0.pool.ntp.org",
                                "1.pool.ntp.org"
                            ],
                            "time_zone_description": "UTC",
                            "time_zone_gmt_offset": 0,
                            "time_zone_identifier": "UTC",
                            "time_zone_name": "UTC"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Ntp_Info
>    * ### esxi01
>    * ### Utc
>      * time_zone_description: UTC
>      * time_zone_gmt_offset: 0
>      * time_zone_identifier: UTC
>      * time_zone_name: UTC
>      * #### Ntp_Servers
>        * 0: 0.pool.ntp.org
>        * 1: 1.pool.ntp.org


### vmware-host-package-info
***
Gathers info about available packages on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_package_info_module.html


#### Base Command

`vmware-host-package-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Package information about each ESXi server will be returned for given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. Package information about this ESXi server will be returned. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostPackageInfo.hosts_package_info | unknown | dict with hostname as key and dict with package information as value | 


#### Command Example
```!vmware-host-package-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostPackageInfo": [
            {
                "changed": false,
                "hosts_package_info": {
                    "esxi01": [
                        {
                            "acceptance_level": "vmware_certified",
                            "creation_date": "2019-07-04T20:27:48.211267+00:00",
                            "description": "Driver for HP/Compaq Smart Array Controllers",
                            "maintenance_mode_required": true,
                            "name": "block-cciss",
                            "summary": "cciss: block driver for VMware ESX",
                            "vendor": "VMW",
                            "version": "3.6.14-10vmw.650.0.0.4564106"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Package_Info
>    * ### esxi01
>    * ### Block-Cciss
>      * acceptance_level: vmware_certified
>      * creation_date: 2019-07-04T20:27:48.211267+00:00
>      * description: Driver for HP/Compaq Smart Array Controllers
>      * maintenance_mode_required: True
>      * name: block-cciss
>      * summary: cciss: block driver for VMware ESX
>      * vendor: VMW
>      * version: 3.6.14-10vmw.650.0.0.4564106


### vmware-host-powermgmt-policy
***
Manages the Power Management Policy of an ESXI host system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_powermgmt_policy_module.html


#### Base Command

`vmware-host-powermgmt-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy | Set the Power Management Policy of the host system. Possible values are: high-performance, balanced, low-power, custom. Default is balanced. | Optional | 
| esxi_hostname | Name of the host system to work with. This is required parameter if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. This is required parameter if `esxi_hostname` is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostPowermgmtPolicy.result | unknown | metadata about host system's Power Management Policy | 


#### Command Example
```!vmware-host-powermgmt-policy esxi_hostname="esxi01" policy="high-performance" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostPowermgmtPolicy": [
            {
                "changed": true,
                "result": {
                    "esxi01": {
                        "changed": true,
                        "current_state": "high-performance",
                        "desired_state": "high-performance",
                        "msg": "Power policy changed",
                        "previous_state": "balanced"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Result
>    * ### esxi01
>      * changed: True
>      * current_state: high-performance
>      * desired_state: high-performance
>      * msg: Power policy changed
>      * previous_state: balanced


### vmware-host-powerstate
***
Manages power states of host systems in vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_powerstate_module.html


#### Base Command

`vmware-host-powerstate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Set the state of the host system. Possible values are: power-down-to-standby, power-up-from-standby, shutdown-host, reboot-host. Default is shutdown-host. | Optional | 
| esxi_hostname | Name of the host system to work with. This is required parameter if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. This is required parameter if `esxi_hostname` is not specified. | Optional | 
| force | This parameter specify if the host should be proceeding with user defined powerstate regardless of whether it is in maintenance mode. If `state` set to `reboot-host` and `force` as `true`, then host system is rebooted regardless of whether it is in maintenance mode. If `state` set to `shutdown-host` and `force` as `true`, then host system is shutdown regardless of whether it is in maintenance mode. If `state` set to `power-down-to-standby` and `force` to `true`, then all powered off VMs will evacuated. Not applicable if `state` set to `power-up-from-standby`. Possible values are: Yes, No. Default is No. | Optional | 
| timeout | This parameter defines timeout for `state` set to `power-down-to-standby` or `power-up-from-standby`. Ignored if `state` set to `reboot-host` or `shutdown-host`. This parameter is defined in seconds. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostPowerstate.result | unknown | metadata about host system's state | 




### vmware-host-scanhba
***
Rescan host HBA's and optionally refresh the storage system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_scanhba_module.html


#### Base Command

`vmware-host-scanhba`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | ESXi hostname to Rescan the storage subsystem on. | Optional | 
| cluster_name | Cluster name to Rescan the storage subsystem on (this will run the rescan task on each host in the cluster). | Optional | 
| refresh_storage | Refresh the storage system in vCenter/ESXi Web Client for each host found. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostScanhba.result | unknown | return confirmation of requested host and updated / refreshed storage system | 


#### Command Example
```!vmware-host-scanhba esxi_hostname="esxi01" refresh_storage="True" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostScanhba": [
            {
                "changed": true,
                "result": {
                    "esxi01": {
                        "refreshed_storage": true,
                        "rescaned_hba": true
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Result
>    * ### esxi01
>      * refreshed_storage: True
>      * rescaned_hba: True


### vmware-host-service-info
***
Gathers info about an ESXi host's services
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_service_info_module.html


#### Base Command

`vmware-host-service-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Service information about each ESXi server will be returned for given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. Service information about this ESXi server will be returned. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostServiceInfo.host_service_info | unknown | dict with hostname as key and dict with host service config information | 


#### Command Example
```!vmware-host-service-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostServiceInfo": [
            {
                "changed": false,
                "host_service_info": {
                    "esxi01": [
                        {
                            "key": "DCUI",
                            "label": "Direct Console UI",
                            "policy": "on",
                            "required": false,
                            "running": true,
                            "source_package_desc": "This VIB contains all of the base functionality of vSphere ESXi.",
                            "source_package_name": "esx-base",
                            "uninstallable": false
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Host_Service_Info
>    * ### esxi01
>    * ### Esx-Base
>      * key: DCUI
>      * label: Direct Console UI
>      * policy: on
>      * required: False
>      * running: True
>      * source_package_desc: This VIB contains all of the base functionality of vSphere ESXi.
>      * source_package_name: esx-base
>      * uninstallable: False


### vmware-host-service-manager
***
Manage services on a given ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_service_manager_module.html


#### Base Command

`vmware-host-service-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Service settings are applied to every ESXi host system/s in given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. Service settings are applied to this ESXi host system. If `cluster_name` is not given, this parameter is required. | Optional | 
| state | Desired state of service. State value 'start' and 'present' has same effect. State value 'stop' and 'absent' has same effect. Possible values are: absent, present, restart, start, stop. Default is start. | Optional | 
| service_policy | Set of valid service policy strings. If set `on`, then service should be started when the host starts up. If set `automatic`, then service should run if and only if it has open firewall ports. If set `off`, then Service should not be started when the host starts up. Possible values are: automatic, off, on. | Optional | 
| service_name | Name of Service to be managed. This is a brief identifier for the service, for example, ntpd, vxsyslogd etc. This value should be a valid ESXi service name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-host-service-manager cluster_name="cluster" service_name="ntpd" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostServiceManager": [
            {
                "changed": true,
                "host_service_status": {
                    "esxi01": {
                        "actual_service_policy": "off",
                        "actual_service_state": "stopped",
                        "changed": true,
                        "desired_service_policy": null,
                        "desired_service_state": "present",
                        "error": "",
                        "service_name": "ntpd"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Host_Service_Status
>    * ### esxi01
>      * actual_service_policy: off
>      * actual_service_state: stopped
>      * changed: True
>      * desired_service_policy: None
>      * desired_service_state: present
>      * error: 
>      * service_name: ntpd


### vmware-host-snmp
***
Configures SNMP on an ESXi host system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_snmp_module.html


#### Base Command

`vmware-host-snmp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Enable, disable, or reset the SNMP agent. Possible values are: disabled, enabled, reset. Default is disabled. | Optional | 
| community | List of SNMP community strings. | Optional | 
| snmp_port | Port used by the SNMP agent. Default is 161. | Optional | 
| trap_targets | A list of trap targets. You need to use `hostname`, `port`, and `community` for each trap target. | Optional | 
| trap_filter | A list of trap oids for traps not to be sent by agent, e.g. [ 1.1.1.1.4.1.6876.1.1.1.2, 1.1.1.1.4.1.6876.4.1.1.1 ] Use value `reset` to clear settings. | Optional | 
| send_trap | Send a test trap to validate the configuration. Possible values are: Yes, No. Default is No. | Optional | 
| hw_source | Source hardware events from IPMI sensors or CIM Indications. The embedded SNMP agent receives hardware events either from IPMI sensors `sensors` or CIM indications `indications`. Possible values are: indications, sensors. Default is indications. | Optional | 
| log_level | Syslog logging level. Possible values are: debug, info, warning, error. Default is info. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostSnmp.results | unknown | metadata about host system's SNMP configuration | 




### vmware-host-ssl-info
***
Gather info of ESXi host system about SSL
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_ssl_info_module.html


#### Base Command

`vmware-host-ssl-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. SSL thumbprint information about all ESXi host system in the given cluster will be reported. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. SSL thumbprint information of this ESXi host system will be reported. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostSslInfo.host_ssl_info | unknown | dict with hostname as key and dict with SSL thumbprint related info | 


#### Command Example
```!vmware-host-ssl-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostSslInfo": [
            {
                "changed": false,
                "host_ssl_info": {
                    "esxi01": {
                        "owner_tag": "",
                        "principal": "",
                        "ssl_thumbprints": []
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Host_Ssl_Info
>    * ### esxi01
>      * owner_tag: 
>      * principal: 
>      * #### Ssl_Thumbprints


### vmware-host-vmhba-info
***
Gathers info about vmhbas available on the given ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_vmhba_info_module.html


#### Base Command

`vmware-host-vmhba-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | Name of the host system to work with. Vmhba information about this ESXi server will be returned. This parameter is required if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. Vmhba information about each ESXi server will be returned for the given cluster. This parameter is required if `esxi_hostname` is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostVmhbaInfo.hosts_vmhbas_info | unknown | dict with hostname as key and dict with vmhbas information as value. | 


#### Command Example
```!vmware-host-vmhba-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostVmhbaInfo": [
            {
                "changed": false,
                "hosts_vmhbas_info": {
                    "esxi01": {
                        "vmhba_details": [
                            {
                                "adapter": "VMware Inc. PVSCSI SCSI Controller",
                                "bus": 3,
                                "device": "vmhba0",
                                "driver": "pvscsi",
                                "location": "0000:03:00.0",
                                "model": "PVSCSI SCSI Controller",
                                "status": "unknown",
                                "type": "ParallelScsiHba"
                            }
                        ]
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Vmhbas_Info
>    * ### esxi01
>      * #### Vmhba_Details
>      * #### List
>        * adapter: VMware Inc. PVSCSI SCSI Controller
>        * bus: 3
>        * device: vmhba0
>        * driver: pvscsi
>        * location: 0000:03:00.0
>        * model: PVSCSI SCSI Controller
>        * status: unknown
>        * type: ParallelScsiHba


### vmware-host-vmnic-info
***
Gathers info about vmnics available on the given ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_host_vmnic_info_module.html


#### Base Command

`vmware-host-vmnic-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| capabilities | Gather information about general capabilities (Auto negotiation, Wake On LAN, and Network I/O Control). Possible values are: Yes, No. Default is No. | Optional | 
| directpath_io | Gather information about DirectPath I/O capabilities and configuration. Possible values are: Yes, No. Default is No. | Optional | 
| sriov | Gather information about SR-IOV capabilities and configuration. Possible values are: Yes, No. Default is No. | Optional | 
| esxi_hostname | Name of the host system to work with. Vmnic information about this ESXi server will be returned. This parameter is required if `cluster_name` is not specified. | Optional | 
| cluster_name | Name of the cluster from which all host systems will be used. Vmnic information about each ESXi server will be returned for the given cluster. This parameter is required if `esxi_hostname` is not specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareHostVmnicInfo.hosts_vmnics_info | unknown | dict with hostname as key and dict with vmnics information as value. for \`num_vmnics\`, only NICs starting with vmnic are counted. NICs like vusb\* are not counted. details about vswitch and dvswitch was added in version 2.7. details about vmnics was added in version 2.8. | 


#### Command Example
```!vmware-host-vmnic-info cluster_name="cluster"```

#### Context Example
```json
{
    "VMware": {
        "VmwareHostVmnicInfo": [
            {
                "changed": false,
                "hosts_vmnics_info": {
                    "esxi01": {
                        "all": [
                            "vmnic0",
                            "vmnic1"
                        ],
                        "available": [
                            "vmnic1"
                        ],
                        "dvswitch": {},
                        "num_vmnics": 2,
                        "used": [
                            "vmnic0"
                        ],
                        "vmnic_details": [
                            {
                                "actual_duplex": "Full Duplex",
                                "actual_speed": 10000,
                                "adapter": "VMware Inc. vmxnet3 Virtual Ethernet Controller",
                                "configured_duplex": "Full Duplex",
                                "configured_speed": 10000,
                                "device": "vmnic0",
                                "driver": "nvmxnet3",
                                "location": "0000:0b:00.0",
                                "mac": "00:0c:29:d9:27:04",
                                "status": "Connected"
                            },
                            {
                                "actual_duplex": "Full Duplex",
                                "actual_speed": 10000,
                                "adapter": "VMware Inc. vmxnet3 Virtual Ethernet Controller",
                                "configured_duplex": "Full Duplex",
                                "configured_speed": 10000,
                                "device": "vmnic1",
                                "driver": "nvmxnet3",
                                "location": "0000:13:00.0",
                                "mac": "00:0c:29:d9:27:0e",
                                "status": "Connected"
                            }
                        ],
                        "vswitch": {
                            "vSwitch0": [
                                "vmnic0"
                            ]
                        }
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Vmnics_Info
>    * ### esxi01
>      * num_vmnics: 2
>      * #### All
>        * 0: vmnic0
>        * 1: vmnic1
>      * #### Available
>        * 0: vmnic1
>      * #### Dvswitch
>      * #### Used
>        * 0: vmnic0
>      * #### Vmnic_Details
>      * #### List
>        * actual_duplex: Full Duplex
>        * actual_speed: 10000
>        * adapter: VMware Inc. vmxnet3 Virtual Ethernet Controller
>        * configured_duplex: Full Duplex
>        * configured_speed: 10000
>        * device: vmnic0
>        * driver: nvmxnet3
>        * location: 0000:0b:00.0
>        * mac: 00:0c:29:d9:27:04
>        * status: Connected
>      * #### List
>        * actual_duplex: Full Duplex
>        * actual_speed: 10000
>        * adapter: VMware Inc. vmxnet3 Virtual Ethernet Controller
>        * configured_duplex: Full Duplex
>        * configured_speed: 10000
>        * device: vmnic1
>        * driver: nvmxnet3
>        * location: 0000:13:00.0
>        * mac: 00:0c:29:d9:27:0e
>        * status: Connected
>      * #### Vswitch
>        * ##### Vswitch0
>          * 0: vmnic0


### vmware-local-role-info
***
Gather info about local roles on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_local_role_info_module.html


#### Base Command

`vmware-local-role-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareLocalRoleInfo.local_role_info | unknown | Info about role present on ESXi host | 


#### Command Example
```!vmware-local-role-info ```

#### Context Example
```json
{
    "VMware": {
        "VmwareLocalRoleInfo": [
            {
                "changed": false,
                "local_role_info": [
                    {
                        "privileges": [
                            "Alarm.Acknowledge",
                            "Alarm.Create"
                        ],
                        "role_id": -6,
                        "role_info_label": "No cryptography administrator",
                        "role_info_summary": "Full access without Cryptographic operations privileges",
                        "role_name": "NoCryptoAdmin",
                        "role_system": true
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Local_Role_Info
>  * ## Nocryptoadmin
>    * role_id: -6
>    * role_info_label: No cryptography administrator
>    * role_info_summary: Full access without Cryptographic operations privileges
>    * role_name: NoCryptoAdmin
>    * role_system: True
>    * ### Privileges
>      * 0: Alarm.Acknowledge
>      * 1: Alarm.Create


### vmware-local-role-manager
***
Manage local roles on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_local_role_manager_module.html


#### Base Command

`vmware-local-role-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_role_name | The local role name to be managed. | Required | 
| local_privilege_ids | The list of privileges that role needs to have. Please see `https://docs.vmware.com/en/VMware-vSphere/6.0/com.vmware.vsphere.security.doc/GUID-ED56F3C4-77D0-49E3-88B6-B99B8B437B62.html`. | Optional | 
| state | Indicate desired state of the role. If the role already exists when `state=present`, the role info is updated. Possible values are: present, absent. Default is present. | Optional | 
| force_remove | If set to `False` then prevents the role from being removed if any permissions are using it. Possible values are: Yes, No. Default is No. | Optional | 
| action | This parameter is only valid while updating an existing role with privileges. `add` will add the privileges to the existing privilege list. `remove` will remove the privileges from the existing privilege list. `set` will replace the privileges of the existing privileges with user defined list of privileges. Possible values are: add, remove, set. Default is set. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareLocalRoleManager.role_name | string | Name of local role | 
| VMware.VmwareLocalRoleManager.role_id | number | ESXi generated local role id | 
| VMware.VmwareLocalRoleManager.privileges | unknown | List of privileges | 
| VMware.VmwareLocalRoleManager.privileges_previous | unknown | List of privileges of role before the update | 
| VMware.VmwareLocalRoleManager.local_role_name | string | Name of local role | 
| VMware.VmwareLocalRoleManager.new_privileges | unknown | List of privileges | 
| VMware.VmwareLocalRoleManager.old_privileges | unknown | List of privileges of role before the update | 


#### Command Example
```!vmware-local-role-manager local_role_name="vmware_qa" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareLocalRoleManager": [
            {
                "changed": true,
                "result": {
                    "local_role_name": "vmware_qa",
                    "msg": "Role created",
                    "new_privileges": [],
                    "privileges": [],
                    "role_id": 55981884,
                    "role_name": "vmware_qa"
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Result
>    * local_role_name: vmware_qa
>    * msg: Role created
>    * role_id: 55981884
>    * role_name: vmware_qa
>    * ### New_Privileges
>    * ### Privileges


### vmware-local-user-info
***
Gather info about users on the given ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_local_user_info_module.html


#### Base Command

`vmware-local-user-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareLocalUserInfo.local_user_info | unknown | metadata about all local users | 




### vmware-local-user-manager
***
Manage local users on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_local_user_manager_module.html


#### Base Command

`vmware-local-user-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_user_name | The local user name to be changed. | Required | 
| local_user_password | The password to be set. | Optional | 
| local_user_description | Description for the user. | Optional | 
| state | Indicate desired state of the user. If the user already exists when `state=present`, the user info is updated. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-maintenancemode
***
Place a host into maintenance mode
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_maintenancemode_module.html


#### Base Command

`vmware-maintenancemode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | Name of the host as defined in vCenter. | Required | 
| vsan | Specify which VSAN compliant mode to enter. Possible values are: ensureObjectAccessibility, evacuateAllData, noAction. | Optional | 
| evacuate | If set to `True`, evacuate all powered off VMs. Possible values are: Yes, No. Default is No. | Optional | 
| timeout | Specify a timeout for the operation. Default is 0. | Optional | 
| state | Enter or exit maintenance mode. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareMaintenancemode.hostsystem | string | Name of vim reference | 
| VMware.VmwareMaintenancemode.hostname | string | Name of host in vCenter | 
| VMware.VmwareMaintenancemode.status | string | Action taken | 


#### Command Example
```!vmware-maintenancemode esxi_hostname="esxi01" vsan="ensureObjectAccessibility" evacuate="True" timeout="3600" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareMaintenancemode": [
            {
                "changed": true,
                "hostname": "esxi01",
                "hostsystem": "'vim.HostSystem:host-10'",
                "msg": "Host esxi01 entered maintenance mode",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * hostname: esxi01
>  * hostsystem: 'vim.HostSystem:host-10'
>  * msg: Host esxi01 entered maintenance mode
>  * status: ENTER


### vmware-migrate-vmk
***
Migrate a VMK interface from VSS to VDS
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_migrate_vmk_module.html


#### Base Command

`vmware-migrate-vmk`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| esxi_hostname | ESXi hostname to be managed. | Required | 
| device | VMK interface name. | Required | 
| current_switch_name | Switch VMK interface is currently on. | Required | 
| current_portgroup_name | Portgroup name VMK interface is currently on. | Required | 
| migrate_switch_name | Switch name to migrate VMK interface to. | Required | 
| migrate_portgroup_name | Portgroup name to migrate VMK interface to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-object-role-permission
***
Manage local roles on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_object_role_permission_module.html


#### Base Command

`vmware-object-role-permission`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role | The role to be assigned permission. | Required | 
| principal | The user to be assigned permission. Required if `group` is not specified. | Optional | 
| group | The group to be assigned permission. Required if `principal` is not specified. | Optional | 
| object_name | The object name to assigned permission. | Required | 
| object_type | The object type being targeted. Possible values are: Folder, VirtualMachine, Datacenter, ResourcePool, Datastore, Network, HostSystem, ComputeResource, ClusterComputeResource, DistributedVirtualSwitch. Default is Folder. | Optional | 
| recursive | Should the permissions be recursively applied. Possible values are: Yes, No. Default is Yes. | Optional | 
| state | Indicate desired state of the object's permission. When `state=present`, the permission will be added if it doesn't already exist. When `state=absent`, the permission is removed if it exists. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareObjectRolePermission.changed | boolean | whether or not a change was made to the object's role | 




### vmware-portgroup
***
Create a VMware portgroup
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_portgroup_module.html


#### Base Command

`vmware-portgroup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | vSwitch to modify. | Required | 
| portgroup | Portgroup name to add. | Required | 
| vlan_id | VLAN ID to assign to portgroup. Set to 0 (no VLAN tagging) by default. Default is 0. | Optional | 
| security | Network policy specifies layer 2 security settings for a portgroup such as promiscuous mode, where guest adapter listens to all the packets, MAC address changes and forged transmits. Dict which configures the different security values for portgroup. Valid attributes are: - `promiscuous_mode` (bool): indicates whether promiscuous mode is allowed. (default: None) - `forged_transmits` (bool): indicates whether forged transmits are allowed. (default: None) - `mac_changes` (bool): indicates whether mac changes are allowed. (default: None). | Optional | 
| teaming | Dictionary which configures the different teaming values for portgroup. Valid attributes are: - `load_balancing` (string): Network adapter teaming policy. `load_balance_policy` is also alias to this option. (default: loadbalance_srcid) - choices: [ loadbalance_ip, loadbalance_srcmac, loadbalance_srcid, failover_explicit ] - `network_failure_detection` (string): Network failure detection. (default: link_status_only) - choices: [ link_status_only, beacon_probing ] - `notify_switches` (bool): Indicate whether or not to notify the physical switch if a link fails. (default: None) - `failback` (bool): Indicate whether or not to use a failback when restoring links. (default: None) - `active_adapters` (list): List of active adapters used for load balancing. - `standby_adapters` (list): List of standby adapters used for failover. - All vmnics are used as active adapters if `active_adapters` and `standby_adapters` are not defined. - `inbound_policy` (bool): Indicate whether or not the teaming policy is applied to inbound frames as well. Deprecated. (default: False) - `rolling_order` (bool): Indicate whether or not to use a rolling policy when restoring links. Deprecated. (default: False). | Optional | 
| traffic_shaping | Dictionary which configures traffic shaping for the switch. Valid attributes are: - `enabled` (bool): Status of Traffic Shaping Policy. (default: None) - `average_bandwidth` (int): Average bandwidth (kbit/s). (default: None) - `peak_bandwidth` (int): Peak bandwidth (kbit/s). (default: None) - `burst_size` (int): Burst size (KB). (default: None). | Optional | 
| cluster_name | Name of cluster name for host membership. Portgroup will be created on all hosts of the given cluster. This option is required if `hosts` is not specified. | Optional | 
| hosts | List of name of host or hosts on which portgroup needs to be added. This option is required if `cluster_name` is not specified. | Optional | 
| state | Determines if the portgroup should be present or not. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwarePortgroup.result | unknown | metadata about the portgroup | 


#### Command Example
```!vmware-portgroup switch="vSwitch0" portgroup="test" vlan_id="123" cluster_name=cluster```

#### Context Example
```json
{
    "VMware": {
        "VmwarePortgroup": [
            {
                "changed": true,
                "result": {
                    "esxi01": {
                        "changed": true,
                        "msg": "Security changed",
                        "portgroup": "test",
                        "sec_forged_transmits": "No override",
                        "sec_forged_transmits_previous": "No override",
                        "sec_mac_changes": "No override",
                        "sec_mac_changes_previous": "No override",
                        "sec_promiscuous_mode": "No override",
                        "sec_promiscuous_mode_previous": "No override",
                        "traffic_shaping": "No override",
                        "vlan_id": 123,
                        "vswitch": "vSwitch0"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## Result
>    * ### esxi01
>      * changed: True
>      * msg: Security changed
>      * portgroup: test
>      * sec_forged_transmits: No override
>      * sec_forged_transmits_previous: No override
>      * sec_mac_changes: No override
>      * sec_mac_changes_previous: No override
>      * sec_promiscuous_mode: No override
>      * sec_promiscuous_mode_previous: No override
>      * traffic_shaping: No override
>      * vlan_id: 123
>      * vswitch: vSwitch0


### vmware-portgroup-info
***
Gathers info about an ESXi host's Port Group configuration
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_portgroup_info_module.html


#### Base Command

`vmware-portgroup-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policies | Gather information about Security, Traffic Shaping, as well as Teaming and failover. The property `ts` stands for Traffic Shaping and `lb` for Load Balancing. Possible values are: Yes, No. Default is No. | Optional | 
| cluster_name | Name of the cluster. Info will be returned for all hostsystem belonging to this cluster name. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwarePortgroupInfo.hosts_portgroup_info | unknown | metadata about host's portgroup configuration | 




### vmware-resource-pool
***
Add/remove resource pools to/from vCenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_resource_pool_module.html


#### Base Command

`vmware-resource-pool`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | Name of the datacenter to add the host. | Required | 
| cluster | Name of the cluster to add the host. | Required | 
| resource_pool | Resource pool name to manage. | Required | 
| cpu_expandable_reservations | In a resource pool with an expandable reservation, the reservation on a resource pool can grow beyond the specified value. Possible values are: Yes, No. Default is Yes. | Optional | 
| cpu_reservation | Amount of resource that is guaranteed available to the virtual machine or resource pool. Default is 0. | Optional | 
| cpu_limit | The utilization of a virtual machine/resource pool will not exceed this limit, even if there are available resources. The default value -1 indicates no limit. Default is -1. | Optional | 
| cpu_shares | Memory shares are used in case of resource contention. Possible values are: high, custom, low, normal. Default is normal. | Optional | 
| mem_expandable_reservations | In a resource pool with an expandable reservation, the reservation on a resource pool can grow beyond the specified value. Possible values are: Yes, No. Default is Yes. | Optional | 
| mem_reservation | Amount of resource that is guaranteed available to the virtual machine or resource pool. Default is 0. | Optional | 
| mem_limit | The utilization of a virtual machine/resource pool will not exceed this limit, even if there are available resources. The default value -1 indicates no limit. Default is -1. | Optional | 
| mem_shares | Memory shares are used in case of resource contention. Possible values are: high, custom, low, normal. Default is normal. | Optional | 
| state | Add or remove the resource pool. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareResourcePool.instance | unknown | metadata about the new resource pool | 




### vmware-resource-pool-info
***
Gathers info about resource pool information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_resource_pool_info_module.html


#### Base Command

`vmware-resource-pool-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareResourcePoolInfo.resource_pool_info | unknown | metadata about resource pool configuration | 


#### Command Example
```!vmware-resource-pool-info ```

#### Context Example
```json
{
    "VMware": {
        "VmwareResourcePoolInfo": [
            {
                "changed": false,
                "resource_pool_info": [
                    {
                        "cpu_allocation_expandable_reservation": true,
                        "cpu_allocation_limit": 0,
                        "cpu_allocation_overhead_limit": null,
                        "cpu_allocation_reservation": 0,
                        "cpu_allocation_shares": 4000,
                        "cpu_allocation_shares_level": "normal",
                        "mem_allocation_expandable_reservation": true,
                        "mem_allocation_limit": 0,
                        "mem_allocation_overhead_limit": null,
                        "mem_allocation_reservation": 0,
                        "mem_allocation_shares": 163840,
                        "mem_allocation_shares_level": "normal",
                        "name": "Resources",
                        "overall_status": "green",
                        "owner": "cluster",
                        "runtime_cpu_max_usage": 0,
                        "runtime_cpu_overall_usage": 0,
                        "runtime_cpu_reservation_used": 0,
                        "runtime_cpu_reservation_used_vm": 0,
                        "runtime_cpu_unreserved_for_pool": 0,
                        "runtime_cpu_unreserved_for_vm": 0,
                        "runtime_memory_max_usage": 0,
                        "runtime_memory_overall_usage": 0,
                        "runtime_memory_reservation_used": 0,
                        "runtime_memory_reservation_used_vm": 0,
                        "runtime_memory_unreserved_for_pool": 0,
                        "runtime_memory_unreserved_for_vm": 0
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Resource_Pool_Info
>  * ## Resources
>    * cpu_allocation_expandable_reservation: True
>    * cpu_allocation_limit: 0
>    * cpu_allocation_overhead_limit: None
>    * cpu_allocation_reservation: 0
>    * cpu_allocation_shares: 4000
>    * cpu_allocation_shares_level: normal
>    * mem_allocation_expandable_reservation: True
>    * mem_allocation_limit: 0
>    * mem_allocation_overhead_limit: None
>    * mem_allocation_reservation: 0
>    * mem_allocation_shares: 163840
>    * mem_allocation_shares_level: normal
>    * name: Resources
>    * overall_status: green
>    * owner: cluster
>    * runtime_cpu_max_usage: 0
>    * runtime_cpu_overall_usage: 0
>    * runtime_cpu_reservation_used: 0
>    * runtime_cpu_reservation_used_vm: 0
>    * runtime_cpu_unreserved_for_pool: 0
>    * runtime_cpu_unreserved_for_vm: 0
>    * runtime_memory_max_usage: 0
>    * runtime_memory_overall_usage: 0
>    * runtime_memory_reservation_used: 0
>    * runtime_memory_reservation_used_vm: 0
>    * runtime_memory_unreserved_for_pool: 0
>    * runtime_memory_unreserved_for_vm: 0


### vmware-tag
***
Manage VMware tags
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_tag_module.html


#### Base Command

`vmware-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | The name of tag to manage. | Required | 
| tag_description | The tag description. This is required only if `state` is set to `present`. This parameter is ignored, when `state` is set to `absent`. Process of updating tag only allows description change. | Optional | 
| category_id | The unique ID generated by vCenter should be used to. User can get this unique ID from facts module. | Optional | 
| state | The state of tag. If set to `present` and tag does not exists, then tag is created. If set to `present` and tag exists, then tag is updated. If set to `absent` and tag exists, then tag is deleted. If set to `absent` and tag does not exists, no action is taken. Possible values are: present, absent. Default is present. | Optional | 
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareTag.results | unknown | dictionary of tag metadata | 




### vmware-tag-info
***
Manage VMware tag info
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_tag_info_module.html


#### Base Command

`vmware-tag-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareTagInfo.results | unknown | dictionary of tag metadata | 




### vmware-tag-manager
***
Manage association of VMware tags with VMware objects
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_tag_manager_module.html


#### Base Command

`vmware-tag-manager`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_names | List of tag(s) to be managed. You can also specify category name by specifying colon separated value. For example, "category_name:tag_name". You can skip category name if you have unique tag names. | Required | 
| state | If `state` is set to `add` or `present` will add the tags to the existing tag list of the given object. If `state` is set to `remove` or `absent` will remove the tags from the existing tag list of the given object. If `state` is set to `set` will replace the tags of the given objects with the user defined list of tags. Possible values are: present, absent, add, remove, set. Default is add. | Optional | 
| object_type | Type of object to work with. Possible values are: VirtualMachine, Datacenter, ClusterComputeResource, HostSystem, DistributedVirtualSwitch, DistributedVirtualPortgroup. | Required | 
| object_name | Name of the object to work with. For DistributedVirtualPortgroups the format should be "switch_name:portgroup_name". | Required | 
| protocol | The connection to protocol. Possible values are: http, https. Default is https. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareTagManager.tag_status | unknown | metadata about tags related to object configuration | 




### vmware-target-canonical-info
***
Return canonical (NAA) from an ESXi host system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_target_canonical_info_module.html


#### Base Command

`vmware-target-canonical-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_id | The target id based on order of scsi device. version 2.6 onwards, this parameter is optional. | Optional | 
| cluster_name | Name of the cluster. Info about all SCSI devices for all host system in the given cluster is returned. This parameter is required, if `esxi_hostname` is not provided. | Optional | 
| esxi_hostname | Name of the ESXi host system. Info about all SCSI devices for the given ESXi host system is returned. This parameter is required, if `cluster_name` is not provided. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareTargetCanonicalInfo.canonical | string | metadata about SCSI Target device | 
| VMware.VmwareTargetCanonicalInfo.scsi_tgt_info | unknown | metadata about all SCSI Target devices | 


#### Command Example
```!vmware-target-canonical-info target_id="7" esxi_hostname="esxi01" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareTargetCanonicalInfo": [
            {
                "canonical": "",
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * canonical: 
>  * changed: False

### vmware-vcenter-settings
***
Configures general settings on a vCenter server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vcenter_settings_module.html


#### Base Command

`vmware-vcenter-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database | The database settings for vCenter server. Valid attributes are: - `max_connections` (int): Maximum connections. (default: 50) - `task_cleanup` (bool): Task cleanup. (default: true) - `task_retention` (int): Task retention (days). (default: 30) - `event_cleanup` (bool): Event cleanup. (default: true) - `event_retention` (int): Event retention (days). (default: 30). Default is {'max_connections': 50, 'task_cleanup': True, 'task_retention': 30, 'event_cleanup': True, 'event_retention': 30}. | Optional | 
| runtime_settings | The unique runtime settings for vCenter server. Valid attributes are: - `unique_id` (int): vCenter server unique ID. - `managed_address` (str): vCenter server managed address. - `vcenter_server_name` (str): vCenter server name. (default: FQDN). | Optional | 
| user_directory | The user directory settings for the vCenter server installation. Valid attributes are: - `timeout` (int): User directory timeout. (default: 60) - `query_limit` (bool): Query limit. (default: true) - `query_limit_size` (int): Query limit size. (default: 5000) - `validation` (bool): Mail Validation. (default: true) - `validation_period` (int): Validation period. (default: 1440). Default is {'timeout': 60, 'query_limit': True, 'query_limit_size': 5000, 'validation': True, 'validation_period': 1440}. | Optional | 
| mail | The settings vCenter server uses to send email alerts. Valid attributes are: - `server` (str): Mail server - `sender` (str): Mail sender address. | Optional | 
| snmp_receivers | SNMP trap destinations for vCenter server alerts. Valid attributes are: - `snmp_receiver_1_url` (str): Primary Receiver ULR. (default: "localhost") - `snmp_receiver_1_enabled` (bool): Enable receiver. (default: True) - `snmp_receiver_1_port` (int): Receiver port. (default: 162) - `snmp_receiver_1_community` (str): Community string. (default: "public") - `snmp_receiver_2_url` (str): Receiver 2 ULR. (default: "") - `snmp_receiver_2_enabled` (bool): Enable receiver. (default: False) - `snmp_receiver_2_port` (int): Receiver port. (default: 162) - `snmp_receiver_2_community` (str): Community string. (default: "") - `snmp_receiver_3_url` (str): Receiver 3 ULR. (default: "") - `snmp_receiver_3_enabled` (bool): Enable receiver. (default: False) - `snmp_receiver_3_port` (int): Receiver port. (default: 162) - `snmp_receiver_3_community` (str): Community string. (default: "") - `snmp_receiver_4_url` (str): Receiver 4 ULR. (default: "") - `snmp_receiver_4_enabled` (bool): Enable receiver. (default: False) - `snmp_receiver_4_port` (int): Receiver port. (default: 162) - `snmp_receiver_4_community` (str): Community string. (default: ""). Default is {'snmp_receiver_1_url': 'localhost', 'snmp_receiver_1_enabled': True, 'snmp_receiver_1_port': 162, 'snmp_receiver_1_community': 'public', 'snmp_receiver_2_url': '', 'snmp_receiver_2_enabled': False, 'snmp_receiver_2_port': 162, 'snmp_receiver_2_community': '', 'snmp_receiver_3_url': '', 'snmp_receiver_3_enabled': False, 'snmp_receiver_3_port': 162, 'snmp_receiver_3_community': '', 'snmp_receiver_4_url': '', 'snmp_receiver_4_enabled': False, 'snmp_receiver_4_port': 162, 'snmp_receiver_4_community': ''}. | Optional | 
| timeout_settings | The vCenter server connection timeout for normal and long operations. Valid attributes are: - `normal_operations` (int) (default: 30) - `long_operations` (int) (default: 120). Default is {'normal_operations': 30, 'long_operations': 120}. | Optional | 
| logging_options | The level of detail that vCenter server usesfor log files. Possible values are: none, error, warning, info, verbose, trivia. Default is info. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVcenterSettings.results | unknown | metadata about vCenter settings | 




### vmware-vcenter-statistics
***
Configures statistics on a vCenter server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vcenter_statistics_module.html


#### Base Command

`vmware-vcenter-statistics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_past_day | Settings for vCenter server past day statistic collection. Valid attributes are: - `enabled` (bool): Past day statistics collection enabled. (default: True) - `interval_minutes` (int): Interval duration (minutes). (choices: [1, 2, 3, 4, 5]) (default: 5) - `save_for_days` (int): Save for (days). (choices: [1, 2, 3, 4, 5]) (default: 1) - `level` (int): Statistics level. (choices: [1, 2, 3, 4]) (default: 1). | Optional | 
| interval_past_week | Settings for vCenter server past week statistic collection. Valid attributes are: - `enabled` (bool): Past week statistics collection enabled. (default: True) - `interval_minutes` (int): Interval duration (minutes). (choices: [30]) (default: 30) - `save_for_weeks` (int): Save for (weeks). (choices: [1]) (default: 1) - `level` (int): Statistics level. (choices: [1, 2, 3, 4]) (default: 1). | Optional | 
| interval_past_month | Settings for vCenter server past month statistic collection. Valid attributes are: - `enabled` (bool): Past month statistics collection enabled. (default: True) - `interval_hours` (int): Interval duration (hours). (choices: [2]) (default: 2) - `save_for_months` (int): Save for (months). (choices: [1]) (default: 1) - `level` (int): Statistics level. (choices: [1, 2, 3, 4]) (default: 1). | Optional | 
| interval_past_year | Settings for vCenter server past month statistic collection. Valid attributes are: - `enabled` (bool): Past month statistics collection enabled. (default: True) - `interval_days` (int): Interval duration (days). (choices: [1]) (default: 1) - `save_for_years` (int): Save for (years). (choices: [1, 2, 3, 4, 5]) (default: 1) - `level` (int): Statistics level. (choices: [1, 2, 3, 4]) (default: 1). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVcenterStatistics.results | unknown | metadata about vCenter statistics settings | 


#### Command Example
```!vmware-vcenter-statistics interval_past_day="{'enabled': True, 'interval_minutes': 5, 'save_for_days': 1, 'level': 1}" interval_past_week="{'enabled': True, 'level': 1}" interval_past_month="{'enabled': True, 'level': 1}" interval_past_year="{'enabled': True, 'save_for_years': 1, 'level': 1}" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareVcenterStatistics": [
            {
                "changed": false,
                "msg": "vCenter statistics already configured properly",
                "past_day_enabled": true,
                "past_day_interval": 5,
                "past_day_level": 1,
                "past_day_save_for": 1,
                "past_month_enabled": true,
                "past_month_interval": 2,
                "past_month_level": 1,
                "past_month_save_for": 1,
                "past_week_enabled": true,
                "past_week_interval": 30,
                "past_week_level": 1,
                "past_week_save_for": 1,
                "past_year_enabled": true,
                "past_year_interval": 1,
                "past_year_level": 1,
                "past_year_save_for": 1,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * msg: vCenter statistics already configured properly
>  * past_day_enabled: True
>  * past_day_interval: 5
>  * past_day_level: 1
>  * past_day_save_for: 1
>  * past_month_enabled: True
>  * past_month_interval: 2
>  * past_month_level: 1
>  * past_month_save_for: 1
>  * past_week_enabled: True
>  * past_week_interval: 30
>  * past_week_level: 1
>  * past_week_save_for: 1
>  * past_year_enabled: True
>  * past_year_interval: 1
>  * past_year_level: 1
>  * past_year_save_for: 1


### vmware-vm-host-drs-rule
***
Creates vm/host group in a given cluster
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vm_host_drs_rule_module.html


#### Base Command

`vmware-vm-host-drs-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| affinity_rule | If set to `True`, the DRS rule will be an Affinity rule. If set to `False`, the DRS rule will be an Anti-Affinity rule. Effective only if `state` is set to `present`. Possible values are: Yes, No. Default is Yes. | Optional | 
| datacenter | Datacenter to search for given cluster. If not set, we use first cluster we encounter with `cluster_name`. | Optional | 
| cluster_name | Cluster to create VM-Host rule. | Required | 
| drs_rule_name | Name of rule to create or remove. | Required | 
| enabled | If set to `True`, the DRS rule will be enabled. Effective only if `state` is set to `present`. Possible values are: Yes, No. Default is No. | Optional | 
| host_group_name | Name of Host group to use with rule. Effective only if `state` is set to `present`. | Required | 
| mandatory | If set to `True`, the DRS rule will be mandatory. Effective only if `state` is set to `present`. Possible values are: Yes, No. Default is No. | Optional | 
| state | If set to `present` and the rule doesn't exists then the rule will be created. If set to `absent` and the rule exists then the rule will be deleted. Possible values are: present, absent. Default is present. | Required | 
| vm_group_name | Name of VM group to use with rule. Effective only if `state` is set to `present`. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-vm-info
***
Return basic info pertaining to a VMware machine guest
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vm_info_module.html


#### Base Command

`vmware-vm-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_type | If set to `vm`, then information are gathered for virtual machines only. If set to `template`, then information are gathered for virtual machine templates only. If set to `all`, then information are gathered for all virtual machines and virtual machine templates. Possible values are: all, vm, template. Default is all. | Optional | 
| show_attribute | Attributes related to VM guest shown in information only when this is set `true`. Possible values are: Yes, No. Default is No. | Optional | 
| folder | Specify a folder location of VMs to gather information from. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| show_tag | Tags related to virtual machine are shown if set to `True`. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmInfo.virtual_machines | unknown | list of dictionary of virtual machines and their information | 


#### Command Example
```!vmware-vm-info```

#### Context Example
```json
{
    "VMware": {
        "VmwareVmInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "virtual_machines": [
                    {
                        "attributes": {},
                        "cluster": "cluster",
                        "datacenter": "DC1",
                        "esxi_hostname": "esxi01",
                        "folder": "/DC1/vm",
                        "guest_fullname": "CentOS 4/5 or later (64-bit)",
                        "guest_name": "test_vm_0001",
                        "ip_address": "",
                        "mac_address": [
                            "aa:bb:dd:aa:00:14"
                        ],
                        "moid": "vm-21",
                        "power_state": "poweredOff",
                        "tags": [],
                        "uuid": "42166c31-2bd1-6ac0-1ebb-a6db907f529e",
                        "vm_network": {}
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Virtual_Machines
>  * ## esxi01
>    * cluster: cluster
>    * datacenter: DC1
>    * esxi_hostname: esxi01
>    * folder: /DC1/vm
>    * guest_fullname: CentOS 4/5 or later (64-bit)
>    * guest_name: test_vm_0001
>    * ip_address: 
>    * moid: vm-21
>    * power_state: poweredOff
>    * uuid: 42166c31-2bd1-6ac0-1ebb-a6db907f529e
>    * ### Attributes
>    * ### Mac_Address
>      * 0: aa:bb:dd:aa:00:14
>    * ### Tags
>    * ### Vm_Network


### vmware-vm-shell
***
Run commands in a VMware guest operating system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vm_shell_module.html


#### Base Command

`vmware-vm-shell`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | The datacenter hosting the virtual machine. If set, it will help to speed up virtual machine search. | Optional | 
| cluster | The cluster hosting the virtual machine. If set, it will help to speed up virtual machine search. | Optional | 
| folder | Destination folder, absolute or relative path to find an existing guest or create the new guest. The folder should include the datacenter. ESX's datacenter is ha-datacenter. Examples: folder: /ha-datacenter/vm folder: ha-datacenter/vm folder: /datacenter1/vm folder: datacenter1/vm folder: /datacenter1/vm/folder1 folder: datacenter1/vm/folder1 folder: /folder1/datacenter1/vm folder: folder1/datacenter1/vm folder: /folder1/datacenter1/vm/folder2. | Optional | 
| vm_id | Name of the virtual machine to work with. | Required | 
| vm_id_type | The VMware identification method by which the virtual machine will be identified. Possible values are: uuid, instance_uuid, dns_name, inventory_path, vm_name. Default is vm_name. | Optional | 
| vm_username | The user to login-in to the virtual machine. | Required | 
| vm_password | The password used to login-in to the virtual machine. | Required | 
| vm_shell | The absolute path to the program to start. On Linux, shell is executed via bash. | Required | 
| vm_shell_args | The argument to the program. The characters which must be escaped to the shell also be escaped on the command line provided. Default is  . | Optional | 
| vm_shell_env | Comma separated list of environment variable, specified in the guest OS notation. | Optional | 
| vm_shell_cwd | The current working directory of the application from which it will be run. | Optional | 
| wait_for_process | If set to `True`, module will wait for process to complete in the given virtual machine. Possible values are: Yes, No. Default is No. | Optional | 
| timeout | Timeout in seconds. If set to positive integers, then `wait_for_process` will honor this parameter and will exit after this timeout. Default is 3600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmShell.results | unknown | metadata about the new process after completion with wait_for_process | 




### vmware-vm-storage-policy-info
***
Gather information about vSphere storage profile defined storage policy information.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vm_storage_policy_info_module.html


#### Base Command

`vmware-vm-storage-policy-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmStoragePolicyInfo.spbm_profiles | unknown | list of dictionary of SPBM info | 


#### Command Example
```!vmware-vm-storage-policy-info ```

#### Context Example
```json
{
    "VMware": {
        "VmwareVmStoragePolicyInfo": [
            {
                "changed": false,
                "spbm_profiles": [
                    {
                        "constraints_sub_profiles": [
                            {
                                "rule_set_info": [
                                    {
                                        "id": "hostFailuresToTolerate",
                                        "value": 1
                                    },
                                    {
                                        "id": "stripeWidth",
                                        "value": 1
                                    },
                                    {
                                        "id": "forceProvisioning",
                                        "value": false
                                    },
                                    {
                                        "id": "proportionalCapacity",
                                        "value": 0
                                    },
                                    {
                                        "id": "cacheReservation",
                                        "value": 0
                                    }
                                ],
                                "rule_set_name": "VSAN sub-profile"
                            }
                        ],
                        "description": "Storage policy used as default for vSAN datastores",
                        "id": "aa6d5a82-1c88-45da-85d3-3d74b91a5bad",
                        "name": "vSAN Default Storage Policy"
                    },
                    {
                        "constraints_sub_profiles": [
                            {
                                "rule_set_info": [
                                    {
                                        "id": "ad5a249d-cbc2-43af-9366-694d7664fa52",
                                        "value": "ad5a249d-cbc2-43af-9366-694d7664fa52"
                                    }
                                ],
                                "rule_set_name": "sp-1"
                            }
                        ],
                        "description": "Sample storage policy for VMware's VM and virtual disk encryption",
                        "id": "4d5f673c-536f-11e6-beb8-9e71128cae77",
                        "name": "VM Encryption Policy"
                    },
                    {
                        "constraints_sub_profiles": [],
                        "description": "Allow the datastore to determine the best placement strategy for storage objects",
                        "id": "f4e5bade-15a2-4805-bf8e-52318c4ce443",
                        "name": "VVol No Requirements Policy"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Spbm_Profiles
>  * ## Vsan Default Storage Policy
>    * description: Storage policy used as default for vSAN datastores
>    * id: aa6d5a82-1c88-45da-85d3-3d74b91a5bad
>    * name: vSAN Default Storage Policy
>    * ### Constraints_Sub_Profiles
>    * ### Vsan Sub-Profile
>      * rule_set_name: VSAN sub-profile
>      * #### Rule_Set_Info
>      * #### Hostfailurestotolerate
>        * id: hostFailuresToTolerate
>        * value: 1
>      * #### Stripewidth
>        * id: stripeWidth
>        * value: 1
>      * #### Forceprovisioning
>        * id: forceProvisioning
>        * value: False
>      * #### Proportionalcapacity
>        * id: proportionalCapacity
>        * value: 0
>      * #### Cachereservation
>        * id: cacheReservation
>        * value: 0
>  * ## Vm Encryption Policy
>    * description: Sample storage policy for VMware's VM and virtual disk encryption
>    * id: 4d5f673c-536f-11e6-beb8-9e71128cae77
>    * name: VM Encryption Policy
>    * ### Constraints_Sub_Profiles
>    * ### Sp-1
>      * rule_set_name: sp-1
>      * #### Rule_Set_Info
>      * #### Ad5A249D-Cbc2-43Af-9366-694D7664Fa52
>        * id: ad5a249d-cbc2-43af-9366-694d7664fa52
>        * value: ad5a249d-cbc2-43af-9366-694d7664fa52
>  * ## Vvol No Requirements Policy
>    * description: Allow the datastore to determine the best placement strategy for storage objects
>    * id: f4e5bade-15a2-4805-bf8e-52318c4ce443
>    * name: VVol No Requirements Policy
>    * ### Constraints_Sub_Profiles


### vmware-vm-vm-drs-rule
***
Configure VMware DRS Affinity rule for virtual machine in given cluster
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vm_vm_drs_rule_module.html


#### Base Command

`vmware-vm-vm-drs-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Desired cluster name where virtual machines are present for the DRS rule. | Required | 
| vms | List of virtual machines name for which DRS rule needs to be applied. Required if `state` is set to `present`. | Optional | 
| drs_rule_name | The name of the DRS rule to manage. | Required | 
| enabled | If set to `True`, the DRS rule will be enabled. Effective only if `state` is set to `present`. Possible values are: Yes, No. Default is No. | Optional | 
| mandatory | If set to `True`, the DRS rule will be mandatory. Effective only if `state` is set to `present`. Possible values are: Yes, No. Default is No. | Optional | 
| affinity_rule | If set to `True`, the DRS rule will be an Affinity rule. If set to `False`, the DRS rule will be an Anti-Affinity rule. Effective only if `state` is set to `present`. Possible values are: Yes, No. Default is Yes. | Optional | 
| state | If set to `present`, then the DRS rule is created if not present. If set to `present`, then the DRS rule is already present, it updates to the given configurations. If set to `absent`, then the DRS rule is deleted if present. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmVmDrsRule.result | unknown | metadata about DRS VM and VM rule | 




### vmware-vm-vss-dvs-migrate
***
Migrates a virtual machine from a standard vswitch to distributed
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vm_vss_dvs_migrate_module.html


#### Base Command

`vmware-vm-vss-dvs-migrate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_name | Name of the virtual machine to migrate to a dvSwitch. | Required | 
| dvportgroup_name | Name of the portgroup to migrate to the virtual machine to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-vmkernel
***
Manages a VMware VMkernel Adapter of an ESXi host.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vmkernel_module.html


#### Base Command

`vmware-vmkernel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vswitch_name | The name of the vSwitch where to add the VMKernel interface. Required parameter only if `state` is set to `present`. Optional parameter from version 2.5 and onwards. | Optional | 
| dvswitch_name | The name of the vSphere Distributed Switch (vDS) where to add the VMKernel interface. Required parameter only if `state` is set to `present`. Optional parameter from version 2.8 and onwards. | Optional | 
| portgroup_name | The name of the port group for the VMKernel interface. | Required | 
| network | A dictionary of network details. The following parameter is required: - `type` (string): Type of IP assignment (either `dhcp` or `static`). The following parameters are required in case of `type` is set to `static`: - `ip_address` (string): Static IP address (implies `type: static`). - `subnet_mask` (string): Static netmask required for `ip_address`. The following parameter is optional in case of `type` is set to `static`: - `default_gateway` (string): Default gateway (Override default gateway for this adapter). The following parameter is optional: - `tcpip_stack` (string): The TCP/IP stack for the VMKernel interface. Can be default, provisioning, vmotion, or vxlan. (default: default). Default is {'type': 'static', 'tcpip_stack': 'default'}. | Optional | 
| ip_address | The IP Address for the VMKernel interface. Use `network` parameter with `ip_address` instead. Deprecated option, will be removed in version 2.9. | Optional | 
| subnet_mask | The Subnet Mask for the VMKernel interface. Use `network` parameter with `subnet_mask` instead. Deprecated option, will be removed in version 2.9. | Optional | 
| mtu | The MTU for the VMKernel interface. The default value of 1500 is valid from version 2.5 and onwards. Default is 1500. | Optional | 
| device | Search VMkernel adapter by device name. The parameter is required only in case of `type` is set to `dhcp`. | Optional | 
| enable_vsan | Enable VSAN traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. | Optional | 
| enable_vmotion | Enable vMotion traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. You cannot enable vMotion on an additional adapter if you already have an adapter with the vMotion TCP/IP stack configured. | Optional | 
| enable_mgmt | Enable Management traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. | Optional | 
| enable_ft | Enable Fault Tolerance traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. | Optional | 
| enable_provisioning | Enable Provisioning traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. | Optional | 
| enable_replication | Enable vSphere Replication traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. | Optional | 
| enable_replication_nfc | Enable vSphere Replication NFC traffic on the VMKernel adapter. This option is only allowed if the default TCP/IP stack is used. | Optional | 
| state | If set to `present`, the VMKernel adapter will be created with the given specifications. If set to `absent`, the VMKernel adapter will be removed. If set to `present` and VMKernel adapter exists, the configurations will be updated. Possible values are: present, absent. Default is present. | Optional | 
| esxi_hostname | Name of ESXi host to which VMKernel is to be managed. From version 2.5 onwards, this parameter is required. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmkernel.result | unknown | metadata about VMKernel name | 




### vmware-vmkernel-info
***
Gathers VMKernel info about an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vmkernel_info_module.html


#### Base Command

`vmware-vmkernel-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. VMKernel information about each ESXi server will be returned for the given cluster. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname. VMKernel information about this ESXi server will be returned. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmkernelInfo.host_vmk_info | unknown | metadata about VMKernel present on given host system | 


#### Command Example
```!vmware-vmkernel-info cluster_name="cluster" ```

#### Context Example
```json
{
    "VMware": {
        "VmwareVmkernelInfo": [
            {
                "changed": false,
                "host_vmk_info": {
                    "esxi01": [
                        {
                            "device": "vmk0",
                            "dhcp": true,
                            "enable_ft": false,
                            "enable_management": true,
                            "enable_vmotion": false,
                            "enable_vsan": false,
                            "ipv4_address": "esxi01",
                            "ipv4_subnet_mask": "255.255.255.0",
                            "key": "key-vim.host.VirtualNic-vmk0",
                            "mac": "00:0c:29:d9:27:04",
                            "mtu": 1500,
                            "portgroup": "Management Network",
                            "stack": "defaultTcpipStack"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Host_Vmk_Info
>    * ### esxi01
>    * ### List
>      * device: vmk0
>      * dhcp: True
>      * enable_ft: False
>      * enable_management: True
>      * enable_vmotion: False
>      * enable_vsan: False
>      * ipv4_address: esxi01
>      * ipv4_subnet_mask: 255.255.255.0
>      * key: key-vim.host.VirtualNic-vmk0
>      * mac: 00:0c:29:d9:27:04
>      * mtu: 1500
>      * portgroup: Management Network
>      * stack: defaultTcpipStack


### vmware-vmkernel-ip-config
***
Configure the VMkernel IP Address
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vmkernel_ip_config_module.html


#### Base Command

`vmware-vmkernel-ip-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vmk_name | VMkernel interface name. | Required | 
| ip_address | IP address to assign to VMkernel interface. | Required | 
| subnet_mask | Subnet Mask to assign to VMkernel interface. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-vmotion
***
Move a virtual machine using vMotion, and/or its vmdks using storage vMotion.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vmotion_module.html


#### Base Command

`vmware-vmotion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_name | Name of the VM to perform a vMotion on. This is required parameter, if `vm_uuid` is not set. Version 2.6 onwards, this parameter is not a required parameter, unlike the previous versions. | Optional | 
| vm_uuid | UUID of the virtual machine to perform a vMotion operation on. This is a required parameter, if `vm_name` or `moid` is not set. | Optional | 
| moid | Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance. This is required if `vm_name` or `vm_uuid` is not supplied. | Optional | 
| use_instance_uuid | Whether to use the VMware instance UUID rather than the BIOS UUID. Possible values are: Yes, No. Default is No. | Optional | 
| destination_host | Name of the destination host the virtual machine should be running on. Version 2.6 onwards, this parameter is not a required parameter, unlike the previous versions. | Optional | 
| destination_datastore | Name of the destination datastore the virtual machine's vmdk should be moved on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVmotion.running_host | string | List the host the virtual machine is registered to | 




### vmware-vsan-cluster
***
Configure VSAN clustering on an ESXi host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vsan_cluster_module.html


#### Base Command

`vmware-vsan-cluster`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_uuid | Desired cluster UUID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!vmware-vsan-cluster ```

#### Context Example
```json
{
    "VMware": {
        "VmwareVsanCluster": [
            {
                "changed": true,
                "cluster_uuid": "525e42db-3df5-4184-b178-874f4ef18006",
                "result": null,
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * cluster_uuid: 525e42db-3df5-4184-b178-874f4ef18006
>  * result: None


### vmware-vspan-session
***
Create or remove a Port Mirroring session.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vspan_session_module.html


#### Base Command

`vmware-vspan-session`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | The name of the distributed vSwitch on which to add or remove the mirroring session. | Required | 
| name | Name of the session. | Required | 
| state | Create or remove the session. Possible values are: present, absent. | Required | 
| session_type | Select the mirroring type. - `encapsulatedRemoteMirrorSource` (str): In encapsulatedRemoteMirrorSource session, Distributed Ports can be used as source entities, and Ip address can be used as destination entities. - `remoteMirrorDest` (str): In remoteMirrorDest session, vlan Ids can be used as source entities, and Distributed Ports can be used as destination entities. - `remoteMirrorSource` (str): In remoteMirrorSource session, Distributed Ports can be used as source entities, and uplink ports name can be used as destination entities. - `dvPortMirror` (str): In dvPortMirror session, Distributed Ports can be used as both source and destination entities. Possible values are: encapsulatedRemoteMirrorSource, remoteMirrorDest, remoteMirrorSource, dvPortMirror. Default is dvPortMirror. | Optional | 
| enabled | Whether the session is enabled. Possible values are: Yes, No. Default is Yes. | Optional | 
| description | The description for the session. | Optional | 
| source_port_transmitted | Source port for which transmitted packets are mirrored. | Optional | 
| source_port_received | Source port for which received packets are mirrored. | Optional | 
| destination_port | Destination port that received the mirrored packets. Also any port designated in the value of this property can not match the source port in any of the Distributed Port Mirroring session. | Optional | 
| encapsulation_vlan_id | VLAN ID used to encapsulate the mirrored traffic. | Optional | 
| strip_original_vlan | Whether to strip the original VLAN tag. if false, the original VLAN tag will be preserved on the mirrored traffic. If encapsulationVlanId has been set and this property is false, the frames will be double tagged with the original VLAN ID as the inner tag. | Optional | 
| mirrored_packet_length | An integer that describes how much of each frame to mirror. If unset, all of the frame would be mirrored. Setting this property to a smaller value is useful when the consumer will look only at the headers. The value cannot be less than 60. | Optional | 
| normal_traffic_allowed | Whether or not destination ports can send and receive "normal" traffic. Setting this to false will make mirror ports be used solely for mirroring and not double as normal access ports. | Optional | 
| sampling_rate | Sampling rate of the session. If its value is n, one of every n packets is mirrored. Valid values are between 1 to 65535, and default value is 1. | Optional | 
| source_vm_transmitted | With this parameter it is possible, to add a NIC of a VM to a port mirroring session. Valid attributes are: - `name` (str): Name of the VM - `nic_label` (bool): Label of the Network Interface Card to use. | Optional | 
| source_vm_received | With this parameter it is possible, to add a NIC of a VM to a port mirroring session. Valid attributes are: - `name` (str): Name of the VM - `nic_label` (bool): Label of the Network Interface Card to use. | Optional | 
| destination_vm | With this parameter it is possible, to add a NIC of a VM to a port mirroring session. Valid attributes are: - `name` (str): Name of the VM - `nic_label` (bool): Label of the Network Interface Card to use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-vswitch
***
Manage a VMware Standard Switch to an ESXi host.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vswitch_module.html


#### Base Command

`vmware-vswitch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch | vSwitch name to add. Alias `switch` is added in version 2.4. | Required | 
| nics | A list of vmnic names or vmnic name to attach to vSwitch. Alias `nics` is added in version 2.4. | Optional | 
| number_of_ports | Number of port to configure on vSwitch. Default is 128. | Optional | 
| mtu | MTU to configure on vSwitch. Default is 1500. | Optional | 
| state | Add or remove the switch. Possible values are: absent, present. Default is present. | Optional | 
| esxi_hostname | Manage the vSwitch using this ESXi host system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVswitch.result | string | information about performed operation | 


#### Command Example
```!vmware-vswitch switch="vswitch_name" nics="vmnic1" mtu="9000" esxi_hostname="esxi01"```

#### Context Example
```json
{
    "VMware": {
        "VmwareVswitch": [
            {
                "changed": false,
                "result": "No change in vSwitch 'vswitch_name'",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * result: No change in vSwitch 'vswitch_name'


### vmware-vswitch-info
***
Gathers info about an ESXi host's vswitch configurations
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vmware_vswitch_info_module.html


#### Base Command

`vmware-vswitch-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | Name of the cluster. Info about vswitch belonging to every ESXi host systems under this cluster will be returned. If `esxi_hostname` is not given, this parameter is required. | Optional | 
| esxi_hostname | ESXi hostname to gather information from. If `cluster_name` is not given, this parameter is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VmwareVswitchInfo.hosts_vswitch_info | unknown | metadata about host's vswitch configuration | 


#### Command Example
```!vmware-vswitch-info cluster_name="cluster"```

#### Context Example
```json
{
    "VMware": {
        "VmwareVswitchInfo": [
            {
                "changed": false,
                "hosts_vswitch_info": {
                    "esxi01": {
                        "vSwitch0": {
                            "mtu": 1500,
                            "num_ports": 128,
                            "pnics": [
                                "vmnic0"
                            ]
                        },
                        "vswitch_name": {
                            "mtu": 9000,
                            "num_ports": 128,
                            "pnics": [
                                "vmnic1"
                            ]
                        }
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Hosts_Vswitch_Info
>    * ### esxi01
>      * #### Vswitch0
>        * mtu: 1500
>        * num_ports: 128
>        * ##### Pnics
>          * 0: vmnic0
>      * #### Vswitch_Name
>        * mtu: 9000
>        * num_ports: 128
>        * ##### Pnics
>          * 0: vmnic1


### vmware-vsphere-file
***
Manage files on a vCenter datastore
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vsphere_file_module.html


#### Base Command

`vmware-vsphere-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The vCenter server on which the datastore is available. | Required | 
| datacenter | The datacenter on the vCenter server that holds the datastore. | Required | 
| datastore | The datastore on the vCenter server to push files to. | Required | 
| path | The file or directory on the datastore on the vCenter server. | Required | 
| timeout | The timeout in seconds for the upload to the datastore. Default is 10. | Optional | 
| state | The state of or the action on the provided path. If `absent`, the file will be removed. If `directory`, the directory will be created. If `file`, more information of the (existing) file will be returned. If `touch`, an empty file will be created if the path does not exist. Possible values are: absent, directory, file, touch. Default is file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### vmware-vcenter-extension
***
Register/deregister vCenter Extensions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vcenter_extension_module.html


#### Base Command

`vmware-vcenter-extension`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| extension_key | The extension key of the extension to install or uninstall. | Required | 
| version | The version of the extension you are installing or uninstalling. | Required | 
| name | Required for `state=present`. The name of the extension you are installing. | Optional | 
| company | Required for `state=present`. The name of the company that makes the extension. | Optional | 
| description | Required for `state=present`. A short description of the extension. | Optional | 
| email | Required for `state=present`. Administrator email to use for extension. | Optional | 
| url | Required for `state=present`. Link to server hosting extension zip file to install. | Optional | 
| ssl_thumbprint | Required for `state=present`. SSL thumbprint of the extension hosting server. | Optional | 
| server_type | Required for `state=present`. Type of server being used to install the extension (SOAP, REST, HTTP, etc.). Default is vsphere-client-serenity. | Optional | 
| client_type | Required for `state=present`. Type of client the extension is (win32, .net, linux, etc.). Default is vsphere-client-serenity. | Optional | 
| visible | Show the extension in solution manager inside vCenter. Possible values are: Yes, No. Default is Yes. | Optional | 
| state | Add or remove vCenter Extension. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VcenterExtension.result | string | information about performed operation | 




### vmware-vcenter-extension-info
***
Gather info vCenter extensions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vcenter_extension_info_module.html


#### Base Command

`vmware-vcenter-extension-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VcenterExtensionInfo.extension_info | unknown | List of extensions | 


#### Command Example
```!vmware-vcenter-extension-info ```

#### Context Example
```json
{
    "VMware": {
        "VcenterExtensionInfo": [
            {
                "changed": false,
                "extension_info": [
                    {
                        "extension_company": "VMware Inc.",
                        "extension_key": "com.vmware.vim.sms",
                        "extension_label": "VMware vCenter Storage Monitoring Service",
                        "extension_last_heartbeat_time": "2021-07-11T15:21:08.666734+00:00",
                        "extension_subject_name": "",
                        "extension_summary": "Storage Monitoring and Reporting",
                        "extension_type": "",
                        "extension_version": "5.5"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Extension_Info
>  * ## 
>    * extension_company: VMware Inc.
>    * extension_key: com.vmware.vim.sms
>    * extension_label: VMware vCenter Storage Monitoring Service
>    * extension_last_heartbeat_time: 2021-07-11T15:21:08.666734+00:00
>    * extension_subject_name: 
>    * extension_summary: Storage Monitoring and Reporting
>    * extension_type: 
>    * extension_version: 5.5


### vmware-vcenter-folder
***
Manage folders on given datacenter
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vcenter_folder_module.html


#### Base Command

`vmware-vcenter-folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datacenter | Name of the datacenter. | Required | 
| folder_name | Name of folder to be managed. This is case sensitive parameter. Folder name should be under 80 characters. This is a VMware restriction. | Required | 
| parent_folder | Name of the parent folder under which new folder needs to be created. This is case sensitive parameter. Please specify unique folder name as there is no way to detect duplicate names. If user wants to create a folder under '/DC0/vm/vm_folder', this value will be 'vm_folder'. | Optional | 
| folder_type | This is type of folder. If set to `vm`, then 'VM and Template Folder' is created under datacenter. If set to `host`, then 'Host and Cluster Folder' is created under datacenter. If set to `datastore`, then 'Storage Folder' is created under datacenter. If set to `network`, then 'Network Folder' is created under datacenter. This parameter is required, if `state` is set to `present` and parent_folder is absent. This option is ignored, if `parent_folder` is set. Possible values are: datastore, host, network, vm. Default is vm. | Optional | 
| state | State of folder. If set to `present` without parent folder parameter, then folder with `folder_type` is created. If set to `present` with parent folder parameter,  then folder in created under parent folder. `folder_type` is ignored. If set to `absent`, then folder is unregistered and destroyed. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VcenterFolder.result | unknown | The detail about the new folder | 


#### Command Example
```!vmware-vcenter-folder datacenter="DC1" folder_name="sample_vm_folder" folder_type="vm" state="present" ```

#### Context Example
```json
{
    "VMware": {
        "VcenterFolder": [
            {
                "changed": false,
                "result": {
                    "msg": "Folder sample_vm_folder already exists",
                    "path": "/DC1/vm/sample_vm_folder"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Result
>    * msg: Folder sample_vm_folder already exists
>    * path: /DC1/vm/sample_vm_folder

### vmware-vcenter-license
***
Manage VMware vCenter license keys
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/vcenter_license_module.html


#### Base Command

`vmware-vcenter-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| labels | The optional labels of the license key to manage in vSphere vCenter. This is dictionary with key/value pair. Default is {'source': 'ansible'}. | Optional | 
| license | The license key to manage in vSphere vCenter. | Required | 
| state | Whether to add (`present`) or remove (`absent`) the license key. Possible values are: absent, present. Default is present. | Optional | 
| esxi_hostname | The hostname of the ESXi server to which the specified license will be assigned. This parameter is optional. | Optional | 
| datacenter | The datacenter name to use for the operation. | Optional | 
| cluster_name | Name of the cluster to apply vSAN license. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMware.VcenterLicense.licenses | unknown | list of license keys after module executed | 


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Cortex XSOAR 6.13 Docker Hardening Guide](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administator-Guide/Docker-Hardening-Guide). and [Cortex XSOAR 8 Cloud Docker Hardening Guide](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
