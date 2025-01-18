FortiManager is a single console central management system that manages Fortinet Devices.
This integration was integrated and tested with version 6.2.2 of FortiManager

## Required Permissions
Following are the required permissions for the integration commands:

| **Setting** | **Minimal Requirement** |
| --- | --- | 
| device-manager | Read-Only | 
| global-policy-packages | Read-Write |
| adom-policy-packages | Read-Write |
| deploy-management | Read-Write |

The eligible predefined administrator profiles are: **Super User**, **Standard User**, and **Package User**.
For more information about administrator permissions see the [FortiManager documentation](https://docs.fortinet.com/document/fortimanager/6.2.2/administration-guide/392019/permissions).

## Configure FortiManager in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| credentials | Username | True |
| adom | The instance ADOM | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortimanager-devices-list
***
List all devices in the ADOM instance.


#### Base Command

`fortimanager-devices-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The FortiManager Administrative Domain (ADOM) from which to fetch the devices. Leave empty to use the instance ADOM. | Optional | 
| device | The name of a specific device to get. If not specified, will get all devices. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | Until which index to get the list. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.Device.adm_pass | String | The ADOM password. | 
| FortiManager.Device.adm_usr | String | The ADOM user. | 
| FortiManager.Device.app_ver | String | The app version of the device. | 
| FortiManager.Device.av_ver | String | The antivirus version of the device. | 
| FortiManager.Device.beta | Number | The beta version of the device. | 
| FortiManager.Device.branch_pt | Number | The branch point of the device. | 
| FortiManager.Device.build | Number | The build of the device. | 
| FortiManager.Device.checksum | String | The checksum of the device. | 
| FortiManager.Device.conf_status | String | The configuration status of the device. | 
| FortiManager.Device.conn_mode | String | The connection mode of the device. | 
| FortiManager.Device.conn_status | String | The connection status of the device. | 
| FortiManager.Device.db_status | String | The database status of the device. | 
| FortiManager.Device.desc | String | The description of the device. | 
| FortiManager.Device.dev_status | String | The status of the device. | 
| FortiManager.Device.fap_cnt | Number | The FortiManager access point count. | 
| FortiManager.Device.faz.full_act | Number | Full act. | 
| FortiManager.Device.faz.perm | Number | Perm. | 
| FortiManager.Device.faz.quota | Number | Quota. | 
| FortiManager.Device.faz.used | Number | Used. | 
| FortiManager.Device.fex_cnt | Number | Fex count. | 
| FortiManager.Device.flags | String | Flags. | 
| FortiManager.Device.foslic_cpu | Number | Foslic CPU. | 
| FortiManager.Device.foslic_dr_site | String | Foslic dr site. | 
| FortiManager.Device.foslic_inst_time | Number | Foslic inst time. | 
| FortiManager.Device.foslic_last_sync | Number | Foslic last sync. | 
| FortiManager.Device.foslic_ram | Number | Foslic RAM. | 
| FortiManager.Device.foslic_type | String | Foslic type. | 
| FortiManager.Device.foslic_utm | String | Foslic UTM. | 
| FortiManager.Device.fsw_cnt | Number | FSW count. | 
| FortiManager.Device.ha_group_id | Number | HA group ID. | 
| FortiManager.Device.ha_group_name | String | HA group name. | 
| FortiManager.Device.ha_mode | String | HA mode. | 
| FortiManager.Device.hdisk_size | Number | Hard disk size. | 
| FortiManager.Device.hostname | String | Hostname. | 
| FortiManager.Device.hw_rev_major | Number | Hardware major revision number. | 
| FortiManager.Device.hw_rev_minor | Number | Hardware minor revision number. | 
| FortiManager.Device.ip | String | Device IP. | 
| FortiManager.Device.ips_ext | Number | External IP. | 
| FortiManager.Device.ips_ver | String | IP version. | 
| FortiManager.Device.last_checked | Number | Last checked. | 
| FortiManager.Device.last_resync | Number | Last resync. | 
| FortiManager.Device.latitude | String | Latitude. | 
| FortiManager.Device.lic_flags | Number | License flags. | 
| FortiManager.Device.lic_region | String | License region. | 
| FortiManager.Device.location_from | String | Location from. | 
| FortiManager.Device.logdisk_size | Number | Log disk size. | 
| FortiManager.Device.longitude | String | Longitude. | 
| FortiManager.Device.maxvdom | Number | Maximum VDOM. | 
| FortiManager.Device.meta_fields | String | Meta fields. | 
| FortiManager.Device.mgmt_id | Number | Management ID. | 
| FortiManager.Device.mgmt_if | String | Management IF. | 
| FortiManager.Device.mgmt_mode | String | Management mode. | 
| FortiManager.Device.mgt_vdom | String | Management VDOM. | 
| FortiManager.Device.module_sn | String | Module serial number. | 
| FortiManager.Device.mr | Number | Mr. | 
| FortiManager.Device.name | String | Device name. | 
| FortiManager.Device.os_type | String | Device operating system type. | 
| FortiManager.Device.os_ver | String | Device operating system version. | 
| FortiManager.Device.patch | Number | Patch. | 
| FortiManager.Device.platform_str | String | Platform string. | 
| FortiManager.Device.prefer_img_ver | String | Prefer image version. | 
| FortiManager.Device.prio | Number | Prio. | 
| FortiManager.Device.psk | String | PSK. | 
| FortiManager.Device.role | String | Device role. | 
| FortiManager.Device.sn | String | Serial number. | 
| FortiManager.Device.vdom.comments | String | VDOM comments. | 
| FortiManager.Device.vdom.name | String | VDOM name. | 
| FortiManager.Device.vdom.opmode | String | VDOM opmode. | 
| FortiManager.Device.vdom.rtm_prof_id | Number | VDOM rtm prof ID. | 
| FortiManager.Device.vdom.status | String | VDOM status. | 
| FortiManager.Device.vdom.vpn_id | Number | VDOM VPN ID. | 
| FortiManager.Device.version | Number | Device version. | 
| FortiManager.Device.vm_cpu | Number | VM CPU. | 
| FortiManager.Device.vm_cpu_limit | Number | VM CPU limit. | 
| FortiManager.Device.vm_lic_expire | Number | VM license expiration. | 
| FortiManager.Device.vm_mem | Number | VM memory. | 
| FortiManager.Device.vm_mem_limit | Number | VM memory limit. | 
| FortiManager.Device.vm_status | Number | VM status. | 


#### Command Example
```!fortimanager-devices-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "Device": [
            {
                "adm_pass": [
                    "ENC",
                    "MMM"
                ],
                "adm_usr": "",
                "app_ver": "",
                "av_ver": "",
                "beta": -1,
                "branch_pt": 4271,
                "build": 4148,
                "checksum": "",
                "conf_status": 0,
                "conn_mode": 0,
                "conn_status": 0,
                "db_status": 2,
                "desc": "",
                "dev_status": 0,
                "fap_cnt": 0,
                "faz.full_act": 0,
                "faz.perm": 15,
                "faz.quota": 0,
                "faz.used": 0,
                "fex_cnt": 0,
                "flags": 2,
                "foslic_cpu": 0,
                "foslic_dr_site": 0,
                "foslic_inst_time": 0,
                "foslic_last_sync": 0,
                "foslic_ram": 0,
                "foslic_type": 0,
                "foslic_utm": 0,
                "fsw_cnt": 0,
                "ha_group_id": 0,
                "ha_group_name": "",
                "ha_mode": 0,
                "ha_slave": null,
                "hdisk_size": 0,
                "hostname": "",
                "hw_rev_major": 0,
                "hw_rev_minor": 0,
                "ip": "1.2.3.4",
                "ips_ext": 0,
                "ips_ver": "",
                "last_checked": 0,
                "last_resync": 0,
                "latitude": "0.0",
                "lic_flags": 0,
                "lic_region": "",
                "location_from": null,
                "logdisk_size": 0,
                "longitude": "0.0",
                "maxvdom": 500,
                "mgmt.__data[0]": 0,
                "mgmt.__data[1]": 0,
                "mgmt.__data[2]": 0,
                "mgmt.__data[3]": 0,
                "mgmt.__data[4]": 0,
                "mgmt.__data[5]": 0,
                "mgmt.__data[6]": 0,
                "mgmt.__data[7]": 0,
                "mgmt_id": 2104064363,
                "mgmt_if": "",
                "mgmt_mode": 2,
                "mgt_vdom": "",
                "module_sn": null,
                "mr": 6,
                "name": "device_name",
                "node_flags": 0,
                "oid": 156,
                "opts": 0,
                "os_type": 0,
                "os_ver": 5,
                "patch": 6,
                "platform_str": "Fortigate-6000F",
                "prefer_img_ver": null,
                "psk": "",
                "sn": "device_name",
                "source": 2,
                "tab_status": "",
                "tunnel_cookie": "",
                "tunnel_ip": "",
                "vdom": [
                    {
                        "comments": null,
                        "devid": "device_name",
                        "ext_flags": 1,
                        "flags": 0,
                        "name": "root",
                        "node_flags": 0,
                        "oid": 3,
                        "opmode": 1,
                        "rtm_prof_id": 0,
                        "status": null,
                        "tab_status": null,
                        "vpn_id": 0
                    },
                    {
                        "comments": null,
                        "devid": "device_name",
                        "ext_flags": 0,
                        "flags": 0,
                        "name": "mgmt-vdom",
                        "node_flags": 0,
                        "oid": 101,
                        "opmode": 1,
                        "rtm_prof_id": 0,
                        "status": null,
                        "tab_status": null,
                        "vpn_id": 0
                    }
                ],
                "version": 500,
                "vm_cpu": 0,
                "vm_cpu_limit": 0,
                "vm_lic_expire": 0,
                "vm_mem": 0,
                "vm_mem_limit": 0,
                "vm_status": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### ADOM adom/root Devices
>|Name|Ip|Hostname|Os Type|Adm Usr|Vdom|Ha Mode|
>|---|---|---|---|---|---|---|
>| device_name | 1.2.3.4 |  | 0 |  | root, mgmt-vdom | 0 |
>| Another_device | 2.3.4.5 | Another_device | 4 | admin | root | 0 |

### fortimanager-device-groups-list
***
List ADOM device groups.


#### Base Command

`fortimanager-device-groups-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the device groups. Leave empty to use the instance ADOM. | Optional | 
| group | The name of a device group to fetch.  If not specified, will get all device groups. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | Until which index to get the list. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.DeviceGroup.desc | String | Description. | 
| FortiManager.DeviceGroup.meta_fields | String | Device group meta fields. | 
| FortiManager.DeviceGroup.name | String | Device group name. | 
| FortiManager.DeviceGroup.os_type | String | Device group operating system type. | 
| FortiManager.DeviceGroup.type | String | Device group type. | 


#### Command Example
```!fortimanager-device-groups-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "DeviceGroup": [
            {
                "desc": "",
                "name": "All_FortiAnalyzer",
                "oid": 253,
                "os_type": 4,
                "type": 1
            },
            {
                "desc": "",
                "name": "All_FortiGate",
                "oid": 101,
                "os_type": 0,
                "type": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### ADOM adom/root Device Groups
>|Name|Type|Os Type|
>|---|---|---|
>| All_FortiAnalyzer | 1 | 4 |
>| All_FortiGate | 1 | 0 |


### fortimanager-address-list
***
List ADOM firewall IPv4 addresses.


#### Base Command

`fortimanager-address-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the addresses. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 
| address | The name of a specific address to fetch.  If not specified, will get all addresses. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.Address._image-base64 | String | Base64 of the address image. | 
| FortiManager.Address.allow-routing | String | Enable/disable use of this address in the static route configuration. | 
| FortiManager.Address.associated-interface | String | Network interface associated with address. | 
| FortiManager.Address.cache-ttl | Number | Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds. | 
| FortiManager.Address.color | Number | The color of the icon in the GUI. | 
| FortiManager.Address.comment | String | The comments attached to the address. | 
| FortiManager.Address.country | String | The IP addresses associated with a specific country. | 
| FortiManager.Address.dynamic_mapping | String | The address dynamic mapping information. | 
| FortiManager.Address.end-ip | String | The final IP address \(inclusive\) in the range for the address. | 
| FortiManager.Address.epg-name | String | The endpoint group name. | 
| FortiManager.Address.filter | String | The match criteria filter. | 
| FortiManager.Address.fqdn | String | The fully qualified domain name \(fqdn\) address. | 
| FortiManager.Address.list.ip | String | The IP list associated with the address. | 
| FortiManager.Address.name | String | The address name. | 
| FortiManager.Address.obj-id | String | The object ID for NSX. | 
| FortiManager.Address.organization | String | The organization domain name \(Syntax: organization/domain\). | 
| FortiManager.Address.policy-group | String | The policy group name. | 
| FortiManager.Address.sdn | String | The software defined networking \(SDN\). | 
| FortiManager.Address.sdn-tag | String | The software defined networking \(SDN\) tag. | 
| FortiManager.Address.start-ip | String | The first IP address \(inclusive\) in the range for the address. | 
| FortiManager.Address.subnet | String | The IP address and subnet mask of address. | 
| FortiManager.Address.subnet-name | String | The subnet name. | 
| FortiManager.Address.tagging.category | String | The tag category. | 
| FortiManager.Address.tagging.name | String | The tagging entry name. | 
| FortiManager.Address.tagging.tags | String | The tags. | 
| FortiManager.Address.tenant | String | The tenant. | 
| FortiManager.Address.type | String | The type of address. | 
| FortiManager.Address.uuid | String | Universally Unique Identifier \(UUID\). This is automatically assigned but can be manually reset. | 
| FortiManager.Address.visibility | String | Enable/disable address visibility in the GUI. | 
| FortiManager.Address.wildcard | String | The IP address and wildcard netmask. | 
| FortiManager.Address.wildcard-fqdn | String | The fully qualified domain name \(fqdn\) with wildcard characters. | 


#### Command Example
```!fortimanager-address-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "Address": [
            {
                "associated-interface": [
                    "any"
                ],
                "clearpass-spt": 0,
                "color": 0,
                "dynamic_mapping": null,
                "end-ip": "1.2.3.4",
                "end-mac": "00:00:00:00:00:00",
                "list": null,
                "name": "FAC-SAML",
                "sdn-addr-type": 0,
                "start-ip": "2.3.4.5",
                "start-mac": "00:00:00:00:00:00",
                "tagging": null,
                "type": 1,
                "uuid": "Some-ID",
                "visibility": 1
            },
            {
                "allow-routing": 0,
                "associated-interface": [
                    "any"
                ],
                "clearpass-spt": 0,
                "color": 0,
                "dynamic_mapping": null,
                "end-mac": "00:00:00:00:00:00",
                "list": null,
                "name": "FIREWALL_AUTH_PORTAL_ADDRESS",
                "sdn-addr-type": 0,
                "start-mac": "00:00:00:00:00:00",
                "subnet": [
                    "0.0.0.0",
                    "0.0.0.0"
                ],
                "tagging": null,
                "type": 0,
                "uuid": "Some-ID",
                "visibility": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Firewall IPv4 Addresses
>|Name|Type|Subnet|Start-ip|End-ip|
>|---|---|---|---|---|
>| FAC-SAML | 1 |  | 1.2.3.4 | 2.3.4.5 |
>| FIREWALL_AUTH_PORTAL_ADDRESS | 0 | 0.0.0.0,<br/>0.0.0.0 |  |  |


### fortimanager-address-create
***
Add a new IPv4 address.


#### Base Command

`fortimanager-address-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to create the address. Leave empty to use the instance ADOM. | Optional | 
| name | The address name. | Required | 
| type | The type of address. Possible values are: "ipmask", "iprange", "fqdn", "wildcard", "geography", "wildcard-fqdn", and "dynamic". | Required | 
| policy_group | Policy group name. | Optional | 
| comment | A comment to add to the address. | Optional | 
| associated_interface | The network interface associated with the address. | Optional | 
| fqdn | The fully qualified domain name (fqdn) address. Required for fqdn address type. | Optional | 
| start_ip | First IP address (inclusive) in the range for the address. Required for iprange address type. | Optional | 
| end_ip | Final IP address (inclusive) in the range for the address. Required for iprange address type. | Optional | 
| subnet | IP address and subnet mask of address. Required for ipmask address type. | Optional | 
| subnet_name | The subnet name | Optional | 
| sdn | The address SDN. Required for dynamic address type. Possible values are: "aci", "aws", "nsx", "nuage", and "azure". | Optional | 
| wildcard | IP address and wildcard netmask. Required for wildcard address type. | Optional | 
| wildcard_fqdn | The fully qualified domain name (fqdn) with wildcard characters. Required for wildcard-fqdn address type. | Optional | 
| country | The two letter abbreviation representing a country associated with an IP address (for example: "us"). Required for geography address type.  | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-address-create name=new_address type=iprange start_ip=1.2.3.4 end_ip=2.3.4.5```


#### Human Readable Output

>Created new Address new_address

### fortimanager-address-update
***
Add a new IPv4 address.


#### Base Command

`fortimanager-address-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to update the address. Leave empty to use the instance ADOM. | Optional | 
| name | The address name. | Required | 
| type | Type of address. Possible values are: "ipmask", "iprange", "fqdn", "wildcard", "geography", "wildcard-fqdn", and "dynamic". | Optional | 
| policy_group | Policy group name. | Optional | 
| comment | A comment to add to the address. | Optional | 
| associated_interface | Network interface associated with address. | Optional | 
| fqdn | The fully qualified domain name (fqdn) address. Required for fqdn address type. | Optional | 
| start_ip | First IP address (inclusive) in the range for the address. Required for iprange address type. | Optional | 
| end_ip | Final IP address (inclusive) in the range for the address. Required for iprange address type. | Optional | 
| subnet | IP address and subnet mask of address. Required for ipmask address type. | Optional | 
| subnet_name | The subnet name | Optional | 
| sdn | The address SDN. Required for dynamic address type. Possible values are: "aci", "aws", "nsx", "nuage", and "azure". | Optional | 
| wildcard | IP address and wildcard netmask. Required for wildcard address type. | Optional | 
| wildcard_fqdn | The fully qualified domain name (fqdn) with wildcard characters. Required for wildcard-fqdn address type. | Optional | 
| country | The two letter abbreviation representing a country associated with an IP address (for example: "us"). Required for geography address type.  | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-address-update name=new_address end_ip=3.3.3.3```

#### Human Readable Output

>Updated Address new_address

### fortimanager-address-delete
***
Delete an address.


#### Base Command

`fortimanager-address-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to delete the address. Leave empty to use the default integration ADOM. | Optional | 
| address | The address to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-address-delete address=new_address```

#### Human Readable Output

>Deleted Address new_address

### fortimanager-address-group-list
***
List ADOM IPv4 address groups.


#### Base Command

`fortimanager-address-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the address groups. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 
| address_group | Name for a specific address group to fetch. If not specified, will get all address groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.AddressGroup._image-base64 | String | Base64 of the address group image. | 
| FortiManager.AddressGroup.allow-routing | String | Enable/disable use of this group in the static route configuration. | 
| FortiManager.AddressGroup.color | Number | The color of the icon in the GUI. | 
| FortiManager.AddressGroup.comment | String | The comment about the address group. | 
| FortiManager.AddressGroup.dynamic_mapping._image-base64 | String | The address group dynamic mapping base64 image. | 
| FortiManager.AddressGroup.dynamic_mapping._scope.name | String | The address group dynamic mapping scope name. | 
| FortiManager.AddressGroup.dynamic_mapping._scope.vdom | String | The address group dynamic mapping scope VDOM. | 
| FortiManager.AddressGroup.dynamic_mapping.allow-routing | String | Enable/disable use of this dynamic mapping in the static route configuration. | 
| FortiManager.AddressGroup.dynamic_mapping.color | Number | The color of the icon in the GUI. | 
| FortiManager.AddressGroup.dynamic_mapping.comment | String | The comment about the address group dynamic mapping. | 
| FortiManager.AddressGroup.dynamic_mapping.exclude | String | Whether to enable or disable the exclusion of the dynamic mapping. | 
| FortiManager.AddressGroup.dynamic_mapping.exclude-member | String | The exclude member. | 
| FortiManager.AddressGroup.dynamic_mapping.global-object | Number | The global object. | 
| FortiManager.AddressGroup.dynamic_mapping.member | String | The address group dynamic mapping member. | 
| FortiManager.AddressGroup.dynamic_mapping.tags | String | The address group dynamic mapping tags. | 
| FortiManager.AddressGroup.dynamic_mapping.type | String | The address group dynamic mapping type. | 
| FortiManager.AddressGroup.dynamic_mapping.uuid | String | The address group dynamic mapping UUID. | 
| FortiManager.AddressGroup.dynamic_mapping.visibility | String | The address group dynamic mapping visibility. | 
| FortiManager.AddressGroup.member | String | The address objects contained within the group. | 
| FortiManager.AddressGroup.name | String | The address group name. | 
| FortiManager.AddressGroup.tagging.category | String | The tag category. | 
| FortiManager.AddressGroup.tagging.name | String | The tagging entry name. | 
| FortiManager.AddressGroup.tagging.tags | String | The tags. | 
| FortiManager.AddressGroup.uuid | String | Universally Unique Identifier \(UUID\). This is automatically assigned but can be manually reset. | 
| FortiManager.AddressGroup.visibility | String | Enable/disable address visibility in the GUI. | 


#### Command Example
```!fortimanager-address-group-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "AddressGroup": [
            {
                "allow-routing": 0,
                "color": 0,
                "dynamic_mapping": null,
                "exclude": 0,
                "exclude-member": [],
                "member": [
                    "address1",
                    "address2",
                ],
                "name": "my_address_group",
                "tagging": null,
                "uuid": "Some-ID",
                "visibility": 1
            },
            {
                "allow-routing": 1,
                "color": 0,
                "comment": "VPN: To-600E (Created by VPN wizard)",
                "dynamic_mapping": null,
                "exclude": 0,
                "exclude-member": [],
                "member": [
                    "some_address"
                ],
                "name": "another_address_group",
                "tagging": null,
                "uuid": "Some-ID",
                "visibility": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Firewall IPv4 Address Groups
>|Name|Member|Allow-routing|
>|---|---|---|
>| my_address_group | address1,<br/>address2 | 0 |
>| another_address_group | some_address | 1 |


### fortimanager-address-group-create
***
Create a new address group.


#### Base Command

`fortimanager-address-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to create the address group. Leave empty to use the instance ADOM. | Optional | 
| name | Address group name. | Required | 
| member | A comma-separated list of the address or address group objects contained within the group. | Required | 
| comment | A comment about the address group. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-address-group-create name=new_address_group member=new_address,my_address2```


#### Human Readable Output

>Created new Address Group new_address_group

### fortimanager-address-group-update
***
Create a new address group.


#### Base Command

`fortimanager-address-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to update the address group. Leave empty to use the instance ADOM. | Optional | 
| name | Address group name. | Required | 
| member | A comma-separated list of the address or address group objects contained within the group. | Optional | 
| comment | A comment about the address group. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-address-group-update name=new_address_group member=new_address```


#### Human Readable Output

>Updated Address Group new_address_group

### fortimanager-address-group-delete
***
Delete an address group.


#### Base Command

`fortimanager-address-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to delete the address group. Leave empty to use the default integration ADOM. | Optional | 
| address_group | The address group to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-address-group-delete address_group=new_address_group```


#### Human Readable Output

>Deleted Address Group new_address_group

### fortimanager-service-categories-list
***
List the ADOM service categories.


#### Base Command

`fortimanager-service-categories-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the service categories. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 
| service_category | Name of a specific category to fetch. If not specified, will get all service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.ServiceCategory.comment | String | Comment. | 
| FortiManager.ServiceCategory.name | String | Service category name. | 


#### Command Example
```!fortimanager-service-categories-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "ServiceCategory": [
            {
                "comment": "Web access.",
                "name": "Web Access",
                "obj seq": 2
            },
            {
                "comment": "File access.",
                "name": "File Access",
                "obj seq": 3
            }
        ]
    }
}
```

#### Human Readable Output

>### Service Categories
>|Name|Comment|
>|---|---|
>| Web Access | Web access. |
>| File Access | File access. |


### fortimanager-service-group-list
***
List ADOM service groups.


#### Base Command

`fortimanager-service-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the service groups. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 
| service_group | Name of a specific service group to fetch. If not specified, will get all service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.ServiceGroup.color | Number | The color of the icon in the GUI. | 
| FortiManager.ServiceGroup.comment | String | Comment. | 
| FortiManager.ServiceGroup.member | String | The service objects contained within the group. | 
| FortiManager.ServiceGroup.name | String | The address group name. | 
| FortiManager.ServiceGroup.proxy | String | Enable/disable web proxy service group. | 


#### Command Example
```!fortimanager-service-group-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "ServiceGroup": [
            {
                "color": 0,
                "member": [
                    "DNS",
                    "HTTP",
                    "HTTPS"
                ],
                "name": "Web Access",
                "proxy": 0
            },
            {
                "color": 0,
                "member": [
                    "DCE-RPC",
                    "DNS",
                    "KERBEROS",
                    "LDAP",
                    "LDAP_UDP",
                    "SAMBA",
                    "SMB"
                ],
                "name": "Windows AD",
                "proxy": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Service Groups
>|Name|Member|Proxy|
>|---|---|---|
>| Web Access | DNS,<br/>HTTP,<br/>HTTPS | 0 |
>| Windows AD | DCE-RPC,<br/>DNS,<br/>KERBEROS,<br/>LDAP,<br/>LDAP_UDP,<br/>SAMBA,<br/>SMB | 0 |


### fortimanager-service-group-create
***
Creates a new service group.


#### Base Command

`fortimanager-service-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to create the service group. Leave empty to use the instance ADOM. | Optional | 
| comment | A comment. | Optional | 
| name | The created service group name. | Required | 
| proxy | Enable/disable a web proxy service group. | Optional | 
| member | A comma-separated list of service objects to be contained within the group. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-service-group-create member=new_service name=new_service_group ```

#### Human Readable Output
>Created new Service Group new_service_group


### fortimanager-service-group-update
***
Create a new service group.


#### Base Command

`fortimanager-service-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to update the service group. Leave empty to use the instance ADOM. | Optional | 
| comment | A comment. | Optional | 
| name | The created service group name. | Required | 
| proxy | Enable/disable a web proxy service group. | Optional | 
| member | A comma-sperated list of service objects to be contained within the group. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-service-group-update name=new_service_group proxy=disable ```

#### Human Readable Output
>Updated Service Group new_service_group


### fortimanager-service-group-delete
***
Delete a service group


#### Base Command

`fortimanager-service-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to delete the service group. Leave empty to use the default integration ADOM. | Optional | 
| service_group | The service group to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-service-group-delete service_group=new_service_group ```

#### Human Readable Output
>Deleted Service Group new_service_group


### fortimanager-custom-service-list
***
List the custom services.


#### Base Command

`fortimanager-custom-service-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the custom service. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 
| custom_service | Name of a specific custom service to fetch.  If not specified, will get all custom services. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.CustomService.app-category | Number | Application category ID. | 
| FortiManager.CustomService.app-service-type | String | Application service type. | 
| FortiManager.CustomService.application | Number | Application ID. | 
| FortiManager.CustomService.category | String | Service category. | 
| FortiManager.CustomService.check-reset-range | String | Configure the type of ICMP error message verification. | 
| FortiManager.CustomService.color | Number | Color of icon in the GUI. | 
| FortiManager.CustomService.comment | String | Comment. | 
| FortiManager.CustomService.fqdn | String | Fully qualified domain \(fqdn\) name. | 
| FortiManager.CustomService.helper | String | Helper name. | 
| FortiManager.CustomService.icmpcode | Number | ICMP code. | 
| FortiManager.CustomService.icmptype | Number | ICMP type. | 
| FortiManager.CustomService.iprange | String | Start and end of the IP range associated with service. | 
| FortiManager.CustomService.name | String | Custom service name. | 
| FortiManager.CustomService.protocol | String | Protocol type based on IANA numbers. | 
| FortiManager.CustomService.protocol-number | Number | IP protocol number. | 
| FortiManager.CustomService.proxy | String | Enable/disable a web proxy service. | 
| FortiManager.CustomService.sctp-portrange | String | Multiple SCTP port ranges. | 
| FortiManager.CustomService.session-ttl | Number | Session TTL \(300 - 604800. Default is 0.\). | 
| FortiManager.CustomService.tcp-halfclose-timer | Number | Wait time to close a TCP session waiting for an unanswered FIN packet \(1 - 86400 sec. Default is 0.\). | 
| FortiManager.CustomService.tcp-halfopen-timer | Number | Wait time to close a TCP session waiting for an unanswered open session packet \(1 - 86400 sec. Default is 0.\). | 
| FortiManager.CustomService.tcp-portrange | String | Multiple TCP port ranges. | 
| FortiManager.CustomService.tcp-timewait-timer | Number | Set the length of the TCP TIME-WAIT state in seconds \(1 - 300 sec. Default is 0.\). | 
| FortiManager.CustomService.udp-idle-timer | Number | UDP half close timeout \(0 - 86400 sec. Default is 0.\). | 
| FortiManager.CustomService.udp-portrange | String | Multiple UDP port ranges. | 
| FortiManager.CustomService.visibility | String | Enable/disable the visibility of the service in the GUI. | 


#### Command Example
```!fortimanager-custom-service-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "CustomService": [
            {
                "app-category": [],
                "app-service-type": 0,
                "application": [],
                "category": [
                    "General"
                ],
                "check-reset-range": 3,
                "color": 0,
                "helper": 1,
                "iprange": "0.0.0.0",
                "name": "ALL_TCP",
                "obj seq": 2,
                "protocol": 5,
                "proxy": 0,
                "sctp-portrange": [],
                "session-ttl": 0,
                "tcp-halfclose-timer": 0,
                "tcp-halfopen-timer": 0,
                "tcp-portrange": [
                    "1-65535"
                ],
                "tcp-timewait-timer": 0,
                "udp-idle-timer": 0,
                "udp-portrange": [],
                "visibility": 1
            },
            {
                "app-category": [],
                "app-service-type": 0,
                "application": [],
                "category": [
                    "General"
                ],
                "check-reset-range": 3,
                "color": 0,
                "helper": 1,
                "iprange": "0.0.0.0",
                "name": "ALL_UDP",
                "obj seq": 3,
                "protocol": 5,
                "proxy": 0,
                "sctp-portrange": [],
                "session-ttl": 0,
                "tcp-halfclose-timer": 0,
                "tcp-halfopen-timer": 0,
                "tcp-portrange": [],
                "tcp-timewait-timer": 0,
                "udp-idle-timer": 0,
                "udp-portrange": [
                    "1-65535"
                ],
                "visibility": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Custom Services
>|Name|Category|Protocol|Iprange|
>|---|---|---|---|
>| ALL_TCP | General | 5 | 0.0.0.0 |
>| ALL_UDP | General | 5 | 0.0.0.0 |


### fortimanager-custom-service-create
***
Create a new custom service.


#### Base Command

`fortimanager-custom-service-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the custom service. Leave empty to use the instance ADOM. | Optional | 
| name | The name of the new custom service. | Required | 
| app_category | Application category ID. | Optional | 
| app_service_type | Application service type. Possible values are: "app-id", "disable", and "app-category". Default is "disable". | Optional | 
| application | The application ID. | Optional | 
| category | The service category. | Optional | 
| check_reset_range | Configure the type of ICMP error message verification. Possible values are: "disable", "default", and "strict". | Optional | 
| comment | A comment. | Optional | 
| fqdn | Fully qualified domain name (fqdn). | Optional | 
| helper | Helper name. | Optional | 
| icmpcode | ICMP code. | Optional | 
| icmptype | ICMP type. | Optional | 
| iprange | Start and end of the IP range associated with the service. | Optional | 
| protocol | Protocol type based on IANA numbers. Possible values are: "ICMP", "IP", "TCP/UDP/SCTP", "ICMP6", "HTTP", "FTP", "CONNECT", "SOCKS", "ALL", "SOCKS-TCP", and "SOCKS-UDP". | Optional | 
| proxy | Enable/disable a web proxy service. | Optional | 
| sctp_portrange | Multiple SCTP port ranges. | Optional | 
| session_ttl | Session TTL in the range of 300 - 604800. Default is 0. | Optional | 
| tcp_halfclose_timer | Wait time to close a TCP session waiting for an unanswered FIN packet (1 - 86400 sec). Default is 0. | Optional | 
| tcp_halfopen_timer | Wait time to close a TCP session waiting for an unanswered open session packet (1 - 86400 sec). Default is 0. | Optional | 
| tcp_portrange | Multiple TCP port ranges. | Optional | 
| tcp_timewait_timer | Set the length of the TCP TIME-WAIT state in seconds (1 - 300 sec). Default is 0. | Optional | 
| udp_idle_timer | UDP half close timeout (0 - 86400 sec). Default is 0. | Optional | 
| udp_portrange | Multiple UDP port ranges. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-custom-service-create name=new_service fqdn=demisto.com```


#### Human Readable Output

>Created new Custom Service new_service

### fortimanager-custom-service-update
***
Update a custom service.


#### Base Command

`fortimanager-custom-service-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM in which to update the custom service. Leave empty to use the instance ADOM. | Optional | 
| name | The name of the new custom service. | Required | 
| app_category | Application category ID. | Optional | 
| app_service_type | Application service type. Possible values are: "app-id", "disable", and "app-category". Default is "disable". | Optional | 
| application | The application ID. | Optional | 
| category | The service category. | Optional | 
| check_reset_range | Configure the type of ICMP error message verification. Possible values are: "disable", "default", and "strict". | Optional | 
| comment | A comment. | Optional | 
| fqdn | Fully qualified domain name (fqdn). | Optional | 
| helper | Helper name. | Optional | 
| icmpcode | ICMP code. | Optional | 
| icmptype | ICMP type. | Optional | 
| iprange | Start and end of the IP range associated with service. | Optional | 
| protocol | Protocol type based on IANA numbers. Possible values are: "ICMP", "IP", "TCP/UDP/SCTP", "ICMP6", "HTTP", "FTP", "CONNECT", "SOCKS", "ALL", "SOCKS-TCP", and "SOCKS-UDP". | Optional | 
| proxy | Enable/disable a web proxy service. | Optional | 
| sctp_portrange | Multiple SCTP port ranges. | Optional | 
| session_ttl | Session TTL in the range of 300 - 604800. Default is 0. | Optional | 
| tcp_halfclose_timer | Wait time to close a TCP session waiting for an unanswered FIN packet (1 - 86400 sec). Default is 0. | Optional | 
| tcp_halfopen_timer | Wait time to close a TCP session waiting for an unanswered open session packet (1 - 86400 sec). Default is 0. | Optional | 
| tcp_portrange | Multiple TCP port ranges. | Optional | 
| tcp_timewait_timer | Set the length of the TCP TIME-WAIT state in seconds (1 - 300 sec). Default is 0. | Optional | 
| udp_idle_timer | UDP half close timeout (0 - 86400 sec). Default is 0. | Optional | 
| udp_portrange | Multiple UDP port ranges. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-custom-service-update name=new_service proxy=enable```


#### Human Readable Output

>Updated Custom Service new_service

### fortimanager-custom-service-delete
***
Delete a custom service.


#### Base Command

`fortimanager-custom-service-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to delete the custom service. Leave empty to use the default integration ADOM. | Optional | 
| custom | The custome service to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-custom-service-delete custom=new_service```


#### Human Readable Output

>Deleted Custom Service new_service

### fortimanager-firewall-policy-package-list
***
List ADOM policy packages.


#### Base Command

`fortimanager-firewall-policy-package-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to fetch the firewall policy packages. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 
| policy_package | Name of a specific policy package to fetch. If not specified, will get all policy packages. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.PolicyPackage.name | String | Policy package name. | 
| FortiManager.PolicyPackage.obj_ver | Number | Policy package object version. | 
| FortiManager.PolicyPackage.oid | Number | Policy package OID. | 
| FortiManager.PolicyPackage.package setting.central-nat | String | Whether to use the central NAT. | 
| FortiManager.PolicyPackage.package setting.consolidated-firewall-mode | String | Whether to enable consolidate firewall mode. | 
| FortiManager.PolicyPackage.package setting.fwpolicy-implicit-log | String | Whether to enable firewall policy implicit log. | 
| FortiManager.PolicyPackage.package setting.fwpolicy6-implicit-log | String | Whether to enable firewall policy 6 implicit log. | 
| FortiManager.PolicyPackage.package setting.inspection-mode | String | Package inspection mode. | 
| FortiManager.PolicyPackage.package setting.ngfw-mode | String | Package NGFW mode. | 
| FortiManager.PolicyPackage.package setting.ssl-ssh-profile | String | Package SSL SSH profile. | 
| FortiManager.PolicyPackage.scope_member.name | String | Policy package scope member name. | 
| FortiManager.PolicyPackage.scope_member.vdom | String | Policy package scope member VDOM. | 
| FortiManager.PolicyPackage.subobj | Unknown | Policy package sub-objects. | 
| FortiManager.PolicyPackage.type | String | Policy package type. | 


#### Command Example
```!fortimanager-firewall-policy-package-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "PolicyPackage": [
            {
                "name": "default",
                "obj ver": 1,
                "oid": 1303,
                "package settings": {
                    "central-nat": 0,
                    "consolidated-firewall-mode": 0,
                    "fwpolicy-implicit-log": 0,
                    "fwpolicy6-implicit-log": 0,
                    "ngfw-mode": 0
                },
                "type": "pkg"
            },
            {
                "name": "my_package",
                "obj ver": 8,
                "oid": 1356,
                "package settings": {
                    "fwpolicy-implicit-log": 0,
                    "fwpolicy6-implicit-log": 0,
                    "ngfw-mode": 1,
                    "ssl-ssh-profile": [
                        "NGFW-SSL-Inspection"
                    ]
                },
                "type": "pkg"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policy Packages
>|Name|Type|
>|---|---|
>| FG5H0E3917901297_root | pkg |
>| Corp_Shared | pkg |


### fortimanager-firewall-policy-package-create
***
Create a new firewall policy package.


#### Base Command

`fortimanager-firewall-policy-package-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to create the service group. Leave empty to use the instance ADOM. | Optional | 
| name | The name of the new policy package. | Required | 
| type | The type of package. Possible values are: "pkg" and "folder". | Required | 
| central_nat | Whether to use central NAT. Default is "disable". | Optional | 
| consolidated_firewall_mode | Whether to enable consolidate firewall mode. Default is "disable". | Optional | 
| fwpolicy_implicit_log | Whether to enable firewall policy implicit log. Default is "disable". | Optional | 
| fwpolicy6_implicit_log | Whether to enable firewall policy 6 implicit log. Default is "disable". | Optional | 
| inspection_mode | Package inspection mode. Possible values are: "proxy" and "flow". Default is "proxy". | Optional | 
| ngfw_mode | Package NGFW mode. Possible values are: "profile-based" and "policy-based". Default is "profile-based". | Optional | 
| ssl_ssh_profile | Package SSL SSH profile. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-package-create name=new_package type=pkg```


#### Human Readable Output

>Created new Policy Package new_package

### fortimanager-firewall-policy-package-update
***
Create a new firewall policy package.


#### Base Command

`fortimanager-firewall-policy-package-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to update the service group. Leave empty to use the instance ADOM. | Optional | 
| name | The name of the Policy Package to update. | Required | 
| type | The type og package. Possible values are: "pkg" and "folder". | Optional | 
| central_nat | Whether to use central NAT. | Optional | 
| consolidated_firewall_mode | Whether to enable consolidate firewall mode. | Optional | 
| fwpolicy_implicit_log | Whether to enable firewall policy implicit log. | Optional | 
| fwpolicy6_implicit_log | Whether to enable firewall policy 6 implicit log. | Optional | 
| inspection_mode | Package inspection mode. Possible values are: "proxy" and "flow". | Optional | 
| ngfw_mode | Package NGFW mode. Possible values are: "profile-based" and "policy-based". | Optional | 
| ssl_ssh_profile | Package SSL SSH profile. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-package-update name=new_package central_nat=enable```

#### Human Readable Output

>Update Policy Package new_package

### fortimanager-firewall-policy-package-delete
***
Delete a firewall policy package.


#### Base Command

`fortimanager-firewall-policy-package-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to delete the policy package. Leave empty to use the default integration ADOM. | Optional | 
| pkg_path | The policy package path to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-package-delete pkg_path=new_package```

#### Human Readable Output

>Deleted Policy Package new_package

### fortimanager-firewall-policy-list
***
List specific firewall policies from a policy package.


#### Base Command

`fortimanager-firewall-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| package | The package from which to fetch the policies. | Required | 
| adom | The ADOM from which to fetch the policies. Leave empty to use the instance ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. | Optional | 
| policy_id | An ID for the specific policy to fetch. If not specified, will get all policies. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.PolicyPackage.Policy.action | String | Policy action \(allow/deny/ipsec\). | 
| FortiManager.PolicyPackage.Policy.app-category | String | Application category ID list. | 
| FortiManager.PolicyPackage.Policy.app-group | String | Application group names. | 
| FortiManager.PolicyPackage.Policy.application | Number | Application ID list. | 
| FortiManager.PolicyPackage.Policy.application-list | String | Name of an existing application list. | 
| FortiManager.PolicyPackage.Policy.auth-cert | String | HTTPS server certificate for policy authentication. | 
| FortiManager.PolicyPackage.Policy.auth-path | String | Enable/disable authentication-based routing. | 
| FortiManager.PolicyPackage.Policy.auth-redirect-addr | String | HTTP-to-HTTPS redirect address for firewall authentication. | 
| FortiManager.PolicyPackage.Policy.auto-asic-offload | String | Enable/disable offloading security profile processing to CP processors. | 
| FortiManager.PolicyPackage.Policy.av-profile | String | Name of an existing antivirus profile. | 
| FortiManager.PolicyPackage.Policy.block-notification | String | Enable/disable block notification. | 
| FortiManager.PolicyPackage.Policy.captive-portal-exempt | String | Enable to exempt some users from the captive portal. | 
| FortiManager.PolicyPackage.Policy.capture-packet | String | Enable/disable capture packets. | 
| FortiManager.PolicyPackage.Policy.comments | String | Comments. | 
| FortiManager.PolicyPackage.Policy.custom-log-fields | String | Custom fields to append to log messages for this policy. | 
| FortiManager.PolicyPackage.Policy.delay-tcp-npu-session | String | Enable TCP NPU session delay to guarantee packet order of 3-way handshake. | 
| FortiManager.PolicyPackage.Policy.devices | String | Names of devices or device groups that can be matched by the policy. | 
| FortiManager.PolicyPackage.Policy.diffserv-forward | String | Enable to change packet DiffServ values to the specified diffservcode-forward value. | 
| FortiManager.PolicyPackage.Policy.diffserv-reverse | String | Enable to change packet reverse \(reply\) DiffServ values to the specified diffservcode-rev value. | 
| FortiManager.PolicyPackage.Policy.diffservcode-forward | String | Change packet DiffServ to this value. | 
| FortiManager.PolicyPackage.Policy.diffservcode-rev | String | Change packet reverse \(reply\) DiffServ to this value. | 
| FortiManager.PolicyPackage.Policy.disclaimer | String | Enable/disable user authentication disclaimer. | 
| FortiManager.PolicyPackage.Policy.dlp-sensor | String | Name of an existing DLP sensor. | 
| FortiManager.PolicyPackage.Policy.dnsfilter-profile | String | Name of an existing DNS filter profile. | 
| FortiManager.PolicyPackage.Policy.dscp-match | String | Enable DSCP check. | 
| FortiManager.PolicyPackage.Policy.dscp-negate | String | Enable negated DSCP match. | 
| FortiManager.PolicyPackage.Policy.dscp-value | String | DSCP value. | 
| FortiManager.PolicyPackage.Policy.dsri | String | Enable DSRI to ignore HTTP server responses. | 
| FortiManager.PolicyPackage.Policy.dstaddr | String | Destination address and address group names. | 
| FortiManager.PolicyPackage.Policy.dstaddr-negate | String | When enabled, dstaddr specifies what the destination address must NOT be. | 
| FortiManager.PolicyPackage.Policy.dstintf | String | Outgoing \(egress\) interface. | 
| FortiManager.PolicyPackage.Policy.firewall-session-dirty | String | How to handle sessions if the configuration of this firewall policy changes. | 
| FortiManager.PolicyPackage.Policy.fixedport | String | Enable to prevent source NAT from changing a session source port. | 
| FortiManager.PolicyPackage.Policy.fsso | String | Enable/disable Fortinet single sign-on. | 
| FortiManager.PolicyPackage.Policy.fsso-agent-for-ntlm | String | FSSO agent to use for NTLM authentication. | 
| FortiManager.PolicyPackage.Policy.global-label | String | Label for the policy that appears when the GUI is in Global View mode. | 
| FortiManager.PolicyPackage.Policy.groups | String | Names of user groups that can authenticate with this policy. | 
| FortiManager.PolicyPackage.Policy.gtp-profile | String | GTP profile. | 
| FortiManager.PolicyPackage.Policy.icap-profile | String | Name of an existing ICAP profile. | 
| FortiManager.PolicyPackage.Policy.identity-based-route | String | Name of identity-based routing rule. | 
| FortiManager.PolicyPackage.Policy.inbound | String | Policy-based IPsec VPN. Only traffic from the remote network can initiate a VPN. | 
| FortiManager.PolicyPackage.Policy.internet-service | String | Enable/disable use of internet services for this policy. If enabled, destination address and service are not used. | 
| FortiManager.PolicyPackage.Policy.internet-service-custom | String | Custom internet service name. | 
| FortiManager.PolicyPackage.Policy.internet-service-id | String | Internet service ID. | 
| FortiManager.PolicyPackage.Policy.internet-service-negate | String | When enabled, internet service specifies what the service must NOT be. | 
| FortiManager.PolicyPackage.Policy.internet-service-src | String | Enable/disable use of internet services in source for this policy. If enabled, source address is not used. | 
| FortiManager.PolicyPackage.Policy.internet-service-src-custom | String | Custom internet service source name. | 
| FortiManager.PolicyPackage.Policy.internet-service-src-id | String | Internet service source ID. | 
| FortiManager.PolicyPackage.Policy.internet-service-src-negate | String | When enabled, internet-service-src specifies what the service must NOT be. | 
| FortiManager.PolicyPackage.Policy.ippool | String | Enable to use IP pools for source NAT. | 
| FortiManager.PolicyPackage.Policy.ips-sensor | String | Name of an existing IPS sensor. | 
| FortiManager.PolicyPackage.Policy.label | String | Label for the policy that appears when the GUI is in Section View mode. | 
| FortiManager.PolicyPackage.Policy.learning-mode | String | Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will be generated. | 
| FortiManager.PolicyPackage.Policy.logtraffic | String | Enable or disable logging. Log all sessions or security profile sessions. | 
| FortiManager.PolicyPackage.Policy.logtraffic-start | String | Record logs when a session starts and ends. | 
| FortiManager.PolicyPackage.Policy.match-vip | String | Enable to match packets that have had their destination addresses changed by a VIP. | 
| FortiManager.PolicyPackage.Policy.mms-profile | String | Name of an existing MMS profile. | 
| FortiManager.PolicyPackage.Policy.name | String | Policy name. | 
| FortiManager.PolicyPackage.Policy.nat | String | Enable/disable a source NAT. | 
| FortiManager.PolicyPackage.Policy.natinbound | String | Policy-based IPsec VPN: apply destination NAT to inbound traffic. | 
| FortiManager.PolicyPackage.Policy.natip | String | Policy-based IPsec VPN: source NAT IP address for outgoing traffic. | 
| FortiManager.PolicyPackage.Policy.natoutbound | String | Policy-based IPsec VPN: apply source NAT to outbound traffic. | 
| FortiManager.PolicyPackage.Policy.np-acceleration | String | Enable/disable UTM Network Processor acceleration. | 
| FortiManager.PolicyPackage.Policy.ntlm | String | Enable/disable NTLM authentication. | 
| FortiManager.PolicyPackage.Policy.ntlm-enabled-browsers | String | HTTP-User-Agent value of supported browsers. | 
| FortiManager.PolicyPackage.Policy.ntlm-guest | String | Enable/disable NTLM guest user access. | 
| FortiManager.PolicyPackage.Policy.outbound | String | Policy-based IPsec VPN: only traffic from the internal network can initiate a VPN. | 
| FortiManager.PolicyPackage.Policy.per-ip-shaper | String | Per-IP traffic shaper. | 
| FortiManager.PolicyPackage.Policy.permit-any-host | String | Accept UDP packets from any host. | 
| FortiManager.PolicyPackage.Policy.permit-stun-host | String | Accept UDP packets from any Session Traversal Utilities for NAT \(STUN\) host. | 
| FortiManager.PolicyPackage.Policy.policyid | Number | Policy ID. | 
| FortiManager.PolicyPackage.Policy.poolname | String | IP pool names. | 
| FortiManager.PolicyPackage.Policy.profile-group | String | Name of profile group. | 
| FortiManager.PolicyPackage.Policy.profile-protocol-options | String | Name of an existing protocol options profile. | 
| FortiManager.PolicyPackage.Policy.profile-type | String | Determine whether the firewall policy allows security profile groups or single profiles only. | 
| FortiManager.PolicyPackage.Policy.radius-mac-auth-bypass | String | Enable MAC authentication bypass. The bypassed MAC address must be received from RADIUS server. | 
| FortiManager.PolicyPackage.Policy.redirect-url | String | The URL users are directed to after seeing and accepting the disclaimer or authenticating. | 
| FortiManager.PolicyPackage.Policy.replacemsg-override-group | String | Override the default replacement message group for this policy. | 
| FortiManager.PolicyPackage.Policy.rsso | String | Enable/disable RADIUS single sign-on \(RSSO\). | 
| FortiManager.PolicyPackage.Policy.rtp-addr | String | Address names if this is an RTP NAT policy. | 
| FortiManager.PolicyPackage.Policy.rtp-nat | String | Enable Real Time Protocol \(RTP\) NAT. | 
| FortiManager.PolicyPackage.Policy.scan-botnet-connections | String | Block or monitor connections to Botnet servers or disable Botnet scanning. | 
| FortiManager.PolicyPackage.Policy.schedule | String | Schedule name. | 
| FortiManager.PolicyPackage.Policy.schedule-timeout | String | Enable to force current sessions to end when the schedule object times out. Disable allows them to end from inactivity. | 
| FortiManager.PolicyPackage.Policy.send-deny-packet | String | Enable to send a reply when a session is denied or blocked by a firewall policy. | 
| FortiManager.PolicyPackage.Policy.service | String | Service and service group names. | 
| FortiManager.PolicyPackage.Policy.service-negate | String | When enabled, service specifies what the service must NOT be. | 
| FortiManager.PolicyPackage.Policy.session-ttl | Number | TTL in seconds for sessions accepted by this policy. \(0 means use the system default session TTL.\) | 
| FortiManager.PolicyPackage.Policy.spamfilter-profile | String | Name of an existing spam filter profile. | 
| FortiManager.PolicyPackage.Policy.srcaddr | String | Source address and address group names. | 
| FortiManager.PolicyPackage.Policy.srcaddr-negate | String | When enabled, srcaddr specifies what the source address must NOT be. | 
| FortiManager.PolicyPackage.Policy.srcintf | String | Incoming \(ingress\) interface. | 
| FortiManager.PolicyPackage.Policy.ssh-filter-profile | String | Name of an existing SSH filter profile. | 
| FortiManager.PolicyPackage.Policy.ssl-mirror | String | Enable to copy decrypted SSL traffic to a FortiGate interface \(called SSL mirroring\). | 
| FortiManager.PolicyPackage.Policy.ssl-mirror-intf | String | SSL mirror interface name. | 
| FortiManager.PolicyPackage.Policy.ssl-ssh-profile | String | Name of an existing SSL SSH profile. | 
| FortiManager.PolicyPackage.Policy.status | String | Enable or disable this policy. | 
| FortiManager.PolicyPackage.Policy.tcp-mss-receiver | Number | Receiver TCP maximum segment size \(MSS\). | 
| FortiManager.PolicyPackage.Policy.tcp-mss-sender | Number | Sender TCP maximum segment size \(MSS\). | 
| FortiManager.PolicyPackage.Policy.tcp-session-without-syn | String | Enable/disable creation of TCP session without SYN flag. | 
| FortiManager.PolicyPackage.Policy.timeout-send-rst | String | Enable/disable sending RST packets when TCP sessions expire. | 
| FortiManager.PolicyPackage.Policy.traffic-shaper | String | Traffic shaper. | 
| FortiManager.PolicyPackage.Policy.traffic-shaper-reverse | String | Reverse traffic shaper. | 
| FortiManager.PolicyPackage.Policy.url-category | String | URL category ID list. | 
| FortiManager.PolicyPackage.Policy.users | String | Names of individual users that can authenticate with this policy. | 
| FortiManager.PolicyPackage.Policy.utm-status | String | Enable to add one or more security profiles \(AV, IPS, etc.\) to the firewall policy. | 
| FortiManager.PolicyPackage.Policy.uuid | String | Universally Unique Identifier \(UUID; automatically assigned but can be manually reset\). | 
| FortiManager.PolicyPackage.Policy.vlan-cos-fwd | Number | VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest. | 
| FortiManager.PolicyPackage.Policy.vlan-cos-rev | Number | VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest. | 
| FortiManager.PolicyPackage.Policy.vlan-filter | String | Set VLAN filters. | 
| FortiManager.PolicyPackage.Policy.voip-profile | String | Name of an existing VoIP profile. | 
| FortiManager.PolicyPackage.Policy.vpn_dst_node.host | String | VPN destination node host. | 
| FortiManager.PolicyPackage.Policy.vpn_dst_node.seq | Number | VPN destination node sequence. | 
| FortiManager.PolicyPackage.Policy.vpn_dst_node.subnet | String | VPN destination node subnet. | 
| FortiManager.PolicyPackage.Policy.vpn_src_node.host | String | VPN source node host. | 
| FortiManager.PolicyPackage.Policy.vpn_src_node.seq | Number | VPN source node sequence. | 
| FortiManager.PolicyPackage.Policy.vpn_src_node.subnet | String | VPN source node subnet. | 
| FortiManager.PolicyPackage.Policy.vpntunnel | String | Policy-based IPsec VPN: name of the IPsec VPN Phase 1. | 
| FortiManager.PolicyPackage.Policy.waf-profile | String | Name of an existing Web application firewall profile. | 
| FortiManager.PolicyPackage.Policy.wanopt | String | Enable/disable WAN optimization. | 
| FortiManager.PolicyPackage.Policy.wanopt-detection | String | WAN optimization auto-detection mode. | 
| FortiManager.PolicyPackage.Policy.wanopt-passive-opt | String | WAN optimization passive mode options. This option decides what IP address will be used to connect server. | 
| FortiManager.PolicyPackage.Policy.wanopt-peer | String | WAN optimization peer. | 
| FortiManager.PolicyPackage.Policy.wanopt-profile | String | WAN optimization profile. | 
| FortiManager.PolicyPackage.Policy.wccp | String | Enable/disable forwarding traffic matching this policy to a configured WCCP server. | 
| FortiManager.PolicyPackage.Policy.webcache | String | Enable/disable a web cache. | 
| FortiManager.PolicyPackage.Policy.webcache-https | String | Enable/disable a web cache for HTTPS. | 
| FortiManager.PolicyPackage.Policy.webfilter-profile | String | Name of an existing Web filter profile. | 
| FortiManager.PolicyPackage.Policy.wsso | String | Enable/disable WiFi single sign-on \(WSSO\). | 


#### Command Example
```!fortimanager-firewall-policy-list package=new_package```

#### Context Example
```json
{
    "FortiManager": {
        "PolicyPackage": {
            "Policy": {
                "_byte": 0,
                "_first_hit": 0,
                "_first_session": 0,
                "_global-vpn": [],
                "_global-vpn-tgt": 0,
                "_hitcount": 0,
                "_last_hit": 0,
                "_last_session": 0,
                "_pkts": 0,
                "_policy_block": 0,
                "_sesscount": 0,
                "action": 1,
                "anti-replay": 1,
                "app-group": [],
                "auto-asic-offload": 1,
                "block-notification": 0,
                "captive-portal-exempt": 0,
                "capture-packet": 0,
                "custom-log-fields": [],
                "delay-tcp-npu-session": 0,
                "diffserv-forward": 0,
                "diffserv-reverse": 0,
                "disclaimer": 0,
                "dsri": 0,
                "dstaddr": [
                    "all"
                ],
                "dstaddr-negate": 0,
                "dstintf": [
                    "any"
                ],
                "email-collect": 0,
                "fsso": 1,
                "fsso-agent-for-ntlm": [],
                "fsso-groups": [],
                "geoip-anycast": 0,
                "groups": [],
                "inspection-mode": 1,
                "internet-service": 0,
                "internet-service-src": 0,
                "logtraffic": 3,
                "logtraffic-start": 0,
                "match-vip": 0,
                "match-vip-only": 0,
                "name": "new_policy",
                "nat": 0,
                "natip": [
                    "0.0.0.0",
                    "0.0.0.0"
                ],
                "np-acceleration": 1,
                "obj seq": 1,
                "per-ip-shaper": [],
                "permit-any-host": 0,
                "policyid": 9,
                "profile-protocol-options": [
                    "default"
                ],
                "profile-type": 0,
                "radius-mac-auth-bypass": 0,
                "replacemsg-override-group": [],
                "reputation-direction": 2,
                "reputation-minimum": 0,
                "rtp-nat": 0,
                "schedule": [
                    "always"
                ],
                "schedule-timeout": 0,
                "service": [
                    "ALL"
                ],
                "service-negate": 0,
                "session-ttl": 0,
                "srcaddr": [
                    "all"
                ],
                "srcaddr-negate": 0,
                "srcintf": [
                    "any"
                ],
                "ssl-mirror": 0,
                "ssl-mirror-intf": [],
                "ssl-ssh-profile": [
                    "no-inspection"
                ],
                "status": 1,
                "tcp-mss-receiver": 0,
                "tcp-mss-sender": 0,
                "tcp-session-without-syn": 2,
                "timeout-send-rst": 0,
                "tos": "0x00",
                "tos-mask": "0x00",
                "tos-negate": 0,
                "traffic-shaper": [],
                "traffic-shaper-reverse": [],
                "users": [],
                "utm-status": 0,
                "uuid": "some-id",
                "vlan-cos-fwd": 255,
                "vlan-cos-rev": 255,
                "vpn_dst_node": null,
                "vpn_src_node": null,
                "wccp": 0,
                "webcache-https": 0,
                "webproxy-forward-server": [],
                "webproxy-profile": []
            }
        }
    }
}
```

#### Human Readable Output

>### ADOM root Policy Package new_package Policies
>|Policyid|Name|Srcintf|Dstintf|Srcaddr|Dstaddr|Schedule|Service|Action|
>|---|---|---|---|---|---|---|---|---|
>| 9 | new_policy | any | any | all | all | always | ALL | 1 |


### fortimanager-firewall-policy-create
***
Create a firewall policy.


#### Base Command

`fortimanager-firewall-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to create the service group. Leave empty to use the instance ADOM. | Optional | 
| package | The package from which to create the policy. | Required | 
| action | The policy action. Possible values are: "deny", "accept", "ipsec", and "ssl-vpn". | Required | 
| comments | A comment. | Optional | 
| dstaddr | Destination address name. Note: dstaddr6 or dstaddr must be set. | Optional | 
| dstaddr6 | IPv6 destination address (web proxy only). Note: dstaddr6 or dstaddr must be set. | Optional | 
| dstaddr_negate | Enable/disable a negated destination address match. | Optional | 
| dstintf | Destination interface name. | Optional | 
| srcaddr | Source address name. Note: srcaddr or srcaddr6 must be set. | Optional | 
| srcaddr6 | IPv6 source address (web proxy only). Note: srcaddr or srcaddr6 must be set. | Optional | 
| srcaddr_negate | Enable/disable a negated source address match. | Optional | 
| srcintf | Source interface name. | Optional | 
| additional_params | A comma-separated list of additional params and their values. For example: Field1=Value1,Field2=Value2. | Optional | 
| name | The name of the policy to create. | Required | 
| logtraffic | Enable or disable logging. Log all sessions or security profile sessions. Possible values are: "enable", "disable", "all", and "utm". | Required | 
| schedule | Schedule name. Default is "always". | Required | 
| service | Service and service group names. Default is "ALL". | Required | 
| status | Enable or disable this policy. | Required | 
| policyid | The ID of the policy to create. Leave empty to use system default. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-create action=accept logtraffic=utm name=new_policy package=new_package dstaddr=all srcaddr=all policyid=9```


#### Human Readable Output

>Created policy with ID 9

### fortimanager-firewall-policy-update
***
Update a firewall policy.


#### Base Command

`fortimanager-firewall-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM on which to update the service group. Leave empty to use the instance ADOM. | Optional | 
| package | The package from which to update the policy. | Required | 
| action | The policy action. Possible values are: "deny", "accept", "ipsec", and "ssl-vpn". | Optional | 
| comments | A comment. | Optional | 
| dstaddr | Destination address name. Note: dstaddr6 or dstaddr must be set. | Optional | 
| dstaddr6 | IPv6 destination address (web proxy only). Note: dstaddr6 or dstaddr must be set. | Optional | 
| dstaddr_negate | Enable/disable a negated destination address match. | Optional | 
| dstintf | Destination interface name. | Optional | 
| srcaddr | Source address name. Note: srcaddr or srcaddr6 must be set. | Optional | 
| srcaddr6 | IPv6 source address (web proxy only). Note: srcaddr or srcaddr6 must be set. | Optional | 
| srcaddr_negate | Enable/disable a negated source address match. | Optional | 
| srcintf | Source interface name. | Optional | 
| additional_params | A comma-separated list of additional params and their values. exmaple: Field1=Value1,Field2=Value2. | Optional | 
| name | The name of the policy to update. | Optional | 
| logtraffic | Enable or disable logging. Log all sessions or security profile sessions. Possible values are: "enable", "disable", "all", and "utm". | Optional | 
| schedule | Schedule name. | Optional | 
| service | Service and service group names. | Optional | 
| status | Enable or disable this policy. | Optional | 
| policyid | The ID of the policy to update. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-update package=new_package policyid=9 status=disable```


#### Human Readable Output

>Updated policy with ID 9

### fortimanager-firewall-policy-delete
***
Delete a firewall policy.


#### Base Command

`fortimanager-firewall-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to delete the policy. Leave empty to use the default integration ADOM. | Optional | 
| package | The policy package from which we want to delete the policy. | Required | 
| policy | The policy we want to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-delete package=new_package policy=9```


#### Human Readable Output

>Deleted Policy 9

### fortimanager-firewall-policy-move
***
Move a policy in the package.


#### Base Command

`fortimanager-firewall-policy-move`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to move the policy. Leave empty to use the default integration ADOM. | Optional | 
| package | The policy package from which we want to move the policy. | Required | 
| policy | The ID of the policy we want to move. | Required | 
| target | The ID of the target policy by which we want to move the policy. | Required | 
| option | Whether to move the policy before or after the target policy. Possible values are: "before" and "after". Default is "before". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortimanager-firewall-policy-move option=after package=some_package policy=1 target=2```


#### Human Readable Output

>Moved policy with ID 1 after 2 in Policy Package: some_package

### fortimanager-dynamic-interface-list
***
List dynamic interfaces


#### Base Command

`fortimanager-dynamic-interface-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom | The ADOM from which to list dynamic interfaces. Leave empty to use the default integration ADOM. | Optional | 
| offset | From which index to start the list. Default is 0. | Optional | 
| limit | To which index to get the list. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.DynamicInterface.color | Number | Color of the icon in the GUI. | 
| FortiManager.DynamicInterface.default-mapping | String | Default mapping of the Interface. | 
| FortiManager.DynamicInterface.defmap-intf | String | Default mapping interface. | 
| FortiManager.DynamicInterface.defmap-intrazone-deny | String | Default mapping intrazone deny. | 
| FortiManager.DynamicInterface.defmap-zonemember | String | Default mapping zone members | 
| FortiManager.DynamicInterface.description | String | Dynamic interface description. | 
| FortiManager.DynamicInterface.dynamic_mapping._scope.name | String | Dynamic mapping scope name. | 
| FortiManager.DynamicInterface.dynamic_mapping._scope.vdom | String | Dynamic mapping scope VDOM. | 
| FortiManager.DynamicInterface.dynamic_mapping.egress-shaping-profile | String | Dynamic mapping egress shaping profile. | 
| FortiManager.DynamicInterface.dynamic_mapping.intrazone-deny | String | Dynamic mapping intrazone deny. | 
| FortiManager.DynamicInterface.dynamic_mapping.local-intf | String | Dynamic mapping local interface. | 
| FortiManager.DynamicInterface.egress-shaping-profile | String | Egress shaping profile. | 
| FortiManager.DynamicInterface.name | String | Dynamic interface name. | 
| FortiManager.DynamicInterface.platform_mapping.egress-shaping-profile | String | Platform mapping egress shaping profile. | 
| FortiManager.DynamicInterface.platform_mapping.intf-zone | String | Platform mapping interface zone. | 
| FortiManager.DynamicInterface.platform_mapping.intrazone-deny | String | Platform mapping intrazone deny. | 
| FortiManager.DynamicInterface.platform_mapping.name | String | Platform mapping name. | 
| FortiManager.DynamicInterface.single-intf | String | Dynamic interface single interface. | 


#### Command Example
```!fortimanager-dynamic-interface-list offset=1 limit=2```

#### Context Example
```json
{
    "FortiManager": {
        "DynamicInterface": [
            {
                "color": 0,
                "default-mapping": 0,
                "defmap-intrazone-deny": 0,
                "defmap-zonemember": [],
                "dynamic_mapping": [
                    {
                        "_scope": [
                            {
                                "name": "device_name",
                                "vdom": "root"
                            }
                        ],
                        "egress-shaping-profile": [],
                        "ingress-shaping-profile": [],
                        "intrazone-deny": 0,
                        "local-intf": [
                            "bgp loopback"
                        ]
                    }
                ],
                "egress-shaping-profile": [],
                "ingress-shaping-profile": [],
                "name": "bgp loopback",
                "single-intf": 1
            },
            {
                "color": 0,
                "default-mapping": 0,
                "defmap-intrazone-deny": 0,
                "defmap-zonemember": [],
                "dynamic_mapping": [
                    {
                        "_scope": [
                            {
                                "name": "device_name",
                                "vdom": "root"
                            }
                        ],
                        "egress-shaping-profile": [],
                        "ingress-shaping-profile": [],
                        "intrazone-deny": 0,
                        "local-intf": [
                            "branch"
                        ]
                    }
                ],
                "egress-shaping-profile": [],
                "ingress-shaping-profile": [],
                "name": "branch",
                "single-intf": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### ADOM root Dynamic Interfaces
>|Name|
>|---|
>| bgp loopback |
>| branch |


### fortimanager-firewall-policy-package-install
***
Schedule a policy package installation.


#### Base Command

`fortimanager-firewall-policy-package-install`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| adom_rev_comment | The comment for the new ADOM revision. | Optional | 
| adom_rev_name | The name for the new ADOM revision. | Optional | 
| adom | The ADOM in which to install the policy package. Leave empty to use the default integration ADOM. | Optional | 
| dev_rev_comment | The comment for the device configuration revision that will be generated during install. | Optional | 
| package | The policy package to install. | Required | 
| name | The device or device group name on which to install the package. | Required | 
| vdom | vdom on which to install the package. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.Installation.id | Number | The installation task ID. | 


#### Command Example
```!fortimanager-policy-package-install package=package_to_install name=device_name vdom=root adom_rev_name=testing_installation ```

#### Human Readable Output
>Installed a policy package my_package in ADOM: root 
>On Device my_device and VDOM vdom_name.
>Task ID: 175

#### Context Example
```json
{
    "FortiManager": {
        "Installation": {
            "id": 175
        }   
    }
}
```


### fortimanager-firewall-policy-package-install-status
***
Get installation status.


#### Base Command

`fortimanager-firewall-policy-package-install-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The installation task ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiManager.Installation.adom | Number | The ADOM on which the installation occurred. | 
| FortiManager.Installation.end_tm | Number | The installation task end time. | 
| FortiManager.Installation.flags | Number | The installation_task_flags. | 
| FortiManager.Installation.id | Number | The installation task ID. | 
| FortiManager.Installation.line.detail | String | The installation status details. | 
| FortiManager.Installation.line.end_tm | Number | The installation task end time. | 
| FortiManager.Installation.line.err | Number | The installation error. | 
| FortiManager.Installation.line.history | String | Installation task historical details. | 
| FortiManager.Installation.line.ip | String | The installation IP. | 
| FortiManager.Installation.line.name | String | The installation name. | 
| FortiManager.Installation.line.oid | Number | The installation task oid. | 
| FortiManager.Installation.line.percent | Number | The installation task completion percent. | 
| FortiManager.Installation.line.start_tm | Number | The installation task start time. | 
| FortiManager.Installation.line.state | String | The installation task state. | 
| FortiManager.Installation.line.vdom | String | The VDOM on which the installation occurred. | 
| FortiManager.Installation.num_done | Number | The number of done tasks. | 
| FortiManager.Installation.num_err | Number | The number of errors found. | 
| FortiManager.Installation.num_lines | Number | The number of installation data lines. | 
| FortiManager.Installation.num_warn | Number | The number of warnings found. | 
| FortiManager.Installation.percent | Number | The installation task completion percent. | 
| FortiManager.Installation.pid | Number | The installation task PID. | 
| FortiManager.Installation.src | String | The installation task source | 
| FortiManager.Installation.start_tm | Number | The installation task start time. | 
| FortiManager.Installation.state | String | The installation task state. | 
| FortiManager.Installation.title | String | The installation task title. | 
| FortiManager.Installation.tot_percent | Number | The installation task completion percent. | 
| FortiManager.Installation.user | String | The installation task user. | 


#### Command Example
```!fortimanager-policy-package-install-status task_id=175 ```

