This integration enables the management of Hetzner Cloud environments using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands.

# Authorize Cortex XSOAR for Ansible Hetzner Cloud

To use this integration you must generate an API token for your HCloud project.

1. Navigate to the [HCloud Console](https://console.hetzner.cloud/projects)
2. Select the project you wish to manage with XSOAR
3. Navigate to **Security** > **API Tokens** and generate an API token with Read & Write
4. Provide this token when you add a configure a Instance of this integration in XSOAR.

**NOTE**: If using 6.0.2 or lower version, put your API Token in the **Password** field, leave the **Username** field empty.

## Configure Ansible HCloud in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Token | This is the API Token for the Hetzner Cloud. | True |
| Endpoint | This is the API Endpoint for the Hetzner Cloud. | True |



# Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

# State Arguement
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
### hcloud-datacenter-info
***
Gather info about the Hetzner Cloud datacenters.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_datacenter_info_module.html


#### Base Command

`hcloud-datacenter-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the datacenter you want to get. | Optional | 
| name | The name of the datacenter you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudDatacenterInfo.hcloud_datacenter_info | unknown | The datacenter info as list
This module was called \`hcloud_datacenter_facts\` before Ansible 2.9, returning \`ansible_facts\` and \`hcloud_datacenter_facts\`. Note that the \`hcloud_datacenter_info\` module no longer returns \`ansible_facts\` and the value was renamed to \`hcloud_datacenter_info\`\! | 


#### Command Example
```!hcloud-datacenter-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudDatacenterInfo": [
            [
                {
                    "description": "Nuremberg 1 DC 3",
                    "id": "2",
                    "location": "nbg1",
                    "name": "nbg1-dc3"
                },
                {
                    "description": "Helsinki 1 DC 2",
                    "id": "3",
                    "location": "hel1",
                    "name": "hel1-dc2"
                },
                {
                    "description": "Falkenstein 1 DC14",
                    "id": "4",
                    "location": "fsn1",
                    "name": "fsn1-dc14"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># Nbg1-Dc3
>  * description: Nuremberg 1 DC 3
>  * id: 2
>  * location: nbg1
>  * name: nbg1-dc3
># Hel1-Dc2
>  * description: Helsinki 1 DC 2
>  * id: 3
>  * location: hel1
>  * name: hel1-dc2
># Fsn1-Dc14
>  * description: Falkenstein 1 DC14
>  * id: 4
>  * location: fsn1
>  * name: fsn1-dc14


### hcloud-floating-ip-info
***
Gather infos about the Hetzner Cloud Floating IPs.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_floating_ip_info_module.html


#### Base Command

`hcloud-floating-ip-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the Floating IP you want to get. | Optional | 
| label_selector | The label selector for the Floating IP you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudFloatingIpInfo.hcloud_floating_ip_info | unknown | The Floating ip infos as list | 


#### Command Example
```!hcloud-floating-ip-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudFloatingIpInfo": [
            []
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 


### hcloud-image-info
***
Gather infos about your Hetzner Cloud images.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_image_info_module.html


#### Base Command

`hcloud-image-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the image you want to get. | Optional | 
| name | The name of the image you want to get. | Optional | 
| label_selector | The label selector for the images you want to get. | Optional | 
| type | The label selector for the images you want to get. Possible values are: system, snapshot, backup. Default is system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudImageInfo.hcloud_image_info | unknown | The image infos as list | 


#### Command Example
```!hcloud-image-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudImageInfo": [
            [
                {
                    "description": "Debian 9",
                    "id": "2",
                    "labels": {},
                    "name": "debian-9",
                    "os_flavor": "debian",
                    "os_version": "9",
                    "status": "available",
                    "type": "system"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># Debian-9
>  * description: Debian 9
>  * id: 2
>  * name: debian-9
>  * os_flavor: debian
>  * os_version: 9
>  * status: available
>  * type: system
>  * ## Labels


### hcloud-location-info
***
Gather infos about your Hetzner Cloud locations.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_location_info_module.html


#### Base Command

`hcloud-location-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the location you want to get. | Optional | 
| name | The name of the location you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudLocationInfo.hcloud_location_info | unknown | The location infos as list | 


#### Command Example
```!hcloud-location-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudLocationInfo": [
            [
                {
                    "city": "Falkenstein",
                    "country": "DE",
                    "description": "Falkenstein DC Park 1",
                    "id": "1",
                    "name": "fsn1"
                },
                {
                    "city": "Nuremberg",
                    "country": "DE",
                    "description": "Nuremberg DC Park 1",
                    "id": "2",
                    "name": "nbg1"
                },
                {
                    "city": "Helsinki",
                    "country": "FI",
                    "description": "Helsinki DC Park 1",
                    "id": "3",
                    "name": "hel1"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># Fsn1
>  * city: Falkenstein
>  * country: DE
>  * description: Falkenstein DC Park 1
>  * id: 1
>  * name: fsn1
># Nbg1
>  * city: Nuremberg
>  * country: DE
>  * description: Nuremberg DC Park 1
>  * id: 2
>  * name: nbg1
># Hel1
>  * city: Helsinki
>  * country: FI
>  * description: Helsinki DC Park 1
>  * id: 3
>  * name: hel1


### hcloud-network
***
Create and manage cloud Networks on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_network_module.html


#### Base Command

`hcloud-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the Hetzner Cloud Networks to manage.<br/>Only required if no Network `name` is given. | Optional | 
| name | The Name of the Hetzner Cloud Network to manage.<br/>Only required if no Network `id` is given or a Network does not exists. | Optional | 
| ip_range | IP range of the Network.<br/>Required if Network does not exists. | Optional | 
| labels | User-defined labels (key-value pairs). | Optional | 
| state | State of the Network. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudNetwork.hcloud_network | unknown | The Network | 


#### Command Example
```!hcloud-network name="my-network" ip_range="10.0.0.0/8" state="present" ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudNetwork": [
            {
                "delete_protection": false,
                "id": "1156447",
                "ip_range": "10.0.0.0/8",
                "labels": {},
                "name": "my-network",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * delete_protection: False
>  * id: 1156447
>  * ip_range: 10.0.0.0/8
>  * name: my-network
>  * ## Labels


### hcloud-network-info
***
Gather info about your Hetzner Cloud networks.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_network_info_module.html


#### Base Command

`hcloud-network-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the network you want to get. | Optional | 
| name | The name of the network you want to get. | Optional | 
| label_selector | The label selector for the network you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudNetworkInfo.hcloud_network_info | unknown | The network info as list | 


#### Command Example
```!hcloud-network-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudNetworkInfo": [
            [
                {
                    "delete_protection": false,
                    "id": "1156447",
                    "ip_range": "10.0.0.0/8",
                    "labels": {},
                    "name": "my-network",
                    "routes": [],
                    "servers": [],
                    "subnetworks": []
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># My-Network
>  * delete_protection: False
>  * id: 1156447
>  * ip_range: 10.0.0.0/8
>  * name: my-network
>  * ## Labels
>  * ## Routes
>  * ## Servers
>  * ## Subnetworks


### hcloud-rdns
***
Create and manage reverse DNS entries on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_rdns_module.html


#### Base Command

`hcloud-rdns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server | The name of the Hetzner Cloud server you want to add the reverse DNS entry to. | Required | 
| ip_address | The IP address that should point to `dns_ptr`. | Required | 
| dns_ptr | The DNS address the `ip_address` should resolve to.<br/>Omit the param to reset the reverse DNS entry to the default value. | Optional | 
| state | State of the reverse DNS entry. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudRdns.hcloud_rdns | unknown | The reverse DNS entry | 


#### Command Example
```!hcloud-rdns server="my-server" ip_address="1.1.1.1" dns_ptr="example.com" state="present"```

#### Context Example
```json
{
    "HCloud": {
        "HcloudRdns": [
            {
                "dns_ptr": "example.com",
                "floating_ip": null,
                "ip_address": "1.1.1.1",
                "server": "my-server",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * dns_ptr: example.com
>  * floating_ip: None
>  * ip_address: 1.1.1.1
>  * server: my-server

### hcloud-route
***
Create and delete cloud routes on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_route_module.html


#### Base Command

`hcloud-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network | The name of the Hetzner Cloud Network. | Required | 
| destination | Destination network or host of this route. | Required | 
| gateway | Gateway for the route. | Required | 
| state | State of the route. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudRoute.hcloud_route | unknown | One Route of a Network | 


#### Command Example
```!hcloud-route network="my-network" destination="1.1.1.1/24" gateway="1.1.1.1" state="present" ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudRoute": [
            {
                "destination": "1.1.1.1/24",
                "gateway": "1.1.1.1",
                "network": "my-network",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * destination: 1.1.1.1/24
>  * gateway: 1.1.1.1
>  * network: my-network


### hcloud-server
***
Create and manage cloud servers on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_server_module.html


#### Base Command

`hcloud-server`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the Hetzner Cloud server to manage.<br/>Only required if no server `name` is given. | Optional | 
| name | The Name of the Hetzner Cloud server to manage.<br/>Only required if no server `id` is given or a server does not exists. | Optional | 
| server_type | The Server Type of the Hetzner Cloud server to manage.<br/>Required if server does not exists. | Optional | 
| ssh_keys | List of SSH key names<br/>The key names correspond to the SSH keys configured for your Hetzner Cloud account access. | Optional | 
| volumes | List of Volumes IDs that should be attached to the server on server creation. | Optional | 
| image | Image the server should be created from.<br/>Required if server does not exists. | Optional | 
| location | Location of Server.<br/>Required if no `datacenter` is given and server does not exists. | Optional | 
| datacenter | Datacenter of Server.<br/>Required of no `location` is given and server does not exists. | Optional | 
| backups | Enable or disable Backups for the given Server. Possible values are: Yes, No. Default is No. | Optional | 
| upgrade_disk | Resize the disk size, when resizing a server.<br/>If you want to downgrade the server later, this value should be False. Possible values are: Yes, No. Default is No. | Optional | 
| force_upgrade | Force the upgrade of the server.<br/>Power off the server if it is running on upgrade. Possible values are: Yes, No. Default is No. | Optional | 
| user_data | User Data to be passed to the server on creation.<br/>Only used if server does not exists. | Optional | 
| rescue_mode | Add the Hetzner rescue system type you want the server to be booted into. | Optional | 
| labels | User-defined labels (key-value pairs). | Optional | 
| state | State of the server. Possible values are: absent, present, restarted, started, stopped, rebuild. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudServer.hcloud_server | unknown | The server instance | 


#### Command Example
```!hcloud-server name="my-server" server_type="cx11" image="ubuntu-18.04" state="present" ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudServer": [
            {
                "backup_window": "None",
                "datacenter": "hel1-dc2",
                "delete_protection": false,
                "id": "12829887",
                "image": "ubuntu-18.04",
                "ipv4_address": "1.1.1.1",
                "ipv6": "11:11:11:11:11:11:11:12/64",
                "labels": {},
                "location": "hel1",
                "name": "my-server",
                "rebuild_protection": false,
                "rescue_enabled": false,
                "server_type": "cx11",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * backup_window: None
>  * datacenter: hel1-dc2
>  * delete_protection: False
>  * id: 12829887
>  * image: ubuntu-18.04
>  * ipv4_address: 1.1.1.1
>  * ipv6: 11:11:11:11:11:11:11:12/64
>  * location: hel1
>  * name: my-server
>  * rebuild_protection: False
>  * rescue_enabled: False
>  * server_type: cx11
>  * status: running
>  * ## Labels


### hcloud-server-info
***
Gather infos about your Hetzner Cloud servers.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_server_info_module.html


#### Base Command

`hcloud-server-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the server you want to get. | Optional | 
| name | The name of the server you want to get. | Optional | 
| label_selector | The label selector for the server you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudServerInfo.hcloud_server_info | unknown | The server infos as list | 


#### Command Example
```!hcloud-server-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudServerInfo": [
            [
                {
                    "backup_window": "None",
                    "datacenter": "hel1-dc2",
                    "delete_protection": false,
                    "id": "12829887",
                    "image": "ubuntu-18.04",
                    "ipv4_address": "1.1.1.1",
                    "ipv6": "11:11:11:11:11:11:11:12/64",
                    "labels": {},
                    "location": "hel1",
                    "name": "my-server",
                    "rebuild_protection": false,
                    "rescue_enabled": false,
                    "server_type": "cx11",
                    "status": "running"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># My-Server
>  * backup_window: None
>  * datacenter: hel1-dc2
>  * delete_protection: False
>  * id: 12829887
>  * image: ubuntu-18.04
>  * ipv4_address: 1.1.1.1
>  * ipv6: 11:11:11:11:11:11:11:12/64
>  * location: hel1
>  * name: my-server
>  * rebuild_protection: False
>  * rescue_enabled: False
>  * server_type: cx11
>  * status: running
>  * ## Labels


### hcloud-server-network
***
Manage the relationship between Hetzner Cloud Networks and servers
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_server_network_module.html


#### Base Command

`hcloud-server-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network | The name of the Hetzner Cloud Networks. | Required | 
| server | The name of the Hetzner Cloud server. | Required | 
| ip | The IP the server should have. | Optional | 
| alias_ips | Alias IPs the server has. | Optional | 
| state | State of the server_network. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudServerNetwork.hcloud_server_network | unknown | The relationship between a server and a network | 


#### Command Example
```!hcloud-server-network network="my-network" server="my-server" state="present"```

#### Context Example
```json
{
    "HCloud": {
        "HcloudServerNetwork": [
            {
                "alias_ips": [],
                "ip": "10.0.0.2",
                "network": "my-network",
                "server": "my-server",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * ip: 10.0.0.2
>  * network: my-network
>  * server: my-server
>  * ## Alias_Ips

### hcloud-server-type-info
***
Gather infos about the Hetzner Cloud server types.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_server_type_info_module.html


#### Base Command

`hcloud-server-type-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the server type you want to get. | Optional | 
| name | The name of the server type you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudServerTypeInfo.hcloud_server_type_info | unknown | The server type infos as list | 


#### Command Example
```!hcloud-server-type-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudServerTypeInfo": [
            [
                {
                    "cores": 1,
                    "cpu_type": "shared",
                    "description": "CX11",
                    "disk": 20,
                    "id": "1",
                    "memory": 2,
                    "name": "cx11",
                    "storage_type": "local"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># Cx11
>  * cores: 1
>  * cpu_type: shared
>  * description: CX11
>  * disk: 20
>  * id: 1
>  * memory: 2.0
>  * name: cx11
>  * storage_type: local


### hcloud-ssh-key
***
Create and manage ssh keys on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_ssh_key_module.html


#### Base Command

`hcloud-ssh-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the Hetzner Cloud ssh_key to manage.<br/>Only required if no ssh_key `name` is given. | Optional | 
| name | The Name of the Hetzner Cloud ssh_key to manage.<br/>Only required if no ssh_key `id` is given or a ssh_key does not exists. | Optional | 
| fingerprint | The Fingerprint of the Hetzner Cloud ssh_key to manage.<br/>Only required if no ssh_key `id` or `name` is given. | Optional | 
| labels | User-defined labels (key-value pairs). | Optional | 
| public_key | The Public Key to add.<br/>Required if ssh_key does not exists. | Optional | 
| state | State of the ssh_key. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudSshKey.hcloud_ssh_key | unknown | The ssh_key instance | 


#### Command Example
```!hcloud-ssh-key name="my-ssh_key" public_key="ssh-rsa XXXXX" state="present" ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudSshKey": [
            {
                "fingerprint": "11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:11",
                "id": "3964657",
                "labels": {},
                "name": "my-ssh_key",
                "public_key": "ssh-rsa XXXXX",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * fingerprint: 11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:11
>  * id: 3964657
>  * name: my-ssh_key
>  * public_key: ssh-rsa XXXXX
>  * ## Labels


### hcloud-ssh-key-info
***
Gather infos about your Hetzner Cloud ssh_keys.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_ssh_key_info_module.html


#### Base Command

`hcloud-ssh-key-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the ssh key you want to get. | Optional | 
| name | The name of the ssh key you want to get. | Optional | 
| fingerprint | The fingerprint of the ssh key you want to get. | Optional | 
| label_selector | The label selector for the ssh key you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudSshKeyInfo.hcloud_ssh_key_info | unknown | The ssh key instances | 


#### Command Example
```!hcloud-ssh-key-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudSshKeyInfo": [
            [
                {
                    "fingerprint": "11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:11",
                    "id": "3964657",
                    "labels": {},
                    "name": "my-ssh_key",
                    "public_key": "ssh-rsa XXXXX"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># My-Ssh_Key
>  * fingerprint: 11:11:11:11:11:11:11:12:11:11:11:11:11:11:11:11
>  * id: 3964657
>  * name: my-ssh_key
>  * public_key: ssh-rsa XXXXX
>  * ## Labels


### hcloud-subnetwork
***
Manage cloud subnetworks on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_subnetwork_module.html


#### Base Command

`hcloud-subnetwork`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network | The ID or Name  of the Hetzner Cloud Networks. | Required | 
| ip_range | IP range of the subnetwork. | Required | 
| type | Type of subnetwork. | Required | 
| network_zone | Name of network zone. | Required | 
| state | State of the subnetwork. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudSubnetwork.hcloud_subnetwork | unknown | One Subnet of a Network | 


#### Command Example
```!hcloud-subnetwork network="my-network" ip_range="10.0.0.0/16" network_zone="eu-central" type="server" state="present" ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudSubnetwork": [
            {
                "gateway": "10.0.0.1",
                "ip_range": "10.0.0.0/16",
                "network": "my-network",
                "network_zone": "eu-central",
                "status": "CHANGED",
                "type": "server",
                "vswitch_id": null
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * gateway: 10.0.0.1
>  * ip_range: 10.0.0.0/16
>  * network: my-network
>  * network_zone: eu-central
>  * type: server
>  * vswitch_id: None


### hcloud-volume
***
Create and manage block volumes on the Hetzner Cloud.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_volume_module.html


#### Base Command

`hcloud-volume`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the Hetzner Cloud Block Volume to manage.<br/>Only required if no volume `name` is given. | Optional | 
| name | The Name of the Hetzner Cloud Block Volume to manage.<br/>Only required if no volume `id` is given or a volume does not exists. | Optional | 
| size | The size of the Block Volume in GB.<br/>Required if volume does not yet exists. | Optional | 
| automount | Automatically mount the Volume. | Optional | 
| format | Automatically Format the volume on creation<br/>Can only be used in case the Volume does not exists. Possible values are: xfs, ext4. | Optional | 
| location | Location of the Hetzner Cloud Volume.<br/>Required if no `server` is given and Volume does not exists. | Optional | 
| server | Server Name the Volume should be assigned to.<br/>Required if no `location` is given and Volume does not exists. | Optional | 
| labels | User-defined key-value pairs. | Optional | 
| state | State of the volume. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudVolume.hcloud_volume | unknown | The block volume | 


#### Command Example
```!hcloud-volume name="my-volume" location="fsn1" size="100" state="present" ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudVolume": [
            {
                "delete_protection": false,
                "id": "12052962",
                "labels": {},
                "linux_device": "/dev/disk/by-id/scsi-0HC_Volume_12052962",
                "location": "fsn1",
                "name": "my-volume",
                "server": "None",
                "size": 100,
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * delete_protection: False
>  * id: 12052962
>  * linux_device: /dev/disk/by-id/scsi-0HC_Volume_12052962
>  * location: fsn1
>  * name: my-volume
>  * server: None
>  * size: 100
>  * ## Labels


### hcloud-volume-info
***
Gather infos about your Hetzner Cloud volumes.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hcloud_volume_info_module.html


#### Base Command

`hcloud-volume-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the volume you want to get. | Optional | 
| name | The name of the volume you want to get. | Optional | 
| label_selector | The label selector for the volume you want to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HCloud.HcloudVolumeInfo.hcloud_volume_info | unknown | The volume infos as list | 


#### Command Example
```!hcloud-volume-info ```

#### Context Example
```json
{
    "HCloud": {
        "HcloudVolumeInfo": [
            [
                {
                    "delete_protection": false,
                    "id": "12052962",
                    "labels": {},
                    "linux_device": "/dev/disk/by-id/scsi-0HC_Volume_12052962",
                    "location": "fsn1",
                    "name": "my-volume",
                    "server": "None",
                    "size": 100
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
># My-Volume
>  * delete_protection: False
>  * id: 12052962
>  * linux_device: /dev/disk/by-id/scsi-0HC_Volume_12052962
>  * location: fsn1
>  * name: my-volume
>  * server: None
>  * size: 100
>  * ## Labels


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
