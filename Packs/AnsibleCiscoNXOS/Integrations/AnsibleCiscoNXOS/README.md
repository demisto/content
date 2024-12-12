This integration enables the management of Cisco NXOS Switches and Routers directly from XSOAR using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the hosts by utilising SSH.

To use this integration, configure an instance of this integration. This will associate a credential to be used to access hosts when commands are run. The commands from this integration will take the NXOS host address(es) as an input, and use the saved credential associated to the instance to execute. Create separate instances if multiple credentials are required.

## Credentials
This integration supports a number of methods of authenticating with the network device:

1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions
Whilst possible to use a `Network-Operator` (read-only) role, most commands require read and write access. It is recommended to use `Network-Admin` or appropriately scoped custom role.

## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the NXOS host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.
## Configure Ansible Cisco NXOS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | The credentials to associate with the instance. SSH keys can be configured using the credential manager. | True |
| Password |  | True |
| Default SSH Port | The default port to use if one is not specified in the commands \`host\` argument. | True |
| Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!nxos-facts`command providing an example `host` as the command argument. This command will connect to the specified network device with the configured credentials in the integration, and if successful output general information about the device.

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
### nxos-aaa-server
***
Manages AAA server global configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_aaa_server_module.html


#### Base Command

`nxos-aaa-server`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| server_type | The server type is either radius or tacacs. Possible values are: radius, tacacs. | Required | 
| global_key | Global AAA shared secret or keyword 'default'. | Optional | 
| encrypt_type | The state of encryption applied to the entered global key. O clear text, 7 encrypted. Type-6 encryption is not supported. Possible values are: 0, 7. | Optional | 
| deadtime | Duration for which a non-reachable AAA server is skipped, in minutes or keyword 'default. Range is 1-1440. Device default is 0. | Optional | 
| server_timeout | Global AAA server timeout period, in seconds or keyword 'default. Range is 1-60. Device default is 5. | Optional | 
| directed_request | Enables direct authentication requests to AAA server or keyword 'default' Device default is disabled. Possible values are: enabled, disabled. | Optional | 
| state | Manage the state of the resource. Possible values are: present, default. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosAaaServer.commands | unknown | command sent to the device | 


#### Command Example
```!nxos-aaa-server host="192.168.1.19" server_type="radius" server_timeout="9" deadtime="20" directed_request="enabled" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosAaaServer": {
            "changed": true,
            "commands": [
                "radius-server deadtime 20",
                "radius-server timeout 9",
                "radius-server directed-request"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: radius-server deadtime 20
>    * 1: radius-server timeout 9
>    * 2: radius-server directed-request


### nxos-aaa-server-host
***
Manages AAA server host-specific configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_aaa_server_host_module.html


#### Base Command

`nxos-aaa-server-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| server_type | The server type is either radius or tacacs. Possible values are: radius, tacacs. | Required | 
| address | Address or name of the radius or tacacs host. | Required | 
| key | Shared secret for the specified host or keyword 'default'. | Optional | 
| encrypt_type | The state of encryption applied to the entered key. O for clear text, 7 for encrypted. Type-6 encryption is not supported. Possible values are: 0, 7. | Optional | 
| host_timeout | Timeout period for specified host, in seconds or keyword 'default. Range is 1-60. | Optional | 
| auth_port | Alternate UDP port for RADIUS authentication or keyword 'default'. | Optional | 
| acct_port | Alternate UDP port for RADIUS accounting or keyword 'default'. | Optional | 
| tacacs_port | Alternate TCP port TACACS Server or keyword 'default'. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosAaaServerHost.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosAaaServerHost.existing | unknown | k/v pairs of existing configuration | 
| CiscoNXOS.NxosAaaServerHost.end_state | unknown | k/v pairs of configuration after module execution | 
| CiscoNXOS.NxosAaaServerHost.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosAaaServerHost.changed | boolean | check to see if a change was made on the device | 


#### Command Example
```!nxos-aaa-server-host host="192.168.1.19" state="present" server_type="radius" address="1.2.3.4" acct_port="2084" host_timeout="10" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosAaaServerHost": {
            "changed": true,
            "end_state": {
                "acct_port": "2084",
                "address": "1.2.3.4",
                "auth_port": null,
                "host_timeout": "10",
                "key": null,
                "server_type": "radius"
            },
            "existing": {},
            "host": "192.168.1.19",
            "proposed": {
                "acct_port": "2084",
                "address": "1.2.3.4",
                "host_timeout": "10",
                "server_type": "radius"
            },
            "status": "CHANGED",
            "updates": [
                "radius-server host 1.2.3.4 acct-port 2084 timeout 10"
            ]
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## End_State
>    * acct_port: 2084
>    * address: 1.2.3.4
>    * auth_port: None
>    * host_timeout: 10
>    * key: None
>    * server_type: radius
>  * ## Existing
>  * ## Proposed
>    * acct_port: 2084
>    * address: 1.2.3.4
>    * host_timeout: 10
>    * server_type: radius
>  * ## Updates
>    * 0: radius-server host 1.2.3.4 acct-port 2084 timeout 10


### nxos-acl
***
Manages access list entries for ACLs.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_acl_module.html


#### Base Command

`nxos-acl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| seq | Sequence number of the entry (ACE). | Optional | 
| name | Case sensitive name of the access list (ACL). | Required | 
| action | Action of the ACE. Possible values are: permit, deny, remark. | Optional | 
| remark | If action is set to remark, this is the description. | Optional | 
| proto | Port number or protocol (as supported by the switch). | Optional | 
| src | Source ip and mask using IP/MASK notation and supports keyword 'any'. | Optional | 
| src_port_op | Source port operands such as eq, neq, gt, lt, range. Possible values are: any, eq, gt, lt, neq, range. | Optional | 
| src_port1 | Port/protocol and also first (lower) port when using range operand. | Optional | 
| src_port2 | Second (end) port when using range operand. | Optional | 
| dest | Destination ip and mask using IP/MASK notation and supports the keyword 'any'. | Optional | 
| dest_port_op | Destination port operands such as eq, neq, gt, lt, range. Possible values are: any, eq, gt, lt, neq, range. | Optional | 
| dest_port1 | Port/protocol and also first (lower) port when using range operand. | Optional | 
| dest_port2 | Second (end) port when using range operand. | Optional | 
| log | Log matches against this entry. Possible values are: enable. | Optional | 
| urg | Match on the URG bit. Possible values are: enable. | Optional | 
| ack | Match on the ACK bit. Possible values are: enable. | Optional | 
| psh | Match on the PSH bit. Possible values are: enable. | Optional | 
| rst | Match on the RST bit. Possible values are: enable. | Optional | 
| syn | Match on the SYN bit. Possible values are: enable. | Optional | 
| fin | Match on the FIN bit. Possible values are: enable. | Optional | 
| established | Match established connections. Possible values are: enable. | Optional | 
| fragments | Check non-initial fragments. Possible values are: enable. | Optional | 
| time_range | Name of time-range to apply. | Optional | 
| precedence | Match packets with given precedence. Possible values are: critical, flash, flash-override, immediate, internet, network, priority, routine. | Optional | 
| dscp | Match packets with given dscp value. Possible values are: af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43, cs1, cs2, cs3, cs4, cs5, cs6, cs7, default, ef. | Optional | 
| state | Specify desired state of the resource. Possible values are: present, absent, delete_acl. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosAcl.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-acl host="192.168.1.19" name="ANSIBLE" seq="10" action="permit" proto="tcp" "src"="192.0.2.1/2" dest="any" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosAcl": {
            "changed": true,
            "commands": [
                "ip access-list ANSIBLE",
                "10 permit tcp 192.0.2.1/24 any"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: ip access-list ANSIBLE
>    * 1: 10 permit tcp 192.0.2.1/24 any


### nxos-acl-interface
***
Manages applying ACLs to interfaces.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_acl_interface_module.html


#### Base Command

`nxos-acl-interface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Case sensitive name of the access list (ACL). | Required | 
| interface | Full name of interface, e.g. `Ethernet1/1`. | Required | 
| direction | Direction ACL to be applied in on the interface. Possible values are: ingress, egress. | Required | 
| state | Specify desired state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosAclInterface.acl_applied_to | unknown | list of interfaces the ACL is applied to | 
| CiscoNXOS.NxosAclInterface.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-acl-interface host="192.168.1.19" name="ANSIBLE" interface="ethernet1/41" direction="egress" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosAclInterface": {
            "changed": true,
            "commands": [
                "interface ethernet1/41",
                "ip access-group ANSIBLE out"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: interface ethernet1/41
>    * 1: ip access-group ANSIBLE out

### nxos-banner
***
Manage multiline banners on Cisco NXOS devices
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_banner_module.html


#### Base Command

`nxos-banner`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| banner | Specifies which banner that should be configured on the remote device. Possible values are: exec, motd. | Required | 
| text | The banner text that should be present in the remote device running configuration. This argument accepts a multiline string, with no empty lines. Requires `state=present`. | Optional | 
| state | Specifies whether or not the configuration is present in the current devices active running configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBanner.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!nxos-banner host="192.168.1.19" banner="exec" text="this is my exec banner" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosBanner": {
            "changed": true,
            "commands": [
                "banner exec @\nthis is my exec banner\n@"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: banner exec @
>this is my exec banner
>@

### nxos-bfd-global
***
Bidirectional Forwarding Detection (BFD) global-level configuration
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_bfd_global_module.html


#### Base Command

`nxos-bfd-global`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| echo_interface | Loopback interface used for echo frames. Valid values are loopback interface name or 'deleted'. Not supported on N5K/N6K. | Optional | 
| echo_rx_interval | BFD Echo receive interval in milliseconds. | Optional | 
| interval | BFD interval timer values. Value must be a dict defining values for keys (tx, min_rx, and multiplier). | Optional | 
| slow_timer | BFD slow rate timer in milliseconds. | Optional | 
| startup_timer | BFD delayed startup timer in seconds. Not supported on N5K/N6K/N7K. | Optional | 
| ipv4_echo_rx_interval | BFD IPv4 session echo receive interval in milliseconds. | Optional | 
| ipv4_interval | BFD IPv4 interval timer values. Value must be a dict defining values for keys (tx, min_rx, and multiplier). | Optional | 
| ipv4_slow_timer | BFD IPv4 slow rate timer in milliseconds. | Optional | 
| ipv6_echo_rx_interval | BFD IPv6 session echo receive interval in milliseconds. | Optional | 
| ipv6_interval | BFD IPv6 interval timer values. Value must be a dict defining values for keys (tx, min_rx, and multiplier). | Optional | 
| ipv6_slow_timer | BFD IPv6 slow rate timer in milliseconds. | Optional | 
| fabricpath_interval | BFD fabricpath interval timer values. Value must be a dict defining values for keys (tx, min_rx, and multiplier). | Optional | 
| fabricpath_slow_timer | BFD fabricpath slow rate timer in milliseconds. | Optional | 
| fabricpath_vlan | BFD fabricpath control vlan. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBfdGlobal.cmds | unknown | commands sent to the device | 



#### Command Example
```!nxos-bfd-global host="192.168.1.19" echo_rx_interval="50" interval="{'tx': 50, 'min_rx': 50, 'multiplier': 4}" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosBfdGlobal": {
            "changed": false,
            "check_mode": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * check_mode: False
>  * ## Commands

### nxos-bfd-interfaces
***
Manages BFD attributes of nxos interfaces.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_bfd_interfaces_module.html


#### Base Command

`nxos-bfd-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | The provided configuration. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBfdInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosBfdInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosBfdInterfaces.commands | unknown | The set of commands pushed to the remote device. | 


#### Command Example
```!nxos-bfd-interfaces host="192.168.1.19" state="deleted" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosBfdInterfaces": {
            "before": [
                {
                    "bfd": "enable",
                    "echo": "enable",
                    "name": "Ethernet1/1"
                },
                {
                    "bfd": "enable",
                    "echo": "enable",
                    "name": "Ethernet1/2"
                }
            ],
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Before
>  * ## Ethernet1/1
>    * bfd: enable
>    * echo: enable
>    * name: Ethernet1/1
>  * ## Ethernet1/2
>    * bfd: enable
>    * echo: enable
>    * name: Ethernet1/2
>  * ## Commands


### nxos-bgp
***
Manages BGP configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_bgp_module.html


#### Base Command

`nxos-bgp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| asn | BGP autonomous system number. Valid values are String, Integer in ASPLAIN or ASDOT notation. | Required | 
| vrf | Name of the VRF. The name 'default' is a valid VRF representing the global BGP. | Optional | 
| bestpath_always_compare_med | Enable/Disable MED comparison on paths from different autonomous systems. | Optional | 
| bestpath_aspath_multipath_relax | Enable/Disable load sharing across the providers with different (but equal-length) AS paths. | Optional | 
| bestpath_compare_routerid | Enable/Disable comparison of router IDs for identical eBGP paths. | Optional | 
| bestpath_compare_neighborid | Enable/Disable neighborid. Use this when more paths available than max path config. | Optional | 
| bestpath_cost_community_ignore | Enable/Disable Ignores the cost community for BGP best-path calculations. | Optional | 
| bestpath_med_confed | Enable/Disable enforcement of bestpath to do a MED comparison only between paths originated within a confederation. | Optional | 
| bestpath_med_missing_as_worst | Enable/Disable assigns the value of infinity to received routes that do not carry the MED attribute, making these routes the least desirable. | Optional | 
| bestpath_med_non_deterministic | Enable/Disable deterministic selection of the best MED pat from among the paths from the same autonomous system. | Optional | 
| cluster_id | Route Reflector Cluster-ID. | Optional | 
| confederation_id | Routing domain confederation AS. | Optional | 
| confederation_peers | AS confederation parameters. | Optional | 
| disable_policy_batching | Enable/Disable the batching evaluation of prefix advertisement to all peers. | Optional | 
| disable_policy_batching_ipv4_prefix_list | Enable/Disable the batching evaluation of prefix advertisements to all peers with prefix list. | Optional | 
| disable_policy_batching_ipv6_prefix_list | Enable/Disable the batching evaluation of prefix advertisements to all peers with prefix list. | Optional | 
| enforce_first_as | Enable/Disable enforces the neighbor autonomous system to be the first AS number listed in the AS path attribute for eBGP. On NX-OS, this property is only supported in the global BGP context. | Optional | 
| event_history_cli | Enable/Disable cli event history buffer. Possible values are: size_small, size_medium, size_large, size_disable, default. | Optional | 
| event_history_detail | Enable/Disable detail event history buffer. Possible values are: size_small, size_medium, size_large, size_disable, default. | Optional | 
| event_history_events | Enable/Disable event history buffer. Possible values are: size_small, size_medium, size_large, size_disable, default. | Optional | 
| event_history_periodic | Enable/Disable periodic event history buffer. Possible values are: size_small, size_medium, size_large, size_disable, default. | Optional | 
| fast_external_fallover | Enable/Disable immediately reset the session if the link to a directly connected BGP peer goes down.  Only supported in the global BGP context. | Optional | 
| flush_routes | Enable/Disable flush routes in RIB upon controlled restart. On NX-OS, this property is only supported in the global BGP context. | Optional | 
| graceful_restart | Enable/Disable graceful restart. | Optional | 
| graceful_restart_helper | Enable/Disable graceful restart helper mode. | Optional | 
| graceful_restart_timers_restart | Set maximum time for a restart sent to the BGP peer. | Optional | 
| graceful_restart_timers_stalepath_time | Set maximum time that BGP keeps the stale routes from the restarting BGP peer. | Optional | 
| isolate | Enable/Disable isolate this router from BGP perspective. | Optional | 
| local_as | Local AS number to be used within a VRF instance. | Optional | 
| log_neighbor_changes | Enable/Disable message logging for neighbor up/down event. | Optional | 
| maxas_limit | Specify Maximum number of AS numbers allowed in the AS-path attribute. Valid values are between 1 and 512. | Optional | 
| neighbor_down_fib_accelerate | Enable/Disable handle BGP neighbor down event, due to various reasons. | Optional | 
| reconnect_interval | The BGP reconnection interval for dropped sessions. Valid values are between 1 and 60. | Optional | 
| router_id | Router Identifier (ID) of the BGP router VRF instance. | Optional | 
| shutdown | Administratively shutdown the BGP protocol. | Optional | 
| suppress_fib_pending | Enable/Disable advertise only routes programmed in hardware to peers. | Optional | 
| timer_bestpath_limit | Specify timeout for the first best path after a restart, in seconds. | Optional | 
| timer_bgp_hold | Set BGP hold timer. | Optional | 
| timer_bgp_keepalive | Set BGP keepalive timer. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBgp.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-bgp host="192.168.1.19" asn="65535" vrf="test" router_id="192.0.2.1" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosBgp": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-bgp-af
***
Manages BGP Address-family configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_bgp_af_module.html


#### Base Command

`nxos-bgp-af`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| asn | BGP autonomous system number. Valid values are String, Integer in ASPLAIN or ASDOT notation. | Required | 
| vrf | Name of the VRF. The name 'default' is a valid VRF representing the global bgp. | Required | 
| afi | Address Family Identifier. Possible values are: ipv4, ipv6, vpnv4, vpnv6, l2vpn. | Required | 
| safi | Sub Address Family Identifier. Possible values are: unicast, multicast, evpn. | Required | 
| additional_paths_install | Install a backup path into the forwarding table and provide prefix independent convergence (PIC) in case of a PE-CE link failure. | Optional | 
| additional_paths_receive | Enables the receive capability of additional paths for all of the neighbors under this address family for which the capability has not been disabled. | Optional | 
| additional_paths_selection | Configures the capability of selecting additional paths for a prefix. Valid values are a string defining the name of the route-map. | Optional | 
| additional_paths_send | Enables the send capability of additional paths for all of the neighbors under this address family for which the capability has not been disabled. | Optional | 
| advertise_l2vpn_evpn | Advertise evpn routes. | Optional | 
| client_to_client | Configure client-to-client route reflection. | Optional | 
| dampen_igp_metric | Specify dampen value for IGP metric-related changes, in seconds. Valid values are integer and keyword 'default'. | Optional | 
| dampening_state | Enable/disable route-flap dampening. | Optional | 
| dampening_half_time | Specify decay half-life in minutes for route-flap dampening. Valid values are integer and keyword 'default'. | Optional | 
| dampening_max_suppress_time | Specify max suppress time for route-flap dampening stable route. Valid values are integer and keyword 'default'. | Optional | 
| dampening_reuse_time | Specify route reuse time for route-flap dampening. Valid values are integer and keyword 'default'. | Optional | 
| dampening_routemap | Specify route-map for route-flap dampening. Valid values are a string defining the name of the route-map. | Optional | 
| dampening_suppress_time | Specify route suppress time for route-flap dampening. Valid values are integer and keyword 'default'. | Optional | 
| default_information_originate | Default information originate. | Optional | 
| default_metric | Sets default metrics for routes redistributed into BGP. Valid values are Integer or keyword 'default'. | Optional | 
| distance_ebgp | Sets the administrative distance for eBGP routes. Valid values are Integer or keyword 'default'. | Optional | 
| distance_ibgp | Sets the administrative distance for iBGP routes. Valid values are Integer or keyword 'default'. | Optional | 
| distance_local | Sets the administrative distance for local BGP routes. Valid values are Integer or keyword 'default'. | Optional | 
| inject_map | An array of route-map names which will specify prefixes to inject. Each array entry must first specify the inject-map name, secondly an exist-map name, and optionally the copy-attributes keyword which indicates that attributes should be copied from the aggregate. For example [['lax_inject_map', 'lax_exist_map'], ['nyc_inject_map', 'nyc_exist_map', 'copy-attributes'], ['fsd_inject_map', 'fsd_exist_map']]. | Optional | 
| maximum_paths | Configures the maximum number of equal-cost paths for load sharing. Valid value is an integer in the range 1-64. | Optional | 
| maximum_paths_ibgp | Configures the maximum number of ibgp equal-cost paths for load sharing. Valid value is an integer in the range 1-64. | Optional | 
| networks | Networks to configure. Valid value is a list of network prefixes to advertise. The list must be in the form of an array. Each entry in the array must include a prefix address and an optional route-map. For example [['10.0.0.0/16', 'routemap_LA'], ['192.168.1.1', 'Chicago'], ['192.168.2.0/24'], ['1.1.1.1/24', 'routemap_NYC']]. | Optional | 
| next_hop_route_map | Configure a route-map for valid nexthops. Valid values are a string defining the name of the route-map. | Optional | 
| redistribute | A list of redistribute directives. Multiple redistribute entries are allowed. The list must be in the form of a nested array. the first entry of each array defines the source-protocol to redistribute from; the second entry defines a route-map name. A route-map is highly advised but may be optional on some platforms, in which case it may be omitted from the array list. For example [['direct', 'rm_direct'], ['lisp', 'rm_lisp']]. | Optional | 
| suppress_inactive | Advertises only active routes to peers. | Optional | 
| table_map | Apply table-map to filter routes downloaded into URIB. Valid values are a string. | Optional | 
| table_map_filter | Filters routes rejected by the route-map and does not download them to the RIB. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBgpAf.commands | unknown | commands sent to the device | 



### nxos-bgp-neighbor
***
Manages BGP neighbors configurations.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_bgp_neighbor_module.html


#### Base Command

`nxos-bgp-neighbor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| asn | BGP autonomous system number. Valid values are string, Integer in ASPLAIN or ASDOT notation. | Required | 
| vrf | Name of the VRF. The name 'default' is a valid VRF representing the global bgp. Default is default. | Optional | 
| neighbor | Neighbor Identifier. Valid values are string. Neighbors may use IPv4 or IPv6 notation, with or without prefix length. | Required | 
| description | Description of the neighbor. | Optional | 
| bfd | Enables/Disables BFD for a given neighbor. Dependency: 'feature bfd'. Possible values are: enable, disable. | Optional | 
| connected_check | Configure whether or not to check for directly connected peer. | Optional | 
| capability_negotiation | Configure whether or not to negotiate capability with this neighbor. | Optional | 
| dynamic_capability | Configure whether or not to enable dynamic capability. | Optional | 
| ebgp_multihop | Specify multihop TTL for a remote peer. Valid values are integers between 2 and 255, or keyword 'default' to disable this property. | Optional | 
| local_as | Specify the local-as number for the eBGP neighbor. Valid values are String or Integer in ASPLAIN or ASDOT notation, or 'default', which means not to configure it. | Optional | 
| log_neighbor_changes | Specify whether or not to enable log messages for neighbor up/down event. Possible values are: enable, disable, inherit. | Optional | 
| low_memory_exempt | Specify whether or not to shut down this neighbor under memory pressure. | Optional | 
| maximum_peers | Specify Maximum number of peers for this neighbor prefix Valid values are between 1 and 1000, or 'default', which does not impose the limit. Note that this parameter is accepted only on neighbors with address/prefix. | Optional | 
| pwd | Specify the password for neighbor. Valid value is string. | Optional | 
| pwd_type | Specify the encryption type the password will use. Valid values are '3des' or 'cisco_type_7' encryption or keyword 'default'. Possible values are: 3des, cisco_type_7, default. | Optional | 
| remote_as | Specify Autonomous System Number of the neighbor. Valid values are String or Integer in ASPLAIN or ASDOT notation, or 'default', which means not to configure it. | Optional | 
| remove_private_as | Specify the config to remove private AS number from outbound updates. Valid values are 'enable' to enable this config, 'disable' to disable this config, 'all' to remove all private AS number, or 'replace-as', to replace the private AS number. Possible values are: enable, disable, all, replace-as. | Optional | 
| shutdown | Configure to administratively shutdown this neighbor. | Optional | 
| suppress_4_byte_as | Configure to suppress 4-byte AS Capability. | Optional | 
| timers_keepalive | Specify keepalive timer value. Valid values are integers between 0 and 3600 in terms of seconds, or 'default', which is 60. | Optional | 
| timers_holdtime | Specify holdtime timer value. Valid values are integers between 0 and 3600 in terms of seconds, or 'default', which is 180. | Optional | 
| transport_passive_only | Specify whether or not to only allow passive connection setup. Valid values are 'true', 'false', and 'default', which defaults to 'false'. This property can only be configured when the neighbor is in 'ip' address format without prefix length. | Optional | 
| update_source | Specify source interface of BGP session and updates. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBgpNeighbor.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-bgp-neighbor host="192.168.1.19" asn="65535" neighbor="1.1.1.1" local_as="20" remote_as="30" bfd="enable" description="just a description" update_source="Ethernet1/3" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosBgpNeighbor": {
            "changed": true,
            "commands": [
                "router bgp 65535",
                "neighbor 1.1.1.1",
                "bfd",
                "description just a description",
                "remote-as 30",
                "update-source Ethernet1/3",
                "local-as 20"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: router bgp 65535
>    * 1: neighbor 1.1.1.1
>    * 2: bfd
>    * 3: description just a description
>    * 4: remote-as 30
>    * 5: update-source Ethernet1/3
>    * 6: local-as 20

### nxos-bgp-neighbor-af
***
Manages BGP address-family's neighbors configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_bgp_neighbor_af_module.html


#### Base Command

`nxos-bgp-neighbor-af`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| asn | BGP autonomous system number. Valid values are String, Integer in ASPLAIN or ASDOT notation. | Required | 
| vrf | Name of the VRF. The name 'default' is a valid VRF representing the global bgp. Default is default. | Optional | 
| neighbor | Neighbor Identifier. Valid values are string. Neighbors may use IPv4 or IPv6 notation, with or without prefix length. | Required | 
| afi | Address Family Identifier. Possible values are: ipv4, ipv6, vpnv4, vpnv6, l2vpn. | Required | 
| safi | Sub Address Family Identifier. Possible values are: unicast, multicast, evpn. | Required | 
| additional_paths_receive | Valid values are enable for basic command enablement; disable for disabling the command at the neighbor af level (it adds the disable keyword to the basic command); and inherit to remove the command at this level (the command value is inherited from a higher BGP layer). Possible values are: enable, disable, inherit. | Optional | 
| additional_paths_send | Valid values are enable for basic command enablement; disable for disabling the command at the neighbor af level (it adds the disable keyword to the basic command); and inherit to remove the command at this level (the command value is inherited from a higher BGP layer). Possible values are: enable, disable, inherit. | Optional | 
| advertise_map_exist | Conditional route advertisement. This property requires two route maps, an advertise-map and an exist-map. Valid values are an array specifying both the advertise-map name and the exist-map name, or simply 'default' e.g. ['my_advertise_map', 'my_exist_map']. This command is mutually exclusive with the advertise_map_non_exist property. | Optional | 
| advertise_map_non_exist | Conditional route advertisement. This property requires two route maps, an advertise-map and an exist-map. Valid values are an array specifying both the advertise-map name and the non-exist-map name, or simply 'default' e.g. ['my_advertise_map', 'my_non_exist_map']. This command is mutually exclusive with the advertise_map_exist property. | Optional | 
| allowas_in | Activate allowas-in property. | Optional | 
| allowas_in_max | Max-occurrences value for allowas_in. Valid values are an integer value or 'default'. This is mutually exclusive with allowas_in. | Optional | 
| as_override | Activate the as-override feature. | Optional | 
| default_originate | Activate the default-originate feature. | Optional | 
| default_originate_route_map | Route-map for the default_originate property. Valid values are a string defining a route-map name, or 'default'. This is mutually exclusive with default_originate. | Optional | 
| disable_peer_as_check | Disable checking of peer AS-number while advertising. | Optional | 
| filter_list_in | Valid values are a string defining a filter-list name, or 'default'. | Optional | 
| filter_list_out | Valid values are a string defining a filter-list name, or 'default'. | Optional | 
| max_prefix_limit | maximum-prefix limit value. Valid values are an integer value or 'default'. | Optional | 
| max_prefix_interval | Optional restart interval. Valid values are an integer. Requires max_prefix_limit. May not be combined with max_prefix_warning. | Optional | 
| max_prefix_threshold | Optional threshold percentage at which to generate a warning. Valid values are an integer value. Requires max_prefix_limit. | Optional | 
| max_prefix_warning | Optional warning-only keyword. Requires max_prefix_limit. May not be combined with max_prefix_interval. | Optional | 
| next_hop_self | Activate the next-hop-self feature. | Optional | 
| next_hop_third_party | Activate the next-hop-third-party feature. | Optional | 
| prefix_list_in | Valid values are a string defining a prefix-list name, or 'default'. | Optional | 
| prefix_list_out | Valid values are a string defining a prefix-list name, or 'default'. | Optional | 
| route_map_in | Valid values are a string defining a route-map name, or 'default'. | Optional | 
| route_map_out | Valid values are a string defining a route-map name, or 'default'. | Optional | 
| route_reflector_client | Router reflector client. | Optional | 
| send_community | send-community attribute. Possible values are: none, both, extended, standard, default. | Optional | 
| soft_reconfiguration_in | Valid values are 'enable' for basic command enablement; 'always' to add the always keyword to the basic command; and 'inherit' to remove the command at this level (the command value is inherited from a higher BGP layer). Possible values are: enable, always, inherit. | Optional | 
| soo | Site-of-origin. Valid values are a string defining a VPN extcommunity or 'default'. | Optional | 
| suppress_inactive | suppress-inactive feature. | Optional | 
| unsuppress_map | unsuppress-map. Valid values are a string defining a route-map name or 'default'. | Optional | 
| weight | Weight value. Valid values are an integer value or 'default'. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosBgpNeighborAf.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-bgp-neighbor-af host="192.168.1.19" asn="65535" neighbor="1.1.1.1" afi="ipv4" safi="unicast" route_reflector_client="True" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosBgpNeighborAf": {
            "changed": true,
            "commands": [
                "router bgp 65535",
                "neighbor 1.1.1.1",
                "address-family ipv4 unicast",
                "route-reflector-client"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: router bgp 65535
>    * 1: neighbor 1.1.1.1
>    * 2: address-family ipv4 unicast
>    * 3: route-reflector-client
### nxos-command
***
Run arbitrary command on Cisco NXOS devices
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_command_module.html


#### Base Command

`nxos-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| commands | The commands to send to the remote NXOS device.  The resulting output from the command is returned.  If the `wait_for` argument is provided, the module is not returned until the condition is satisfied or the number of retires as expired. The `commands` argument also accepts an alternative form that allows for complex values that specify the command to run and the output format to return.   This can be done on a command by command basis.  The complex argument supports the keywords `command` and `output` where `command` is the command to run and `output` is one of 'text' or 'json'. | Required | 
| wait_for | Specifies what to evaluate from the output of the command and what conditionals to apply.  This argument will cause the task to wait for a particular conditional to be true before moving forward.   If the conditional is not true by the configured retries, the task fails.  See examples. | Optional | 
| match | The `match` argument is used in conjunction with the `wait_for` argument to specify the match policy.  Valid values are `all` or `any`.  If the value is set to `all` then all conditionals in the `wait_for` must be satisfied.  If the value is set to `any` then only one of the values must be satisfied. Default is all. | Optional | 
| retries | Specifies the number of retries a command should by tried before it is considered failed.  The command is run on the target device every retry and evaluated against the `wait_for` conditionals. Default is 10. | Optional | 
| interval | Configures the interval in seconds to wait between retries of the command.  If the command does not pass the specified conditional, the interval indicates how to long to wait before trying the command again. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosCommand.stdout | unknown | The set of responses from the commands | 
| CiscoNXOS.NxosCommand.stdout_lines | unknown | The value of stdout split into a list | 
| CiscoNXOS.NxosCommand.failed_conditions | unknown | The list of conditionals that have failed | 


#### Command Example
```!nxos-command host="192.168.1.19" commands="show version" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosCommand": {
            "changed": false,
            "host": "192.168.1.19",
            "status": "SUCCESS",
            "stdout": [
                "Cisco Nexus Operating System (NX-OS) Software\nTAC support: http://www.cisco.com/tac\nDocuments: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html\nCopyright (c) 2002-2019, Cisco Systems, Inc. All rights reserved.\nThe copyrights to certain works contained herein are owned by\nother third parties and are used and distributed under license.\nSome parts of this software are covered under the GNU Public\nLicense. A copy of the license is available at\nhttp://www.gnu.org/licenses/gpl.html.\n\nNexus 9000v is a demo version of the Nexus Operating System\n\nSoftware\n  BIOS: version \n NXOS: version 9.3(3)\n  BIOS compile time:  \n  NXOS image file is: bootflash:///nxos.9.3.3.bin\n  NXOS compile time:  12/22/2019 2:00:00 [12/22/2019 14:00:37]\n\n\nHardware\n  cisco Nexus9000 C9500v Chassis (\"Supervisor Module\")\n   with 7837092 kB of memory.\n  Processor Board ID 9ESGSKDKPR0\n\n  Device name: n9kv01\n  bootflash:    4287040 kB\nKernel uptime is 0 day(s), 8 hour(s), 56 minute(s), 55 second(s)\n\nLast reset \n  Reason: Unknown\n  System version: \n  Service: \n\nplugin\n  Core Plugin, Ethernet Plugin\n\nActive Package(s):"
            ],
            "stdout_lines": [
                [
                    "Cisco Nexus Operating System (NX-OS) Software",
                    "TAC support: http://www.cisco.com/tac",
                    "Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html",
                    "Copyright (c) 2002-2019, Cisco Systems, Inc. All rights reserved.",
                    "The copyrights to certain works contained herein are owned by",
                    "other third parties and are used and distributed under license.",
                    "Some parts of this software are covered under the GNU Public",
                    "License. A copy of the license is available at",
                    "http://www.gnu.org/licenses/gpl.html.",
                    "",
                    "Nexus 9000v is a demo version of the Nexus Operating System",
                    "",
                    "Software",
                    "  BIOS: version ",
                    " NXOS: version 9.3(3)",
                    "  BIOS compile time:  ",
                    "  NXOS image file is: bootflash:///nxos.9.3.3.bin",
                    "  NXOS compile time:  12/22/2019 2:00:00 [12/22/2019 14:00:37]",
                    "",
                    "",
                    "Hardware",
                    "  cisco Nexus9000 C9500v Chassis (\"Supervisor Module\")",
                    "   with 7837092 kB of memory.",
                    "  Processor Board ID 9ESGSKDKPR0",
                    "",
                    "  Device name: n9kv01",
                    "  bootflash:    4287040 kB",
                    "Kernel uptime is 0 day(s), 8 hour(s), 56 minute(s), 55 second(s)",
                    "",
                    "Last reset ",
                    "  Reason: Unknown",
                    "  System version: ",
                    "  Service: ",
                    "",
                    "plugin",
                    "  Core Plugin, Ethernet Plugin",
                    "",
                    "Active Package(s):"
                ]
            ]
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Stdout
>    * 0: Cisco Nexus Operating System (NX-OS) Software
>TAC support: http://www.cisco.com/tac
>Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
>Copyright (c) 2002-2019, Cisco Systems, Inc. All rights reserved.
>The copyrights to certain works contained herein are owned by
>other third parties and are used and distributed under license.
>Some parts of this software are covered under the GNU Public
>License. A copy of the license is available at
>http://www.gnu.org/licenses/gpl.html.
>
>Nexus 9000v is a demo version of the Nexus Operating System
>
>Software
>  BIOS: version 
> NXOS: version 9.3(3)
>  BIOS compile time:  
>  NXOS image file is: bootflash:///nxos.9.3.3.bin
>  NXOS compile time:  12/22/2019 2:00:00 [12/22/2019 14:00:37]
>
>
>Hardware
>  cisco Nexus9000 C9500v Chassis ("Supervisor Module")
>   with 7837092 kB of memory.
>  Processor Board ID 9ESGSKDKPR0
>
>  Device name: n9kv01
>  bootflash:    4287040 kB
>Kernel uptime is 0 day(s), 8 hour(s), 56 minute(s), 55 second(s)
>
>Last reset 
>  Reason: Unknown
>  System version: 
>  Service: 
>
>plugin
>  Core Plugin, Ethernet Plugin
>
>Active Package(s):
>  * ## Stdout_Lines
>  * ## List
>    * 0: Cisco Nexus Operating System (NX-OS) Software
>    * 1: TAC support: http://www.cisco.com/tac
>    * 2: Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
>    * 3: Copyright (c) 2002-2019, Cisco Systems, Inc. All rights reserved.
>    * 4: The copyrights to certain works contained herein are owned by
>    * 5: other third parties and are used and distributed under license.
>    * 6: Some parts of this software are covered under the GNU Public
>    * 7: License. A copy of the license is available at
>    * 8: http://www.gnu.org/licenses/gpl.html.
>    * 9: 
>    * 10: Nexus 9000v is a demo version of the Nexus Operating System
>    * 9: 
>    * 12: Software
>    * 13:   BIOS: version 
>    * 14:  NXOS: version 9.3(3)
>    * 15:   BIOS compile time:  
>    * 16:   NXOS image file is: bootflash:///nxos.9.3.3.bin
>    * 17:   NXOS compile time:  12/22/2019 2:00:00 [12/22/2019 14:00:37]
>    * 9: 
>    * 9: 
>    * 20: Hardware
>    * 21:   cisco Nexus9000 C9500v Chassis ("Supervisor Module")
>    * 22:    with 7837092 kB of memory.
>    * 23:   Processor Board ID 9ESGSKDKPR0
>    * 9: 
>    * 25:   Device name: n9kv01
>    * 26:   bootflash:    4287040 kB
>    * 27: Kernel uptime is 0 day(s), 8 hour(s), 56 minute(s), 55 second(s)
>    * 9: 
>    * 29: Last reset 
>    * 30:   Reason: Unknown
>    * 31:   System version: 
>    * 32:   Service: 
>    * 9: 
>    * 34: plugin
>    * 35:   Core Plugin, Ethernet Plugin
>    * 9: 
>    * 37: Active Package(s):


### nxos-config
***
Manage Cisco NXOS configuration sections
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_config_module.html


#### Base Command

`nxos-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| lines | The ordered set of commands that should be configured in the section.  The commands must be the exact same commands as found in the device running-config.  Be sure to note the configuration command syntax as some commands are automatically modified by the device config parser. | Optional | 
| parents | The ordered set of parents that uniquely identify the section or hierarchy the commands should be checked against.  If the parents argument is omitted, the commands are checked against the set of top level or global commands. | Optional | 
| src | The `src` argument provides a path to the configuration file to load into the remote system.  The path can either be a full system path to the configuration file if the value starts with / or relative to the root of the implemented role or playbook. This argument is mutually exclusive with the `lines` and `parents` arguments. | Optional | 
| replace_src | The `replace_src` argument provides path to the configuration file to load into the remote system. This argument is used to replace the entire config with a flat-file. This is used with argument `replace` with value `config`. This is mutually exclusive with the `lines` and `src` arguments. This argument is supported on Nexus 9K device. Use `nxos_file_copy` module to copy the flat file to remote device and then use the path with this argument. | Optional | 
| before | The ordered set of commands to push on to the command stack if a change needs to be made.  This allows the playbook designer the opportunity to perform configuration commands prior to pushing any changes without affecting how the set of commands are matched against the system. | Optional | 
| after | The ordered set of commands to append to the end of the command stack if a change needs to be made.  Just like with `before` this allows the playbook designer to append a set of commands to be executed after the command set. | Optional | 
| match | Instructs the module on the way to perform the matching of the set of commands against the current device config.  If match is set to `line`, commands are matched line by line.  If match is set to `strict`, command lines are matched with respect to position.  If match is set to `exact`, command lines must be an equal match.  Finally, if match is set to `none`, the module will not attempt to compare the source configuration with the running configuration on the remote device. Possible values are: line, strict, exact, none. Default is line. | Optional | 
| replace | Instructs the module on the way to perform the configuration on the device.  If the replace argument is set to `line` then the modified lines are pushed to the device in configuration mode.  If the replace argument is set to `block` then the entire command block is pushed to the device in configuration mode if any line is not correct. replace `config` is supported only on Nexus 9K device. Possible values are: line, block, config. Default is line. | Optional | 
| backup | This argument will cause the module to create a full backup of the current `running-config` from the remote device before any changes are made. If the `backup_options` value is not given, the backup file is written to the `backup` folder in the playbook root directory or role root directory, if playbook is part of an ansible role. If the directory does not exist, it is created. Default is no. | Optional | 
| running_config | The module, by default, will connect to the remote device and retrieve the current running-config to use as a base for comparing against the contents of source.  There are times when it is not desirable to have the task get the current running-config for every task in a playbook.  The `running_config` argument allows the implementer to pass in the configuration to use as the base config for comparison. | Optional | 
| defaults | The `defaults` argument will influence how the running-config is collected from the device.  When the value is set to true, the command used to collect the running-config is append with the all keyword.  When the value is set to false, the command is issued without the all keyword. Default is no. | Optional | 
| save_when | When changes are made to the device running-configuration, the changes are not copied to non-volatile storage by default.  Using this argument will change that before.  If the argument is set to `always`, then the running-config will always be copied to the startup-config and the `modified` flag will always be set to True.  If the argument is set to `modified`, then the running-config will only be copied to the startup-config if it has changed since the last save to startup-config.  If the argument is set to `never`, the running-config will never be copied to the startup-config.  If the argument is set to `changed`, then the running-config will only be copied to the startup-config if the task has made a change. `changed` was added in Ansible 2.6. Possible values are: always, never, modified, changed. Default is never. | Optional | 
| diff_against | When using the `ansible-playbook --diff` command line argument the module can generate diffs against different sources. When this option is configure as `startup`, the module will return the diff of the running-config against the startup-config. When this option is configured as `intended`, the module will return the diff of the running-config against the configuration provided in the `intended_config` argument. When this option is configured as `running`, the module will return the before and after diff of the running-config with respect to any changes made to the device configuration. Possible values are: startup, intended, running. Default is startup. | Optional | 
| diff_ignore_lines | Use this argument to specify one or more lines that should be ignored during the diff.  This is used for lines in the configuration that are automatically updated by the system.  This argument takes a list of regular expressions or exact line matches. | Optional | 
| intended_config | The `intended_config` provides the master configuration that the node should conform to and is used to check the final running-config against.   This argument will not modify any settings on the remote device and is strictly used to check the compliance of the current device's configuration against.  When specifying this argument, the task should also modify the `diff_against` value and set it to `intended`. | Optional | 
| backup_options | This is a dict object containing configurable options related to backup file path. The value of this option is read only when `backup` is set to `True`, if `backup` is set to `false` this option will be silently ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosConfig.commands | unknown | The set of commands that will be pushed to the remote device | 
| CiscoNXOS.NxosConfig.updates | unknown | The set of commands that will be pushed to the remote device | 
| CiscoNXOS.NxosConfig.backup_path | string | The full path to the backup file | 
| CiscoNXOS.NxosConfig.filename | string | The name of the backup file | 
| CiscoNXOS.NxosConfig.shortname | string | The full path to the backup file excluding the timestamp | 
| CiscoNXOS.NxosConfig.date | string | The date extracted from the backup file name | 
| CiscoNXOS.NxosConfig.time | string | The time extracted from the backup file name | 


#### Command Example
```!nxos-config host="192.168.1.19" lines="hostname n9kv01" save_when="modified"  backup=yes```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosConfig": {
            "backup_path": "./backup/192.168.1.19_config.2021-07-11@00:43:34",
            "changed": true,
            "commands": [
                "hostname n9kv01"
            ],
            "date": "2021-07-11",
            "filename": "192.168.1.19_config.2021-07-11@00:43:34",
            "host": "192.168.1.19",
            "shortname": "./backup/192.168.1.19_config",
            "status": "CHANGED",
            "time": "00:43:34",
            "updates": [
                "hostname n9kv01"
            ]
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * backup_path: ./backup/192.168.1.19_config.2021-07-11@00:43:34
>  * changed: True
>  * date: 2021-07-11
>  * filename: 192.168.1.19_config.2021-07-11@00:43:34
>  * shortname: ./backup/192.168.1.19_config
>  * time: 00:43:34
>  * ## Commands
>    * 0: hostname n9kv01
>  * ## Updates
>    * 0: hostname n9kv01

### nxos-evpn-global
***
Handles the EVPN control plane for VXLAN.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_evpn_global_module.html


#### Base Command

`nxos-evpn-global`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| nv_overlay_evpn | EVPN control plane. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosEvpnGlobal.commands | unknown | The set of commands to be sent to the remote device | 


#### Command Example
```!nxos-evpn-global host="192.168.1.19" nv_overlay_evpn="True" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosEvpnGlobal": {
            "changed": true,
            "commands": [
                "nv overlay evpn"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: nv overlay evpn


### nxos-evpn-vni
***
Manages Cisco EVPN VXLAN Network Identifier (VNI).
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_evpn_vni_module.html


#### Base Command

`nxos-evpn-vni`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| vni | The EVPN VXLAN Network Identifier. | Required | 
| route_distinguisher | The VPN Route Distinguisher (RD). The RD is combined with the IPv4 or IPv6 prefix learned by the PE router to create a globally unique address. | Required | 
| route_target_both | Enables/Disables route-target settings for both import and export target communities using a single property. | Optional | 
| route_target_import | Sets the route-target 'import' extended communities. | Optional | 
| route_target_export | Sets the route-target 'export' extended communities. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosEvpnVni.commands | unknown | commands sent to the device | 



### nxos-facts
***
Gets facts about NX-OS switches
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_facts_module.html


#### Base Command

`nxos-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| gather_subset | When supplied, this argument will restrict the facts collected to a given subset.  Possible values for this argument include all, hardware, config, legacy, and interfaces.  Can specify a list of values to include a larger subset.  Values can also be used with an initial `M(!`) to specify that a specific subset should not be collected. Default is !config. | Optional | 
| gather_network_resources | When supplied, this argument will restrict the facts collected to a given subset. Possible values for this argument include all and the resources like interfaces, vlans etc. Can specify a list of values to include a larger subset. Values can also be used with an initial `M(!`) to specify that a specific subset should not be collected. Valid subsets are 'all', 'bfd_interfaces', 'lag_interfaces', 'telemetry', 'vlans', 'lacp', 'lacp_interfaces', 'interfaces', 'l3_interfaces', 'l2_interfaces', 'lldp_global'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosFacts.net_gather_subset | unknown | The list of fact subsets collected from the device | 
| CiscoNXOS.NxosFacts.net_gather_network_resources | unknown | The list of fact for network resource subsets collected from the device | 
| CiscoNXOS.NxosFacts.net_model | string | The model name returned from the device | 
| CiscoNXOS.NxosFacts.net_serialnum | string | The serial number of the remote device | 
| CiscoNXOS.NxosFacts.net_version | string | The operating system version running on the remote device | 
| CiscoNXOS.NxosFacts.net_hostname | string | The configured hostname of the device | 
| CiscoNXOS.NxosFacts.net_image | string | The image file the device is running | 
| CiscoNXOS.NxosFacts.net_api | string | The name of the transport | 
| CiscoNXOS.NxosFacts.net_license_hostid | string | The License host id of the device | 
| CiscoNXOS.NxosFacts.net_python_version | string | The Python version Ansible controller is using | 
| CiscoNXOS.NxosFacts.net_filesystems | unknown | All file system names available on the device | 
| CiscoNXOS.NxosFacts.net_memfree_mb | number | The available free memory on the remote device in Mb | 
| CiscoNXOS.NxosFacts.net_memtotal_mb | number | The total memory on the remote device in Mb | 
| CiscoNXOS.NxosFacts.net_config | string | The current active config from the device | 
| CiscoNXOS.NxosFacts.net_all_ipv4_addresses | unknown | All IPv4 addresses configured on the device | 
| CiscoNXOS.NxosFacts.net_all_ipv6_addresses | unknown | All IPv6 addresses configured on the device | 
| CiscoNXOS.NxosFacts.net_interfaces | unknown | A hash of all interfaces running on the system | 
| CiscoNXOS.NxosFacts.net_neighbors | unknown | The list of LLDP and CDP neighbors from the device. If both, CDP and LLDP neighbor data is present on one port, CDP is preferred. | 
| CiscoNXOS.NxosFacts.fan_info | unknown | A hash of facts about fans in the remote device | 
| CiscoNXOS.NxosFacts.hostname | unknown | The configured hostname of the remote device | 
| CiscoNXOS.NxosFacts.interfaces_list | unknown | The list of interface names on the remote device | 
| CiscoNXOS.NxosFacts.kickstart | string | The software version used to boot the system | 
| CiscoNXOS.NxosFacts.module | unknown | A hash of facts about the modules in a remote device | 
| CiscoNXOS.NxosFacts.platform | string | The hardware platform reported by the remote device | 
| CiscoNXOS.NxosFacts.power_supply_info | string | A hash of facts about the power supplies in the remote device | 
| CiscoNXOS.NxosFacts.vlan_list | unknown | The list of VLAN IDs configured on the remote device | 


#### Command Example
```!nxos-facts host="192.168.1.19" gather_subset="all" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosFacts": {
            "discovered_interpreter_python": "/usr/local/bin/python",
            "host": "192.168.1.19",
            "net__hostname": "192.168.1.19",
            "net__os": "9.3(3)",
            "net__platform": "Nexus9000 C9500v Chassis",
            "net_all_ipv4_addresses": [
                "192.168.1.19"
            ],
            "net_all_ipv6_addresses": [],
            "net_api": "cliconf",
            "net_config": "!Command: show running-config\n!Running configuration last done at: Sat Jul 10 23:00:14 2021\n!Time: Sat Jul 10 23:00:57 2021\n\nversion 9.3(3) Bios:version  \nhostname 192.168.1.19\nvdc 192.168.1.19 id 1\n  limit-resource vlan minimum 16 maximum 4094\n  limit-resource vrf minimum 2 maximum 4096\n  limit-resource port-channel minimum 0 maximum 511\n  limit-resource u4route-mem minimum 248 maximum 248\n  limit-resource u6route-mem minimum 96 maximum 96\n  limit-resource m4route-mem minimum 58 maximum 58\n  limit-resource m6route-mem minimum 8 maximum 8\n\nnv overlay evpn\nfeature bfd\nclock protocol none vdc 1\n\nusername admin password 5 $5$GYWPMp8g$uCosvTBewY0RcsJx/XB4e92DceRU8J4mvDI1JztQtG3  role network-admin\nip domain-lookup\nradius-server timeout 9\nradius-server deadtime 20\nradius-server host 1.2.3.4 acct-port 2084 authentication accounting timeout 10 \nsystem default switchport\nip access-list ANSIBLE\n  10 permit tcp 192.0.2.1/24 any \nbfd interval 50 min_rx 50 multiplier 4\nsnmp-server user admin network-admin auth md5 0x4f14136eab1027c832da1709141f5070 priv 0x4f14136eab1027c832da1709141f5070 localizedkey\nrmon event 1 description FATAL(1) owner PMON@FATAL\nrmon event 2 description CRITICAL(2) owner PMON@CRITICAL\nrmon event 3 description ERROR(3) owner PMON@ERROR\nrmon event 4 description WARNING(4) owner PMON@WARNING\nrmon event 5 description INFORMATION(5) owner PMON@INFO\nradius-server directed-request \n\nvlan 1\n\nvrf context management\n  ip domain-name lan\n  ip name-server 192.168.1.1\n  ip route 0.0.0.0/0 192.168.1.1\n\ninterface Ethernet1/1\n\ninterface Ethernet1/2\n\ninterface Ethernet1/3\n\ninterface Ethernet1/4\n\ninterface Ethernet1/5\n\ninterface Ethernet1/6\n\ninterface Ethernet1/7\n\ninterface Ethernet1/8\n\ninterface Ethernet1/9\n\ninterface Ethernet1/10\n\ninterface Ethernet1/11\n\ninterface Ethernet1/12\n\ninterface Ethernet1/13\n\ninterface Ethernet1/14\n\ninterface Ethernet1/15\n\ninterface Ethernet1/16\n\ninterface Ethernet1/17\n\ninterface Ethernet1/18\n\ninterface Ethernet1/19\n\ninterface Ethernet1/20\n\ninterface Ethernet1/21\n\ninterface Ethernet1/22\n\ninterface Ethernet1/23\n\ninterface Ethernet1/24\n\ninterface Ethernet1/25\n\ninterface Ethernet1/26\n\ninterface Ethernet1/27\n\ninterface Ethernet1/28\n\ninterface Ethernet1/29\n\ninterface Ethernet1/30\n\ninterface Ethernet1/31\n\ninterface Ethernet1/32\n\ninterface Ethernet1/33\n\ninterface Ethernet1/34\n\ninterface Ethernet1/35\n\ninterface Ethernet1/36\n\ninterface Ethernet1/37\n\ninterface Ethernet1/38\n\ninterface Ethernet1/39\n\ninterface Ethernet1/40\n\ninterface Ethernet1/41\n\ninterface Ethernet1/42\n\ninterface Ethernet1/43\n\ninterface Ethernet1/44\n\ninterface Ethernet1/45\n\ninterface Ethernet1/46\n\ninterface Ethernet1/47\n\ninterface Ethernet1/48\n\ninterface Ethernet1/49\n\ninterface Ethernet1/50\n\ninterface Ethernet1/51\n\ninterface Ethernet1/52\n\ninterface Ethernet1/53\n\ninterface Ethernet1/54\n\ninterface Ethernet1/55\n\ninterface Ethernet1/56\n\ninterface Ethernet1/57\n\ninterface Ethernet1/58\n\ninterface Ethernet1/59\n\ninterface Ethernet1/60\n\ninterface Ethernet1/61\n\ninterface Ethernet1/62\n\ninterface Ethernet1/63\n\ninterface Ethernet1/64\n\ninterface mgmt0\n  description DHCP Configuration for PnP\n  vrf member management\n  ip address 192.168.1.19/24\nline console\nline vty\nno system default switchport shutdown\n",
            "net_fan_info": [],
            "net_features_enabled": [
                "bfd"
            ],
            "net_filesystems": [
                "bootflash:"
            ],
            "net_gather_network_resources": [],
            "net_gather_subset": [
                "interfaces",
                "config",
                "hardware",
                "legacy",
                "default",
                "features"
            ],
            "net_hostname": "192.168.1.19",
            "net_image": "bootflash:///nxos.9.3.3.bin",
            "net_interfaces": {
                "Ethernet1/1": {
                    "bandwidth": "1000000",
                    "duplex": "full",
                    "macaddress": "0cc2.8a00.0101",
                    "mode": "access",
                    "mtu": "1500",
                    "speed": "1000 Mb/s",
                    "state": "up",
                    "type": "100/1000/10000 Ethernet"
                },
                "mgmt0": {
                    "bandwidth": "1000000",
                    "description": "DHCP Configuration for PnP",
                    "duplex": "full",
                    "ipv4": {
                        "address": "192.168.1.19",
                        "masklen": "24"
                    },
                    "macaddress": "0c05.2bc2.8a00",
                    "mtu": "1500",
                    "speed": "1000 Mb/s",
                    "state": "up",
                    "type": "GigabitEthernet"
                }
            },
            "net_interfaces_list": [
                "mgmt0",
                "Ethernet1/1",
            ],
            "net_license_hostid": "91EMAC025KL",
            "net_memfree_mb": 3965.3359375,
            "net_memtotal_mb": 7653.41015625,
            "net_model": "Nexus9000 C9500v Chassis (\"Supervisor Module\")",
            "net_module": [
                {
                    "model": "N9K-X9564v",
                    "ports": "64",
                    "status": "ok",
                    "type": "Nexus 9000v 64 port Ethernet Module"
                },
                {
                    "model": "N9K-vSUP",
                    "ports": "0",
                    "status": "active *",
                    "type": "Virtual Supervisor Module"
                }
            ],
            "net_neighbors": {},
            "net_platform": "N9K-C9500v",
            "net_python_version": "3.9.5",
            "net_serialnum": "9ESGSKDKPR0",
            "net_system": "nxos",
            "net_version": "9.3(3)",
            "net_vlan_list": [
                "1"
            ],
            "network_resources": {},
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * net__hostname: 192.168.1.19
>  * net__os: 9.3(3)
>  * net__platform: Nexus9000 C9500v Chassis
>  * net_api: cliconf
>  * net_config: !Command: show running-config
>!Running configuration last done at: Sat Jul 10 23:00:14 2021
>!Time: Sat Jul 10 23:00:57 2021
>
>version 9.3(3) Bios:version  
>hostname 192.168.1.19
>vdc 192.168.1.19 id 1
>  limit-resource vlan minimum 16 maximum 4094
>  limit-resource vrf minimum 2 maximum 4096
>  limit-resource port-channel minimum 0 maximum 511
>  limit-resource u4route-mem minimum 248 maximum 248
>  limit-resource u6route-mem minimum 96 maximum 96
>  limit-resource m4route-mem minimum 58 maximum 58
>  limit-resource m6route-mem minimum 8 maximum 8
>
>nv overlay evpn
>feature bfd
>clock protocol none vdc 1
>
>username admin password 5 $5$GYWPMp8g$uCosvTBewY0RcsJx/XB4e92DceRU8J4mvDI1JztQtG3  role network-admin
>ip domain-lookup
>radius-server timeout 9
>radius-server deadtime 20
>radius-server host 1.2.3.4 acct-port 2084 authentication accounting timeout 10 
>system default switchport
>ip access-list ANSIBLE
>  10 permit tcp 192.0.2.1/24 any 
>bfd interval 50 min_rx 50 multiplier 4
>snmp-server user admin network-admin auth md5 0x4f14136eab1027c832da1709141f5070 priv 0x4f14136eab1027c832da1709141f5070 localizedkey
>rmon event 1 description FATAL(1) owner PMON@FATAL
>rmon event 2 description CRITICAL(2) owner PMON@CRITICAL
>rmon event 3 description ERROR(3) owner PMON@ERROR
>rmon event 4 description WARNING(4) owner PMON@WARNING
>rmon event 5 description INFORMATION(5) owner PMON@INFO
>radius-server directed-request 
>
>vlan 1
>
>vrf context management
>  ip domain-name lan
>  ip name-server 192.168.1.1
>  ip route 0.0.0.0/0 192.168.1.1
>
>interface Ethernet1/1
>
>
>interface mgmt0
>  description DHCP Configuration for PnP
>  vrf member management
>  ip address 192.168.1.19/24
>line console
>line vty
>no system default switchport shutdown
>
>  * net_hostname: 192.168.1.19
>  * net_image: bootflash:///nxos.9.3.3.bin
>  * net_license_hostid: 91EMAC025KL
>  * net_memfree_mb: 3965.3359375
>  * net_memtotal_mb: 7653.41015625
>  * net_model: Nexus9000 C9500v Chassis ("Supervisor Module")
>  * net_platform: N9K-C9500v
>  * net_python_version: 3.9.5
>  * net_serialnum: 9ESGSKDKPR0
>  * net_system: nxos
>  * net_version: 9.3(3)
>  * discovered_interpreter_python: /usr/local/bin/python
>  * ## Net_All_Ipv4_Addresses
>    * 0: 192.168.1.19
>  * ## Net_All_Ipv6_Addresses
>  * ## Net_Fan_Info
>  * ## Net_Features_Enabled
>    * 0: bfd
>  * ## Net_Filesystems
>    * 0: bootflash:
>  * ## Net_Gather_Network_Resources
>  * ## Net_Gather_Subset
>    * 0: interfaces
>    * 1: config
>    * 2: hardware
>    * 3: legacy
>    * 4: default
>    * 5: features
>  * ## Net_Interfaces
>    * ### Ethernet1/1
>      * bandwidth: 1000000
>      * duplex: full
>      * macaddress: 0cc2.8a00.0101
>      * mode: access
>      * mtu: 1500
>      * speed: 1000 Mb/s
>      * state: up
>      * type: 100/1000/10000 Ethernet
>    * ### Mgmt0
>      * bandwidth: 1000000
>      * description: DHCP Configuration for PnP
>      * duplex: full
>      * macaddress: 0c05.2bc2.8a00
>      * mtu: 1500
>      * speed: 1000 Mb/s
>      * state: up
>      * type: GigabitEthernet
>      * #### Ipv4
>        * address: 192.168.1.19
>        * masklen: 24
>  * ## Net_Interfaces_List
>    * 0: mgmt0
>    * 1: Ethernet1/1
>  * ## Net_Module
>  * ## List
>    * model: N9K-X9564v
>    * ports: 64
>    * status: ok
>    * type: Nexus 9000v 64 port Ethernet Module
>  * ## List
>    * model: N9K-vSUP
>    * ports: 0
>    * status: active *
>    * type: Virtual Supervisor Module
>  * ## Net_Neighbors
>  * ## Net_Vlan_List
>    * 0: 1
>  * ## Network_Resources


### nxos-feature
***
Manage features in NX-OS switches.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_feature_module.html


#### Base Command

`nxos-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| feature | Name of feature. | Required | 
| state | Desired state of the feature. Possible values are: enabled, disabled. Default is enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosFeature.commands | unknown | The set of commands to be sent to the remote device | 


#### Command Example
```!nxos-feature host="192.168.1.19" feature="lacp" state="enabled" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosFeature": {
            "changed": true,
            "commands": [
                "terminal dont-ask",
                "feature lacp"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: terminal dont-ask
>    * 1: feature lacp


### nxos-gir
***
Trigger a graceful removal or insertion (GIR) of the switch.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_gir_module.html


#### Base Command

`nxos-gir`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| system_mode_maintenance | When `system_mode_maintenance=true` it puts all enabled protocols in maintenance mode (using the isolate command). When `system_mode_maintenance=false` it puts all enabled protocols in normal mode (using the no isolate command). | Optional | 
| system_mode_maintenance_dont_generate_profile | When `system_mode_maintenance_dont_generate_profile=true` it prevents the dynamic searching of enabled protocols and executes commands configured in a maintenance-mode profile. Use this option if you want the system to use a maintenance-mode profile that you have created. When `system_mode_maintenance_dont_generate_profile=false` it prevents the dynamic searching of enabled protocols and executes commands configured in a normal-mode profile. Use this option if you want the system to use a normal-mode profile that you have created. | Optional | 
| system_mode_maintenance_timeout | Keeps the switch in maintenance mode for a specified number of minutes. Range is 5-65535. | Optional | 
| system_mode_maintenance_shutdown | Shuts down all protocols, vPC domains, and interfaces except the management interface (using the shutdown command). This option is disruptive while `system_mode_maintenance` (which uses the isolate command) is not. | Optional | 
| system_mode_maintenance_on_reload_reset_reason | Boots the switch into maintenance mode automatically in the event of a specified system crash. Note that not all reset reasons are applicable for all platforms. Also if reset reason is set to match_any, it is not idempotent as it turns on all reset reasons. If reset reason is match_any and state is absent, it turns off all the reset reasons. Possible values are: hw_error, svc_failure, kern_failure, wdog_timeout, fatal_error, lc_failure, match_any, manual_reload, any_other, maintenance. | Optional | 
| state | Specify desired state of the resource. Possible values are: present, absent. Default is present. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosGir.final_system_mode | string | describe the last system mode | 
| CiscoNXOS.NxosGir.updates | unknown | commands sent to the device | 
| CiscoNXOS.NxosGir.changed | boolean | check to see if a change was made on the device | 


#### Command Example
```!nxos-gir host="192.168.1.19" system_mode_maintenance="True"```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosGir": {
            "changed": true,
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True


### nxos-gir-profile-management
***
Create a maintenance-mode or normal-mode profile for GIR.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_gir_profile_management_module.html


#### Base Command

`nxos-gir-profile-management`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| commands | List of commands to be included into the profile. | Optional | 
| mode | Configure the profile as Maintenance or Normal mode. Possible values are: maintenance, normal. | Required | 
| state | Specify desired state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosGirProfileManagement.proposed | unknown | list of commands passed into module. | 
| CiscoNXOS.NxosGirProfileManagement.existing | unknown | list of existing profile commands. | 
| CiscoNXOS.NxosGirProfileManagement.end_state | unknown | list of profile entries after module execution. | 
| CiscoNXOS.NxosGirProfileManagement.updates | unknown | commands sent to the device | 
| CiscoNXOS.NxosGirProfileManagement.changed | boolean | check to see if a change was made on the device | 


#### Command Example
```!nxos-gir-profile-management host="192.168.1.19" mode="maintenance" commands="{{ ['router eigrp 11', 'isolate'] }}" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosGirProfileManagement": {
            "changed": true,
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True

### nxos-hsrp
***
Manages HSRP configuration on NX-OS switches.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_hsrp_module.html


#### Base Command

`nxos-hsrp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| group | HSRP group number. | Required | 
| interface | Full name of interface that is being managed for HSRP. | Required | 
| version | HSRP version. Possible values are: 1, 2. Default is 1. | Optional | 
| priority | HSRP priority or keyword 'default'. | Optional | 
| preempt | Enable/Disable preempt. Possible values are: enabled, disabled. | Optional | 
| vip | HSRP virtual IP address or keyword 'default'. | Optional | 
| auth_string | Authentication string. If this needs to be hidden(for md5 type), the string should be 7 followed by the key string. Otherwise, it can be 0 followed by key string or just key string (for backward compatibility). For text type, this should be just be a key string. if this is 'default', authentication is removed. | Optional | 
| auth_type | Authentication type. Possible values are: text, md5. | Optional | 
| state | Specify desired state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosHsrp.commands | unknown | commands sent to the device | 



### nxos-igmp
***
Manages IGMP global configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_igmp_module.html


#### Base Command

`nxos-igmp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| flush_routes | Removes routes when the IGMP process is restarted. By default, routes are not flushed. | Optional | 
| enforce_rtr_alert | Enables or disables the enforce router alert option check for IGMPv2 and IGMPv3 packets. | Optional | 
| restart | Restarts the igmp process (using an exec config command). | Optional | 
| state | Manages desired state of the resource. Possible values are: present, default. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosIgmp.updates | unknown | commands sent to the device | 


#### Command Example
```!nxos-igmp host="192.168.1.19" state="default" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosIgmp": {
            "changed": false,
            "host": "192.168.1.19",
            "status": "SUCCESS",
            "updates": []
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Updates


### nxos-igmp-interface
***
Manages IGMP interface configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_igmp_interface_module.html


#### Base Command

`nxos-igmp-interface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| interface | The full interface name for IGMP configuration. e.g. `Ethernet1/2`. | Required | 
| version | IGMP version. It can be 2 or 3 or keyword 'default'. Possible values are: 2, 3, default. | Optional | 
| startup_query_interval | Query interval used when the IGMP process starts up. The range is from 1 to 18000 or keyword 'default'. The default is 31. | Optional | 
| startup_query_count | Query count used when the IGMP process starts up. The range is from 1 to 10 or keyword 'default'. The default is 2. | Optional | 
| robustness | Sets the robustness variable. Values can range from 1 to 7 or keyword 'default'. The default is 2. | Optional | 
| querier_timeout | Sets the querier timeout that the software uses when deciding to take over as the querier. Values can range from 1 to 65535 seconds or keyword 'default'. The default is 255 seconds. | Optional | 
| query_mrt | Sets the response time advertised in IGMP queries. Values can range from 1 to 25 seconds or keyword 'default'. The default is 10 seconds. | Optional | 
| query_interval | Sets the frequency at which the software sends IGMP host query messages. Values can range from 1 to 18000 seconds or keyword 'default'. The default is 125 seconds. | Optional | 
| last_member_qrt | Sets the query interval waited after sending membership reports before the software deletes the group state. Values can range from 1 to 25 seconds or keyword 'default'. The default is 1 second. | Optional | 
| last_member_query_count | Sets the number of times that the software sends an IGMP query in response to a host leave message. Values can range from 1 to 5 or keyword 'default'. The default is 2. | Optional | 
| group_timeout | Sets the group membership timeout for IGMPv2. Values can range from 3 to 65,535 seconds or keyword 'default'. The default is 260 seconds. | Optional | 
| report_llg | Configures report-link-local-groups. Enables sending reports for groups in 224.0.0.0/24. Reports are always sent for nonlink local groups. By default, reports are not sent for link local groups. | Optional | 
| immediate_leave | Enables the device to remove the group entry from the multicast routing table immediately upon receiving a leave message for the group. Use this command to minimize the leave latency of IGMPv2 group memberships on a given IGMP interface because the device does not send group-specific queries. The default is disabled. | Optional | 
| oif_routemap | Configure a routemap for static outgoing interface (OIF) or keyword 'default'. | Optional | 
| oif_prefix | This argument is deprecated, please use oif_ps instead. Configure a prefix for static outgoing interface (OIF). | Optional | 
| oif_source | This argument is deprecated, please use oif_ps instead. Configure a source for static outgoing interface (OIF). | Optional | 
| oif_ps | Configure prefixes and sources for static outgoing interface (OIF). This is a list of dict where each dict has source and prefix defined or just prefix if source is not needed. The specified values will be configured on the device and if any previous prefix/sources exist, they will be removed. Keyword 'default' is also accepted which removes all existing prefix/sources. | Optional | 
| restart | Restart IGMP. This is NOT idempotent as this is action only. Possible values are: Yes, No. Default is No. | Optional | 
| state | Manages desired state of the resource. Possible values are: present, absent, default. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosIgmpInterface.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosIgmpInterface.existing | unknown | k/v pairs of existing igmp_interface configuration | 
| CiscoNXOS.NxosIgmpInterface.end_state | unknown | k/v pairs of igmp interface configuration after module execution | 
| CiscoNXOS.NxosIgmpInterface.updates | unknown | commands sent to the device | 
| CiscoNXOS.NxosIgmpInterface.changed | boolean | check to see if a change was made on the device | 



### nxos-igmp-snooping
***
Manages IGMP snooping global configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_igmp_snooping_module.html


#### Base Command

`nxos-igmp-snooping`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| snooping | Enables/disables IGMP snooping on the switch. | Optional | 
| group_timeout | Group membership timeout value for all VLANs on the device. Accepted values are integer in range 1-10080, `never` and `default`. | Optional | 
| link_local_grp_supp | Global link-local groups suppression. | Optional | 
| report_supp | Global IGMPv1/IGMPv2 Report Suppression. | Optional | 
| v3_report_supp | Global IGMPv3 Report Suppression and Proxy Reporting. | Optional | 
| state | Manage the state of the resource. Possible values are: present, default. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosIgmpSnooping.commands | unknown | command sent to the device | 


#### Command Example
```!nxos-igmp-snooping host="192.168.1.19" state="default" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosIgmpSnooping": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands


### nxos-install-os
***
Set boot options like boot, kickstart image and issu.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_install_os_module.html


#### Base Command

`nxos-install-os`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| system_image_file | Name of the system (or combined) image file on flash. | Required | 
| kickstart_image_file | Name of the kickstart image file on flash. (Not required on all Nexus platforms). | Optional | 
| issu | Upgrade using In Service Software Upgrade (ISSU). (Supported on N5k, N7k, N9k platforms) Selecting 'required' or 'yes' means that upgrades will only proceed if the switch is capable of ISSU. Selecting 'desired' means that upgrades will use ISSU if possible but will fall back to disruptive upgrade if needed. Selecting 'no' means do not use ISSU. Forced disruptive. Possible values are: required, desired, yes, no. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosInstallOs.install_state | unknown | Boot and install information. | 



### nxos-interface-ospf
***
Manages configuration of an OSPF interface instance.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_interface_ospf_module.html


#### Base Command

`nxos-interface-ospf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| interface | Name of this cisco_interface resource. Valid value is a string. | Required | 
| ospf | Name of the ospf instance. | Required | 
| area | Ospf area associated with this cisco_interface_ospf instance. Valid values are a string, formatted as an IP address (i.e. "0.0.0.0") or as an integer. | Required | 
| bfd | Enables bfd at interface level. This overrides the bfd variable set at the ospf router level. Valid values are 'enable', 'disable' or 'default'. Dependency: 'feature bfd'. Possible values are: enable, disable, default. | Optional | 
| cost | The cost associated with this cisco_interface_ospf instance. | Optional | 
| hello_interval | Time between sending successive hello packets. Valid values are an integer or the keyword 'default'. | Optional | 
| dead_interval | Time interval an ospf neighbor waits for a hello packet before tearing down adjacencies. Valid values are an integer or the keyword 'default'. | Optional | 
| passive_interface | Enable or disable passive-interface state on this interface. true - (enable) Prevent OSPF from establishing an adjacency or sending routing updates on this interface. false - (disable) Override global 'passive-interface default' for this interface. | Optional | 
| network | Specifies interface ospf network type. Valid values are 'point-to-point' or 'broadcast'. Possible values are: point-to-point, broadcast. | Optional | 
| message_digest | Enables or disables the usage of message digest authentication. | Optional | 
| message_digest_key_id | Md5 authentication key-id associated with the ospf instance. If this is present, message_digest_encryption_type, message_digest_algorithm_type and message_digest_password are mandatory. Valid value is an integer and 'default'. | Optional | 
| message_digest_algorithm_type | Algorithm used for authentication among neighboring routers within an area. Valid values are 'md5' and 'default'. Possible values are: md5, default. | Optional | 
| message_digest_encryption_type | Specifies the scheme used for encrypting message_digest_password. Valid values are '3des' or 'cisco_type_7' encryption or 'default'. Possible values are: cisco_type_7, 3des, default. | Optional | 
| message_digest_password | Specifies the message_digest password. Valid value is a string. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosInterfaceOspf.commands | unknown | commands sent to the device | 



### nxos-interfaces
***
Manages interface attributes of NX-OS Interfaces
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_interfaces_module.html


#### Base Command

`nxos-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of interface options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosInterfaces.commands | unknown | The set of commands pushed to the remote device. | 

#### Command Example
```!nxos-interfaces host="192.168.1.19" config="{{ [{'name': 'Ethernet1/1', 'description': 'Configured by Ansible', 'enabled': True}, {'name': 'Ethernet1/2', 'description': 'Configured by Ansible Network', 'enabled': False}] }}" state="merged" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosInterfaces": {
            "before": [
                {
                    "description": "Configured by Ansible",
                    "name": "Ethernet1/1"
                },
                {
                    "description": "Configured by Ansible Network",
                    "enabled": false,
                    "name": "Ethernet1/2"
                },
                {
                    "name": "Ethernet1/3"
                },
                {
                    "name": "Ethernet1/4"
                },
                {
                    "name": "mgmt0"
                }
            ],
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Before
>  * ## Ethernet1/1
>    * description: Configured by Ansible
>    * name: Ethernet1/1
>  * ## Ethernet1/2
>    * description: Configured by Ansible Network
>    * enabled: False
>    * name: Ethernet1/2
>  * ## Ethernet1/3
>    * name: Ethernet1/3
>  * ## Ethernet1/4
>    * name: Ethernet1/4
>  * ## Mgmt0
>    * name: mgmt0
>  * ## Commands



### nxos-l2-interfaces
***
Manages Layer-2 Interfaces attributes of NX-OS Interfaces
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_l2_interfaces_module.html


#### Base Command

`nxos-l2-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of Layer-2 interface options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosL2Interfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosL2Interfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosL2Interfaces.commands | unknown | The set of commands pushed to the remote device. | 

#### Command Example
```!nxos-l2-interfaces host="192.168.1.19" config="{{ [{'name': 'Ethernet1/1', 'trunk': {'native_vlan': 10, 'allowed_vlans': '2,4,15'}}, {'name': 'Ethernet1/2', 'access': {'vlan': 30}}] }}" state="merged" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosL2Interfaces": {
            "before": [
                {
                    "name": "Ethernet1/1",
                    "trunk": {
                        "allowed_vlans": "2,4,15",
                        "native_vlan": 10
                    }
                },
                {
                    "access": {
                        "vlan": 30
                    },
                    "name": "Ethernet1/2"
                },
                {
                    "name": "Ethernet1/3"
                },
                {
                    "name": "Ethernet1/4"
                },
                {
                    "name": "Ethernet1/5"
                },
                {
                    "name": "mgmt0"
                }
            ],
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Before
>  * ## Ethernet1/1
>    * name: Ethernet1/1
>    * ### Trunk
>      * allowed_vlans: 2,4,15
>      * native_vlan: 10
>  * ## Ethernet1/2
>    * name: Ethernet1/2
>    * ### Access
>      * vlan: 30
>  * ## Ethernet1/3
>    * name: Ethernet1/3
>  * ## Ethernet1/4
>    * name: Ethernet1/4
>  * ## Ethernet1/5
>    * name: Ethernet1/5
>  * ## Mgmt0
>    * name: mgmt0
>  * ## Commands



### nxos-l3-interfaces
***
Manages Layer-3 Interfaces attributes of NX-OS Interfaces
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_l3_interfaces_module.html


#### Base Command

`nxos-l3-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of Layer-3 interface options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosL3Interfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosL3Interfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosL3Interfaces.commands | unknown | The set of commands pushed to the remote device. | 



### nxos-lacp
***
Manage Global Link Aggregation Control Protocol (LACP) on Cisco NX-OS devices.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_lacp_module.html


#### Base Command

`nxos-lacp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | LACP global options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosLacp.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosLacp.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosLacp.commands | unknown | The set of commands pushed to the remote device. | 


#### Command Example
```!nxos-lacp host="192.168.1.19" config="{'system': {'priority': 10, 'mac': {'address': '00c1.4c00.bd15'}}}" state="merged" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosLacp": {
            "after": {
                "system": {
                    "mac": {
                        "address": "00c1.4c00.bd15",
                        "role": "primary"
                    },
                    "priority": 10
                }
            },
            "before": {},
            "changed": true,
            "commands": [
                "lacp system-priority 10",
                "lacp system-mac 00c1.4c00.bd15"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## After
>    * ### System
>      * priority: 10
>      * #### Mac
>        * address: 00c1.4c00.bd15
>        * role: primary
>  * ## Before
>  * ## Commands
>    * 0: lacp system-priority 10
>    * 1: lacp system-mac 00c1.4c00.bd15


### nxos-lacp-interfaces
***
Manage Link Aggregation Control Protocol (LACP) attributes of interfaces on Cisco NX-OS devices.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_lacp_interfaces_module.html


#### Base Command

`nxos-lacp-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of LACP interfaces options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosLacpInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosLacpInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosLacpInterfaces.commands | unknown | The set of commands pushed to the remote device. | 



### nxos-lag-interfaces
***
Manages link aggregation groups of NX-OS Interfaces
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_lag_interfaces_module.html


#### Base Command

`nxos-lag-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A list of link aggregation group configurations. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosLagInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosLagInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosLagInterfaces.commands | unknown | The set of commands pushed to the remote device. | 


#### Command Example
```!nxos-lag-interfaces host="192.168.1.19" config="{{ [{'name': 'port-channel99', 'members': [{'member': 'Ethernet1/4'}]}] }}" state="merged" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosLagInterfaces": {
            "after": [
                {
                    "members": [
                        {
                            "member": "Ethernet1/4"
                        }
                    ],
                    "name": "port-channel99"
                }
            ],
            "before": [],
            "changed": true,
            "commands": [
                "interface Ethernet1/4",
                "channel-group 99"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## After
>  * ## Port-Channel99
>    * name: port-channel99
>    * ### Members
>    * ### List
>      * member: Ethernet1/4
>  * ## Before
>  * ## Commands
>    * 0: interface Ethernet1/4
>    * 1: channel-group 99


### nxos-lldp
***
Manage LLDP configuration on Cisco NXOS network devices.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_lldp_module.html


#### Base Command

`nxos-lldp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | State of the LLDP configuration. If value is `present` lldp will be enabled else if it is `absent` it will be disabled. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosLldp.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!nxos-lldp host="192.168.1.19" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosLldp": {
            "changed": true,
            "commands": [
                "terminal dont-ask",
                "feature lldp"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: terminal dont-ask
>    * 1: feature lldp


### nxos-lldp-global
***
Configure and manage Link Layer Discovery Protocol(LLDP) attributes on NX-OS platforms.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_lldp_global_module.html


#### Base Command

`nxos-lldp-global`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A list of link layer discovery configurations. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosLldpGlobal.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosLldpGlobal.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosLldpGlobal.commands | unknown | The set of commands pushed to the remote device. | 


#### Command Example
```!nxos-lldp-global host="192.168.1.19" config="{'timer': 35, 'holdtime': 100}" state="merged" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosLldpGlobal": {
            "after": {
                "holdtime": 100,
                "timer": 35
            },
            "before": {},
            "changed": true,
            "commands": [
                "lldp holdtime 100",
                "lldp timer 35"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## After
>    * holdtime: 100
>    * timer: 35
>  * ## Before
>  * ## Commands
>    * 0: lldp holdtime 100
>    * 1: lldp timer 35


### nxos-logging
***
Manage logging on network devices
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_logging_module.html


#### Base Command

`nxos-logging`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dest | Destination of the logs. Possible values are: console, logfile, module, monitor, server. | Optional | 
| remote_server | Hostname or IP Address for remote logging (when dest is 'server'). | Optional | 
| use_vrf | VRF to be used while configuring remote logging (when dest is 'server'). | Optional | 
| interface | Interface to be used while configuring source-interface for logging (e.g., 'Ethernet1/2', 'mgmt0'). | Optional | 
| name | If value of `dest` is `logfile` it indicates file-name. | Optional | 
| facility | Facility name for logging. | Optional | 
| dest_level | Set logging severity levels. | Optional | 
| facility_level | Set logging severity levels for facility based log messages. | Optional | 
| aggregate | List of logging definitions. | Optional | 
| state | State of the logging configuration. Possible values are: present, absent. Default is present. | Optional | 
| event | Link/trunk enable/default interface configuration logging. Possible values are: link-enable, link-default, trunk-enable, trunk-default. | Optional | 
| interface_message | Add interface description to interface syslogs. Does not work with version 6.0 images using nxapi as a transport. Possible values are: add-interface-description. | Optional | 
| file_size | Set logfile size. | Optional | 
| facility_link_status | Set logging facility ethpm link status. Not idempotent with version 6.0 images. Possible values are: link-down-notif, link-down-error, link-up-notif, link-up-error. | Optional | 
| timestamp | Set logging timestamp format. Possible values are: microseconds, milliseconds, seconds. | Optional | 
| purge | Remove any switch logging configuration that does not match what has been configured Not supported for connection local. All nxos_logging tasks must use the same connection type. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosLogging.commands | unknown | The list of configuration mode commands to send to the device | 



### nxos-ntp
***
Manages core NTP configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_ntp_module.html


#### Base Command

`nxos-ntp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| server | Network address of NTP server. | Optional | 
| peer | Network address of NTP peer. | Optional | 
| key_id | Authentication key identifier to use with given NTP server or peer or keyword 'default'. | Optional | 
| prefer | Makes given NTP server or peer the preferred NTP server or peer for the device. Possible values are: enabled, disabled. | Optional | 
| vrf_name | Makes the device communicate with the given NTP server or peer over a specific VRF or keyword 'default'. | Optional | 
| source_addr | Local source address from which NTP messages are sent or keyword 'default'. | Optional | 
| source_int | Local source interface from which NTP messages are sent. Must be fully qualified interface name or keyword 'default'. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosNtp.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosNtp.existing | unknown | k/v pairs of existing ntp server/peer | 
| CiscoNXOS.NxosNtp.end_state | unknown | k/v pairs of ntp info after module execution | 
| CiscoNXOS.NxosNtp.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosNtp.changed | boolean | check to see if a change was made on the device | 


#### Command Example
```!nxos-ntp host="192.168.1.19" server="1.2.3.4" key_id="32" prefer="enabled"```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosNtp": {
            "changed": true,
            "end_state": {
                "address": "1.2.3.4",
                "key_id": "32",
                "peer_type": "server",
                "prefer": "enabled",
                "vrf_name": "default"
            },
            "existing": {},
            "host": "192.168.1.19",
            "peer_server_list": [],
            "proposed": {
                "address": "1.2.3.4",
                "key_id": "32",
                "peer_type": "server",
                "prefer": "enabled"
            },
            "status": "CHANGED",
            "updates": [
                "ntp server 1.2.3.4 prefer key 32"
            ]
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## End_State
>    * address: 1.2.3.4
>    * key_id: 32
>    * peer_type: server
>    * prefer: enabled
>    * vrf_name: default
>  * ## Existing
>  * ## Peer_Server_List
>  * ## Proposed
>    * address: 1.2.3.4
>    * key_id: 32
>    * peer_type: server
>    * prefer: enabled
>  * ## Updates
>    * 0: ntp server 1.2.3.4 prefer key 32


### nxos-ntp-auth
***
Manages NTP authentication.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_ntp_auth_module.html


#### Base Command

`nxos-ntp-auth`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| key_id | Authentication key identifier (numeric). | Optional | 
| md5string | MD5 String. | Optional | 
| auth_type | Whether the given md5string is in cleartext or has been encrypted. If in cleartext, the device will encrypt it before storing it. Possible values are: text, encrypt. Default is text. | Optional | 
| trusted_key | Whether the given key is required to be supplied by a time source for the device to synchronize to the time source. Possible values are: false, true. Default is false. | Optional | 
| authentication | Turns NTP authentication on or off. Possible values are: on, off. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosNtpAuth.commands | unknown | command sent to the device | 


#### Command Example
```!nxos-ntp-auth host="192.168.1.19" key_id="32" md5string="hello" auth_type="text" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosNtpAuth": {
            "changed": true,
            "end_state": {
                "auth_type": "encrypt",
                "authentication": "off",
                "key_id": "32",
                "md5string": "kapqg",
                "trusted_key": "false"
            },
            "existing": {
                "authentication": "off",
                "trusted_key": "false"
            },
            "host": "192.168.1.19",
            "proposed": {
                "auth_type": "text",
                "key_id": "32",
                "md5string": "hello",
                "trusted_key": "false"
            },
            "status": "CHANGED",
            "updates": [
                "ntp authentication-key 32 md5 hello 0"
            ]
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## End_State
>    * auth_type: encrypt
>    * authentication: off
>    * key_id: 32
>    * md5string: kapqg
>    * trusted_key: false
>  * ## Existing
>    * authentication: off
>    * trusted_key: false
>  * ## Proposed
>    * auth_type: text
>    * key_id: 32
>    * md5string: hello
>    * trusted_key: false
>  * ## Updates
>    * 0: ntp authentication-key 32 md5 hello 0


### nxos-ntp-options
***
Manages NTP options.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_ntp_options_module.html


#### Base Command

`nxos-ntp-options`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| master | Sets whether the device is an authoritative NTP server. | Optional | 
| stratum | If `master=true`, an optional stratum can be supplied (1-15). The device default is 8. | Optional | 
| logging | Sets whether NTP logging is enabled on the device. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosNtpOptions.updates | unknown | command sent to the device | 


#### Command Example
```!nxos-ntp-options host="192.168.1.19" master="True" stratum="12" logging="False"```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosNtpOptions": {
            "changed": true,
            "commands": [
                "ntp master",
                "ntp master 12"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED",
            "updates": [
                "ntp master",
                "ntp master 12"
            ]
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: ntp master
>    * 1: ntp master 12
>  * ## Updates
>    * 0: ntp master
>    * 1: ntp master 12


### nxos-nxapi
***
Manage NXAPI configuration on an NXOS device.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_nxapi_module.html


#### Base Command

`nxos-nxapi`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| http_port | Configure the port with which the HTTP server will listen on for requests.  By default, NXAPI will bind the HTTP service to the standard HTTP port 80.  This argument accepts valid port values in the range of 1 to 65535. Default is 80. | Optional | 
| http | Controls the operating state of the HTTP protocol as one of the underlying transports for NXAPI.  By default, NXAPI will enable the HTTP transport when the feature is first configured.  To disable the use of the HTTP transport, set the value of this argument to False. Possible values are: Yes, No. Default is Yes. | Optional | 
| https_port | Configure the port with which the HTTPS server will listen on for requests.  By default, NXAPI will bind the HTTPS service to the standard HTTPS port 443.  This argument accepts valid port values in the range of 1 to 65535. Default is 443. | Optional | 
| https | Controls the operating state of the HTTPS protocol as one of the underlying transports for NXAPI.  By default, NXAPI will disable the HTTPS transport when the feature is first configured.  To enable the use of the HTTPS transport, set the value of this argument to True. Possible values are: Yes, No. Default is No. | Optional | 
| sandbox | The NXAPI feature provides a web base UI for developers for entering commands.  This feature is initially disabled when the NXAPI feature is configured for the first time.  When the `sandbox` argument is set to True, the developer sandbox URL will accept requests and when the value is set to False, the sandbox URL is unavailable. This is supported on NX-OS 7K series. Possible values are: Yes, No. Default is No. | Optional | 
| state | The `state` argument controls whether or not the NXAPI feature is configured on the remote device.  When the value is `present` the NXAPI feature configuration is present in the device running-config.  When the values is `absent` the feature configuration is removed from the running-config. Possible values are: present, absent. Default is present. | Optional | 
| ssl_strong_ciphers | Controls the use of whether strong or weak ciphers are configured. By default, this feature is disabled and weak ciphers are configured.  To enable the use of strong ciphers, set the value of this argument to True. Possible values are: Yes, No. Default is No. | Optional | 
| tlsv1_0 | Controls the use of the Transport Layer Security version 1.0 is configured.  By default, this feature is enabled.  To disable the use of TLSV1.0, set the value of this argument to True. Possible values are: Yes, No. Default is Yes. | Optional | 
| tlsv1_1 | Controls the use of the Transport Layer Security version 1.1 is configured.  By default, this feature is disabled.  To enable the use of TLSV1.1, set the value of this argument to True. Possible values are: Yes, No. Default is No. | Optional | 
| tlsv1_2 | Controls the use of the Transport Layer Security version 1.2 is configured.  By default, this feature is disabled.  To enable the use of TLSV1.2, set the value of this argument to True. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosNxapi.updates | unknown | Returns the list of commands that need to be pushed into the remote device to satisfy the arguments | 


#### Command Example
```!nxos-nxapi host="192.168.1.19" state="present" sandbox=No```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosNxapi": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-ospf
***
Manages configuration of an ospf instance.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_ospf_module.html


#### Base Command

`nxos-ospf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| ospf | Name of the ospf instance. | Required | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosOspf.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-ospf host="192.168.1.19" ospf="1" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosOspf": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands


### nxos-ospf-vrf
***
Manages a VRF for an OSPF router.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_ospf_vrf_module.html


#### Base Command

`nxos-ospf-vrf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| vrf | Name of the resource instance. Valid value is a string. The name 'default' is a valid VRF representing the global OSPF. Default is default. | Optional | 
| ospf | Name of the OSPF instance. | Required | 
| router_id | Router Identifier (ID) of the OSPF router VRF instance. | Optional | 
| default_metric | Specify the default Metric value. Valid values are an integer or the keyword 'default'. | Optional | 
| log_adjacency | Controls the level of log messages generated whenever a neighbor changes state. Valid values are 'log', 'detail', and 'default'. Possible values are: log, detail, default. | Optional | 
| timer_throttle_lsa_start | Specify the start interval for rate-limiting Link-State Advertisement (LSA) generation. Valid values are an integer, in milliseconds, or the keyword 'default'. | Optional | 
| timer_throttle_lsa_hold | Specify the hold interval for rate-limiting Link-State Advertisement (LSA) generation. Valid values are an integer, in milliseconds, or the keyword 'default'. | Optional | 
| timer_throttle_lsa_max | Specify the max interval for rate-limiting Link-State Advertisement (LSA) generation. Valid values are an integer, in milliseconds, or the keyword 'default'. | Optional | 
| timer_throttle_spf_start | Specify initial Shortest Path First (SPF) schedule delay. Valid values are an integer, in milliseconds, or the keyword 'default'. | Optional | 
| timer_throttle_spf_hold | Specify minimum hold time between Shortest Path First (SPF) calculations. Valid values are an integer, in milliseconds, or the keyword 'default'. | Optional | 
| timer_throttle_spf_max | Specify the maximum wait time between Shortest Path First (SPF) calculations. Valid values are an integer, in milliseconds, or the keyword 'default'. | Optional | 
| auto_cost | Specifies the reference bandwidth used to assign OSPF cost. Valid values are an integer, in Mbps, or the keyword 'default'. | Optional | 
| bfd | Enables BFD on all OSPF interfaces. Dependency: 'feature bfd'. Possible values are: enable, disable. | Optional | 
| passive_interface | Setting to `yes` will suppress routing update on interface. | Optional | 
| state | State of ospf vrf configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosOspfVrf.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-ospf-vrf host="192.168.1.19" ospf="1" timer_throttle_spf_start="50" timer_throttle_spf_hold="1000" timer_throttle_spf_max="2000" timer_throttle_lsa_start="60" timer_throttle_lsa_hold="1100" timer_throttle_lsa_max="3000" vrf="test" bfd="enable" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosOspfVrf": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-overlay-global
***
Configures anycast gateway MAC of the switch.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_overlay_global_module.html


#### Base Command

`nxos-overlay-global`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| anycast_gateway_mac | Anycast gateway mac of the switch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosOverlayGlobal.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-overlay-global host="192.168.1.19" anycast_gateway_mac="b.b.b" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosOverlayGlobal": {
            "changed": true,
            "commands": [
                "fabric forwarding anycast-gateway-mac 000B.000B.000B"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: fabric forwarding anycast-gateway-mac 000B.000B.000B


### nxos-pim
***
Manages configuration of a PIM instance.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_pim_module.html


#### Base Command

`nxos-pim`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| bfd | Enables BFD on all PIM interfaces. Dependency: 'feature bfd'. Possible values are: enable, disable. | Optional | 
| ssm_range | Configure group ranges for Source Specific Multicast (SSM). Valid values are multicast addresses or the keyword `none` or keyword `default`. `none` removes all SSM group ranges. `default` will set ssm_range to the default multicast address. If you set multicast address, please ensure that it is not the same as the `default`, otherwise use the `default` option. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosPim.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-pim host="192.168.1.19" bfd="enable" ssm_range="224.0.0.0/8"```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosPim": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-pim-interface
***
Manages PIM interface configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_pim_interface_module.html


#### Base Command

`nxos-pim-interface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| interface | Full name of the interface such as Ethernet1/33. | Required | 
| sparse | Enable/disable sparse-mode on the interface. Possible values are: Yes, No. Default is No. | Optional | 
| bfd | Enables BFD for PIM at the interface level. This overrides the bfd variable set at the pim global level. Valid values are 'enable', 'disable' or 'default'. Dependency: 'feature bfd'. Possible values are: enable, disable, default. | Optional | 
| dr_prio | Configures priority for PIM DR election on interface. | Optional | 
| hello_auth_key | Authentication for hellos on this interface. | Optional | 
| hello_interval | Hello interval in milliseconds for this interface. | Optional | 
| jp_policy_out | Policy for join-prune messages (outbound). | Optional | 
| jp_policy_in | Policy for join-prune messages (inbound). | Optional | 
| jp_type_out | Type of policy mapped to `jp_policy_out`. Possible values are: prefix, routemap. | Optional | 
| jp_type_in | Type of policy mapped to `jp_policy_in`. Possible values are: prefix, routemap. | Optional | 
| border | Configures interface to be a boundary of a PIM domain. Possible values are: Yes, No. Default is No. | Optional | 
| neighbor_policy | Configures a neighbor policy for filtering adjacencies. | Optional | 
| neighbor_type | Type of policy mapped to neighbor_policy. Possible values are: prefix, routemap. | Optional | 
| state | Manages desired state of the resource. Possible values are: present, default. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosPimInterface.commands | unknown | command sent to the device | 



### nxos-pim-rp-address
***
Manages configuration of an PIM static RP address instance.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_pim_rp_address_module.html


#### Base Command

`nxos-pim-rp-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| rp_address | Configures a Protocol Independent Multicast (PIM) static rendezvous point (RP) address. Valid values are unicast addresses. | Required | 
| group_list | Group range for static RP. Valid values are multicast addresses. | Optional | 
| prefix_list | Prefix list policy for static RP. Valid values are prefix-list policy names. | Optional | 
| route_map | Route map policy for static RP. Valid values are route-map policy names. | Optional | 
| bidir | Group range is treated in PIM bidirectional mode. | Optional | 
| state | Specify desired state of the resource. Possible values are: present, absent, default. Default is present. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosPimRpAddress.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-pim-rp-address host="192.168.1.19" rp_address="10.1.1.20" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosPimRpAddress": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-ping
***
Tests reachability using ping from Nexus switch.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_ping_module.html


#### Base Command

`nxos-ping`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dest | IP address or hostname (resolvable by switch) of remote node. | Required | 
| count | Number of packets to send. Default is 5. | Optional | 
| source | Source IP Address or hostname (resolvable by switch). | Optional | 
| vrf | Outgoing VRF. | Optional | 
| state | Determines if the expected result is success or fail. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosPing.commands | unknown | Show the command sent | 
| CiscoNXOS.NxosPing.rtt | unknown | Show RTT stats | 
| CiscoNXOS.NxosPing.packets_rx | number | Packets successfully received | 
| CiscoNXOS.NxosPing.packets_tx | number | Packets successfully transmitted | 
| CiscoNXOS.NxosPing.packet_loss | string | Percentage of packets lost | 


#### Command Example
```!nxos-ping host="192.168.1.19" dest="8.8.8.8" vrf="management"```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosPing": {
            "changed": false,
            "commands": [
                "ping 8.8.8.8 count 5 vrf management"
            ],
            "host": "192.168.1.19",
            "packet_loss": "0.00%",
            "packets_rx": 5,
            "packets_tx": 5,
            "rtt": {
                "avg": 11.171,
                "max": 11.845,
                "min": 10.811
            },
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * packet_loss: 0.00%
>  * packets_rx: 5
>  * packets_tx: 5
>  * ## Commands
>    * 0: ping 8.8.8.8 count 5 vrf management
>  * ## Rtt
>    * avg: 11.171
>    * max: 11.845
>    * min: 10.811


### nxos-reboot
***
Reboot a network device.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_reboot_module.html


#### Base Command

`nxos-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| confirm | Safeguard boolean. Set to true if you're sure you want to reboot. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosReboot.rebooted | boolean | Whether the device was instructed to reboot. | 


#### Command Example
```!nxos-reboot host="192.168.1.19" confirm="True" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosReboot": {
            "changed": true,
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True


### nxos-rollback
***
Set a checkpoint or rollback to a checkpoint.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_rollback_module.html


#### Base Command

`nxos-rollback`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| checkpoint_file | Name of checkpoint file to create. Mutually exclusive with rollback_to. | Optional | 
| rollback_to | Name of checkpoint file to rollback to. Mutually exclusive with checkpoint_file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosRollback.filename | string | The filename of the checkpoint/rollback file. | 
| CiscoNXOS.NxosRollback.status | string | Which operation took place and whether it was successful. | 


#### Command Example
```!nxos-rollback host="192.168.1.19" checkpoint_file="backup.cfg"```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosRollback": {
            "changed": true,
            "filename": "backup.cfg",
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * filename: backup.cfg
>  * status: checkpoint file created

### nxos-rpm
***
Install patch or feature rpms on Cisco NX-OS devices.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_rpm_module.html


#### Base Command

`nxos-rpm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| pkg | Name of the RPM package. | Required | 
| file_system | The remote file system of the device. If omitted, devices that support a file_system parameter will use their default values. Default is bootflash. | Optional | 
| aggregate | List of RPM/patch definitions. | Optional | 
| state | If the state is present, the rpm will be installed, If the state is absent, it will be removed. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosRpm.commands | unknown | commands sent to the device | 



### nxos-smu
***
Perform SMUs on Cisco NX-OS devices.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_smu_module.html


#### Base Command

`nxos-smu`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| pkg | Name of the remote package. | Required | 
| file_system | The remote file system of the device. If omitted, devices that support a file_system parameter will use their default values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSmu.commands | unknown | commands sent to the device | 



### nxos-snapshot
***
Manage snapshots of the running states of selected features.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snapshot_module.html


#### Base Command

`nxos-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| action | Define what snapshot action the module would perform. Possible values are: add, compare, create, delete, delete_all. | Required | 
| snapshot_name | Snapshot name, to be used when `action=create` or `action=delete`. | Optional | 
| description | Snapshot description to be used when `action=create`. | Optional | 
| snapshot1 | First snapshot to be used when `action=compare`. | Optional | 
| snapshot2 | Second snapshot to be used when `action=compare`. | Optional | 
| comparison_results_file | Name of the file where snapshots comparison will be stored when `action=compare`. | Optional | 
| compare_option | Snapshot options to be used when `action=compare`. Possible values are: summary, ipv4routes, ipv6routes. | Optional | 
| section | Used to name the show command output, to be used when `action=add`. | Optional | 
| show_command | Specify a new show command, to be used when `action=add`. | Optional | 
| row_id | Specifies the tag of each row entry of the show command's XML output, to be used when `action=add`. | Optional | 
| element_key1 | Specify the tags used to distinguish among row entries, to be used when `action=add`. | Optional | 
| element_key2 | Specify the tags used to distinguish among row entries, to be used when `action=add`. | Optional | 
| save_snapshot_locally | Specify to locally store a new created snapshot, to be used when `action=create`. Default is no. | Optional | 
| path | Specify the path of the file where new created snapshot or snapshots comparison will be stored, to be used when `action=create` and `save_snapshot_locally=true` or `action=compare`. Default is ./. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnapshot.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-snapshot host="192.168.1.19" action="create" snapshot_name="test_snapshot" description="Done with Ansible" save_snapshot_locally="True" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSnapshot": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-snmp-community
***
Manages SNMP community configs.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snmp_community_module.html


#### Base Command

`nxos-snmp-community`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| community | Case-sensitive community string. | Required | 
| access | Access type for community. Possible values are: ro, rw. | Optional | 
| group | Group to which the community belongs. | Optional | 
| acl | ACL name to filter snmp requests or keyword 'default'. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnmpCommunity.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-snmp-community host="192.168.1.19" community="TESTING7" group="network-operator" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSnmpCommunity": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-snmp-contact
***
Manages SNMP contact info.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snmp_contact_module.html


#### Base Command

`nxos-snmp-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| contact | Contact information. | Required | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnmpContact.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-snmp-contact host="192.168.1.19" contact="Test" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSnmpContact": {
            "changed": true,
            "commands": [
                "snmp-server contact Test"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: snmp-server contact Test


### nxos-snmp-host
***
Manages SNMP host configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snmp_host_module.html


#### Base Command

`nxos-snmp-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| snmp_host | IP address of hostname of target host. | Required | 
| version | SNMP version. If this is not specified, v1 is used. Possible values are: v1, v2c, v3. | Optional | 
| v3 | Use this when verion is v3. SNMPv3 Security level. Possible values are: noauth, auth, priv. | Optional | 
| community | Community string or v3 username. | Optional | 
| udp | UDP port number (0-65535). Default is 162. | Optional | 
| snmp_type | type of message to send to host. If this is not specified, trap type is used. Possible values are: trap, inform. | Optional | 
| vrf | VRF to use to source traffic to source. If state = absent, the vrf is removed. | Optional | 
| vrf_filter | Name of VRF to filter. If state = absent, the vrf is removed from the filter. | Optional | 
| src_intf | Source interface. Must be fully qualified interface name. If state = absent, the interface is removed. | Optional | 
| state | Manage the state of the resource. If state = present, the host is added to the configuration. If only vrf and/or vrf_filter and/or src_intf are given, they will be added to the existing host configuration. If state = absent, the host is removed if community parameter is given. It is possible to remove only vrf and/or src_int and/or vrf_filter by providing only those parameters and no community parameter. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnmpHost.commands | unknown | commands sent to the device | 

#### Command Example
```!nxos-snmp-host host="192.168.1.19" snmp_host="1.1.1.1" community="TESTING" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSnmpHost": {
            "changed": true,
            "commands": [
                "snmp-server host 1.1.1.1 trap version 1 TESTING  udp-port 162"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: snmp-server host 1.1.1.1 trap version 1 TESTING  udp-port 162



### nxos-snmp-location
***
Manages SNMP location information.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snmp_location_module.html


#### Base Command

`nxos-snmp-location`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| location | Location information. | Required | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnmpLocation.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-snmp-location host="192.168.1.19" location="Test" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSnmpLocation": {
            "changed": true,
            "commands": [
                "snmp-server location Test"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: snmp-server location Test

### nxos-snmp-traps
***
Manages SNMP traps.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snmp_traps_module.html


#### Base Command

`nxos-snmp-traps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| group | Case sensitive group. Possible values are: aaa, bfd, bgp, bridge, callhome, cfs, config, eigrp, entity, feature-control, generic, hsrp, license, link, lldp, mmode, ospf, pim, rf, rmon, snmp, storm-control, stpx, switchfabric, syslog, sysmgr, system, upgrade, vtp, all. | Required | 
| state | Manage the state of the resource. Possible values are: enabled, disabled. Default is enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnmpTraps.commands | unknown | command sent to the device | 



### nxos-snmp-user
***
Manages SNMP users for monitoring.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_snmp_user_module.html


#### Base Command

`nxos-snmp-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| user | Name of the user. | Required | 
| group | Group to which the user will belong to. If state = present, and the user is existing, the group is added to the user. If the user is not existing, user entry is created with this group argument. If state = absent, only the group is removed from the user entry. However, to maintain backward compatibility, if the existing user belongs to only one group, and if group argument is same as the existing user's group, then the user entry also is deleted. | Optional | 
| authentication | Authentication parameters for the user. Possible values are: md5, sha. | Optional | 
| pwd | Authentication password when using md5 or sha. This is not idempotent. | Optional | 
| privacy | Privacy password for the user. This is not idempotent. | Optional | 
| encrypt | Enables AES-128 bit encryption when using privacy password. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSnmpUser.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-snmp-user host="192.168.1.19" user="ntc" group="network-operator" authentication="md5" pwd="test_password" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSnmpUser": {
            "changed": true,
            "commands": [
                "snmp-server user ntc auth md5 ********"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: snmp-server user ntc auth md5 ********


### nxos-static-route
***
Manages static route configuration
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_static_route_module.html


#### Base Command

`nxos-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| prefix | Destination prefix of static route. | Required | 
| next_hop | Next hop address or interface of static route. If interface, it must be the fully-qualified interface name. | Required | 
| vrf | VRF for static route. Default is default. | Optional | 
| tag | Route tag value (numeric) or keyword 'default'. | Optional | 
| route_name | Name of the route or keyword 'default'. Used with the name parameter on the CLI. | Optional | 
| pref | Preference or administrative difference of route (range 1-255) or keyword 'default'. | Optional | 
| aggregate | List of static route definitions. | Optional | 
| track | Track value (range 1 - 512). Track must already be configured on the device before adding the route. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosStaticRoute.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-static-route host="192.168.1.19" prefix="1.1.1.2/24" next_hop="1.1.1.1" route_name="testing" pref="100" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosStaticRoute": {
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Commands

### nxos-system
***
Manage the system attributes on Cisco NXOS devices
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_system_module.html


#### Base Command

`nxos-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| hostname | Configure the device hostname parameter. This option takes an ASCII string value or keyword 'default'. | Optional | 
| domain_name | Configures the default domain name suffix to be used when referencing this node by its FQDN.  This argument accepts either a list of domain names or a list of dicts that configure the domain name and VRF name or keyword 'default'. See examples. | Optional | 
| domain_lookup | Enables or disables the DNS lookup feature in Cisco NXOS.  This argument accepts boolean values.  When enabled, the system will try to resolve hostnames using DNS and when disabled, hostnames will not be resolved. | Optional | 
| domain_search | Configures a list of domain name suffixes to search when performing DNS name resolution. This argument accepts either a list of domain names or a list of dicts that configure the domain name and VRF name or keyword 'default'. See examples. | Optional | 
| name_servers | List of DNS name servers by IP address to use to perform name resolution lookups.  This argument accepts either a list of DNS servers or a list of hashes that configure the name server and VRF name or keyword 'default'. See examples. | Optional | 
| system_mtu | Specifies the mtu, must be an integer or keyword 'default'. | Optional | 
| state | State of the configuration values in the device's current active configuration.  When set to `present`, the values should be configured in the device active configuration and when set to `absent` the values should not be in the device active configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosSystem.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!nxos-system host="192.168.1.19" hostname="nxos01" domain_name="test.example.com" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosSystem": {
            "changed": true,
            "commands": [
                "hostname nxos01"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: hostname nxos01


### nxos-telemetry
***
Telemetry Monitoring Service (TMS) configuration
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_telemetry_module.html


#### Base Command

`nxos-telemetry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | The provided configuration. | Optional | 
| state | Final configuration state. Possible values are: merged, replaced, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosTelemetry.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosTelemetry.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosTelemetry.commands | unknown | The set of commands pushed to the remote device. | 


#### Command Example
```!nxos-telemetry host="192.168.1.19" state="deleted" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosTelemetry": {
            "before": {},
            "changed": false,
            "commands": [],
            "host": "192.168.1.19",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  SUCCESS 
>  * changed: False
>  * ## Before
>  * ## Commands

### nxos-udld
***
Manages UDLD global configuration params.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_udld_module.html


#### Base Command

`nxos-udld`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| aggressive | Toggles aggressive mode. Possible values are: enabled, disabled. | Optional | 
| msg_time | Message time in seconds for UDLD packets or keyword 'default'. | Optional | 
| reset | Ability to reset all ports shut down by UDLD. 'state' parameter cannot be 'absent' when this is present. Default is no. | Optional | 
| state | Manage the state of the resource. When set to 'absent', aggressive and msg_time are set to their default values. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosUdld.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosUdld.existing | unknown | k/v pairs of existing udld configuration | 
| CiscoNXOS.NxosUdld.end_state | unknown | k/v pairs of udld configuration after module execution | 
| CiscoNXOS.NxosUdld.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosUdld.changed | boolean | check to see if a change was made on the device | 



### nxos-udld-interface
***
Manages UDLD interface configuration params.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_udld_interface_module.html


#### Base Command

`nxos-udld-interface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| mode | Manages UDLD mode for an interface. Possible values are: enabled, disabled, aggressive. | Required | 
| interface | FULL name of the interface, i.e. Ethernet1/1-. | Required | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosUdldInterface.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosUdldInterface.existing | unknown | k/v pairs of existing configuration | 
| CiscoNXOS.NxosUdldInterface.end_state | unknown | k/v pairs of configuration after module execution | 
| CiscoNXOS.NxosUdldInterface.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosUdldInterface.changed | boolean | check to see if a change was made on the device | 



### nxos-user
***
Manage the collection of local users on Nexus devices
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_user_module.html


#### Base Command

`nxos-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| aggregate | The set of username objects to be configured on the remote Cisco Nexus device.  The list entries can either be the username or a hash of username and properties.  This argument is mutually exclusive with the `name` argument. | Optional | 
| name | The username to be configured on the remote Cisco Nexus device.  This argument accepts a string value and is mutually exclusive with the `aggregate` argument. | Optional | 
| configured_password | The password to be configured on the network device. The password needs to be provided in cleartext and it will be encrypted on the device. Please note that this option is not same as `provider password`. | Optional | 
| update_password | Since passwords are encrypted in the device running config, this argument will instruct the module when to change the password.  When set to `always`, the password will always be updated in the device and when set to `on_create` the password will be updated only if the username is created. Possible values are: on_create, always. Default is always. | Optional | 
| role | The `role` argument configures the role for the username in the device running configuration.  The argument accepts a string value defining the role name.  This argument does not check if the role has been configured on the device. | Optional | 
| sshkey | The `sshkey` argument defines the SSH public key to configure for the username.  This argument accepts a valid SSH key value. | Optional | 
| purge | The `purge` argument instructs the module to consider the resource definition absolute.  It will remove any previously configured usernames on the device with the exception of the `admin` user which cannot be deleted per nxos constraints. Default is no. | Optional | 
| state | The `state` argument configures the state of the username definition as it relates to the device operational configuration.  When set to `present`, the username(s) should be configured in the device active configuration and when set to `absent` the username(s) should not be in the device active configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosUser.commands | unknown | The list of configuration mode commands to send to the device | 
| CiscoNXOS.NxosUser.start | string | The time the job started | 
| CiscoNXOS.NxosUser.end | string | The time the job ended | 
| CiscoNXOS.NxosUser.delta | string | The time elapsed to perform all operations | 


#### Command Example
```!nxos-user host="192.168.1.19" name="ansible" sshkey="ssh-rsa AAAAB3...u+DM=" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosUser": {
            "changed": true,
            "commands": [
                "username ansible",
                "username ansible sshkey ssh-rsa AAAAB3...u+DM="
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: username ansible
>    * 1: username ansible sshkey ssh-rsa AAAAB3...u+DM=


### nxos-vlans
***
Create VLAN and manage VLAN configurations on NX-OS Interfaces
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vlans_module.html


#### Base Command

`nxos-vlans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of Vlan options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVlans.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoNXOS.NxosVlans.after | unknown | The configuration as structured data after module completion. | 
| CiscoNXOS.NxosVlans.commands | unknown | The set of commands pushed to the remote device. | 



### nxos-vpc
***
Manages global VPC configuration
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vpc_module.html


#### Base Command

`nxos-vpc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| domain | VPC domain. | Required | 
| role_priority | Role priority for device. Remember lower is better. | Optional | 
| system_priority | System priority device.  Remember they must match between peers. | Optional | 
| pkl_src | Source IP address used for peer keepalive link. | Optional | 
| pkl_dest | Destination (remote) IP address used for peer keepalive link pkl_dest is required whenever pkl options are used. | Optional | 
| pkl_vrf | VRF used for peer keepalive link The VRF must exist on the device before using pkl_vrf. (Note) 'default' is an overloaded term: Default vrf context for pkl_vrf is 'management'; 'pkl_vrf: default' refers to the literal 'default' rib. Default is management. | Optional | 
| peer_gw | Enables/Disables peer gateway. | Optional | 
| auto_recovery | Enables/Disables auto recovery on platforms that support disable timers are not modifiable with this attribute mutually exclusive with auto_recovery_reload_delay. | Optional | 
| auto_recovery_reload_delay | Manages auto-recovery reload-delay timer in seconds mutually exclusive with auto_recovery. | Optional | 
| delay_restore | manages delay restore command and config value in seconds. | Optional | 
| delay_restore_interface_vlan | manages delay restore interface-vlan command and config value in seconds not supported on all platforms. | Optional | 
| delay_restore_orphan_port | manages delay restore orphan-port command and config value in seconds not supported on all platforms. | Optional | 
| state | Manages desired state of the resource. Possible values are: present, absent. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVpc.commands | unknown | commands sent to the device | 



### nxos-vpc-interface
***
Manages interface VPC configuration
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vpc_interface_module.html


#### Base Command

`nxos-vpc-interface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| portchannel | Group number of the portchannel that will be configured. | Required | 
| vpc | VPC group/id that will be configured on associated portchannel. | Optional | 
| peer_link | Set to true/false for peer link config on associated portchannel. | Optional | 
| state | Manages desired state of the resource. Possible values are: present, absent. Default is present. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVpcInterface.commands | unknown | commands sent to the device | 



### nxos-vrf
***
Manages global VRF configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vrf_module.html


#### Base Command

`nxos-vrf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of VRF to be managed. | Required | 
| admin_state | Administrative state of the VRF. Possible values are: up, down. Default is up. | Optional | 
| vni | Specify virtual network identifier. Valid values are Integer or keyword 'default'. | Optional | 
| rd | VPN Route Distinguisher (RD). Valid values are a string in one of the route-distinguisher formats (ASN2:NN, ASN4:NN, or IPV4:NN); the keyword 'auto', or the keyword 'default'. | Optional | 
| interfaces | List of interfaces to check the VRF has been configured correctly or keyword 'default'. | Optional | 
| associated_interfaces | This is a intent option and checks the operational state of the for given vrf `name` for associated interfaces. If the value in the `associated_interfaces` does not match with the operational state of vrf interfaces on device it will result in failure. | Optional | 
| aggregate | List of VRFs definitions. | Optional | 
| purge | Purge VRFs not defined in the `aggregate` parameter. Default is no. | Optional | 
| state | Manages desired state of the resource. Possible values are: present, absent. Default is present. | Optional | 
| description | Description of the VRF or keyword 'default'. | Optional | 
| delay | Time in seconds to wait before checking for the operational state on remote device. This wait is applicable for operational state arguments. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVrf.commands | unknown | commands sent to the device | 


#### Command Example
```!nxos-vrf host="192.168.1.19" name="ntc" description="testing" state="present" ```

#### Context Example
```json
{
    "CiscoNXOS": {
        "NxosVrf": {
            "changed": true,
            "commands": [
                "vrf context ntc",
                "description testing",
                "no shutdown",
                "exit"
            ],
            "host": "192.168.1.19",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 192.168.1.19 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: vrf context ntc
>    * 1: description testing
>    * 2: no shutdown
>    * 3: exit

### nxos-vrf-af
***
Manages VRF AF.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vrf_af_module.html


#### Base Command

`nxos-vrf-af`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| vrf | Name of the VRF. | Required | 
| afi | Address-Family Identifier (AFI). Possible values are: ipv4, ipv6. | Required | 
| route_target_both_auto_evpn | Enable/Disable the EVPN route-target 'auto' setting for both import and export target communities. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVrfAf.commands | unknown | commands sent to the device | 



### nxos-vrf-interface
***
Manages interface specific VRF configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vrf_interface_module.html


#### Base Command

`nxos-vrf-interface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| vrf | Name of VRF to be managed. | Required | 
| interface | Full name of interface to be managed, i.e. Ethernet1/1. | Required | 
| state | Manages desired state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVrfInterface.commands | unknown | commands sent to the device | 



### nxos-vrrp
***
Manages VRRP configuration on NX-OS switches.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vrrp_module.html


#### Base Command

`nxos-vrrp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| group | VRRP group number. | Required | 
| interface | Full name of interface that is being managed for VRRP. | Required | 
| interval | Time interval between advertisement or 'default' keyword. Default is 1. | Optional | 
| priority | VRRP priority or 'default' keyword. Default is 100. | Optional | 
| preempt | Enable/Disable preempt. Default is yes. | Optional | 
| vip | VRRP virtual IP address or 'default' keyword. | Optional | 
| authentication | Clear text authentication string or 'default' keyword. | Optional | 
| admin_state | Used to enable or disable the VRRP process. Possible values are: shutdown, no shutdown, default. Default is shutdown. | Optional | 
| state | Specify desired state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVrrp.commands | unknown | commands sent to the device | 



### nxos-vtp-domain
***
Manages VTP domain configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vtp_domain_module.html


#### Base Command

`nxos-vtp-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| domain | VTP domain name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVtpDomain.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosVtpDomain.existing | unknown | k/v pairs of existing vtp domain | 
| CiscoNXOS.NxosVtpDomain.end_state | unknown | k/v pairs of vtp domain after module execution | 
| CiscoNXOS.NxosVtpDomain.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosVtpDomain.changed | boolean | check to see if a change was made on the device | 



### nxos-vtp-password
***
Manages VTP password configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vtp_password_module.html


#### Base Command

`nxos-vtp-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| vtp_password | VTP password. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVtpPassword.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosVtpPassword.existing | unknown | k/v pairs of existing vtp | 
| CiscoNXOS.NxosVtpPassword.end_state | unknown | k/v pairs of vtp after module execution | 
| CiscoNXOS.NxosVtpPassword.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosVtpPassword.changed | boolean | check to see if a change was made on the device | 



### nxos-vtp-version
***
Manages VTP version configuration.
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vtp_version_module.html


#### Base Command

`nxos-vtp-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| version | VTP version number. Possible values are: 1, 2. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVtpVersion.proposed | unknown | k/v pairs of parameters passed into module | 
| CiscoNXOS.NxosVtpVersion.existing | unknown | k/v pairs of existing vtp | 
| CiscoNXOS.NxosVtpVersion.end_state | unknown | k/v pairs of vtp after module execution | 
| CiscoNXOS.NxosVtpVersion.updates | unknown | command sent to the device | 
| CiscoNXOS.NxosVtpVersion.changed | boolean | check to see if a change was made on the device | 



### nxos-vxlan-vtep
***
Manages VXLAN Network Virtualization Endpoint (NVE).
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vxlan_vtep_module.html


#### Base Command

`nxos-vxlan-vtep`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| interface | Interface name for the VXLAN Network Virtualization Endpoint. | Required | 
| description | Description of the NVE interface. | Optional | 
| host_reachability | Specify mechanism for host reachability advertisement. | Optional | 
| shutdown | Administratively shutdown the NVE interface. | Optional | 
| source_interface | Specify the loopback interface whose IP address should be used for the NVE interface. | Optional | 
| source_interface_hold_down_time | Suppresses advertisement of the NVE loopback address until the overlay has converged. | Optional | 
| global_mcast_group_L3 | Global multicast ip prefix for L3 VNIs or the keyword 'default' This is available on NX-OS 9K series running 9.2.x or higher. | Optional | 
| global_mcast_group_L2 | Global multicast ip prefix for L2 VNIs or the keyword 'default' This is available on NX-OS 9K series running 9.2.x or higher. | Optional | 
| global_suppress_arp | Enables ARP suppression for all VNIs This is available on NX-OS 9K series running 9.2.x or higher. | Optional | 
| global_ingress_replication_bgp | Configures ingress replication protocol as bgp for all VNIs This is available on NX-OS 9K series running 9.2.x or higher. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVxlanVtep.commands | unknown | commands sent to the device | 



### nxos-vxlan-vtep-vni
***
Creates a Virtual Network Identifier member (VNI)
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nxos_vxlan_vtep_vni_module.html


#### Base Command

`nxos-vxlan-vtep-vni`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| interface | Interface name for the VXLAN Network Virtualization Endpoint. | Required | 
| vni | ID of the Virtual Network Identifier. | Required | 
| assoc_vrf | This attribute is used to identify and separate processing VNIs that are associated with a VRF and used for routing. The VRF and VNI specified with this command must match the configuration of the VNI under the VRF. | Optional | 
| ingress_replication | Specifies mechanism for host reachability advertisement. Possible values are: bgp, static, default. | Optional | 
| multicast_group | The multicast group (range) of the VNI. Valid values are string and keyword 'default'. | Optional | 
| peer_list | Set the ingress-replication static peer list. Valid values are an array, a space-separated string of ip addresses, or the keyword 'default'. | Optional | 
| suppress_arp | Suppress arp under layer 2 VNI. | Optional | 
| suppress_arp_disable | Overrides the global ARP suppression config. This is available on NX-OS 9K series running 9.2.x or higher. | Optional | 
| state | Determines whether the config should be present or not on the device. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoNXOS.NxosVxlanVtepVni.commands | unknown | commands sent to the device | 


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
