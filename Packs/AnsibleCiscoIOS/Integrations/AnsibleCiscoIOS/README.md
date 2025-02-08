This integration enables the management of Cisco IOS Switches and Routers directly from XSOAR using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the hosts by utilising SSH.

To use this integration, configure an instance of this integration. This will associate a credential to be used to access hosts when commands are run. The commands from this integration will take the IOS host address(es) as an input, and use the saved credential associated to the instance to execute. Create separate instances if multiple credentials are required.

## Credentials
This integration supports a number of methods of authenticating with the network device:

1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

In addition to the SSH credential, a `enable` password must be also provided.
## Permissions
The user account used for initial SSH login access can be level 1, however the enable password must also be provided.
## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the IOS host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.
## Configure Ansible Cisco IOS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | The credentials to associate with the instance. SSH keys can be configured using the credential manager. | True |
| Password |  | True |
| Enable Password |  | True |
| Default SSH Port | The default port to use if one is not specified in the commands \`host\` argument. | True |
| Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!ios-facts`command providing an example `host` as the command argument. This command will connect to the specified network device with the configured credentials in the integration, and if successful output general information about the device.

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
### ios-banner
***
Manage multiline banners on Cisco IOS devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_banner_module.html


#### Base Command

`ios-banner`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| banner | Specifies which banner should be configured on the remote device. In Ansible 2.4 and earlier only `login` and `motd` were supported. Possible values are: login, motd, exec, incoming, slip-ppp. | Required | 
| text | The banner text that should be present in the remote device running configuration.  This argument accepts a multiline string, with no empty lines. Requires `state=present`. | Optional | 
| state | Specifies whether or not the configuration is present in the current devices active running configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosBanner.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-banner host="123.123.123.123" banner="login" text="this is my login banner" state="present" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosBanner": {
            "changed": true,
            "commands": [
                "banner login @\nthis is my login banner\n@"
            ],
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: banner login @
>this is my login banner
>@


### ios-bgp
***
Configure global BGP protocol settings on Cisco IOS.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_bgp_module.html


#### Base Command

`ios-bgp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | Specifies the BGP related configuration. | Optional | 
| operation | Specifies the operation to be performed on the BGP process configured on the device. In case of merge, the input configuration will be merged with the existing BGP configuration on the device. In case of replace, if there is a diff between the existing configuration and the input configuration, the existing configuration will be replaced by the input configuration for every option that has the diff. In case of override, all the existing BGP configuration will be removed from the device and replaced with the input configuration. In case of delete the existing BGP configuration will be removed from the device. Possible values are: merge, replace, override, delete. Default is merge. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosBgp.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-bgp host="123.123.123.123" config="{{ {'bgp_as': 64496, 'router_id': '192.0.2.1', 'log_neighbor_changes': True, 'neighbors': [{'neighbor': '1.1.1.1', 'remote_as': 64511, 'timers': {'keepalive': 300, 'holdtime': 360, 'min_neighbor_holdtime': 360}}, {'neighbor': '1.1.1.2', 'remote_as': 64498}], 'networks': [{'prefix': '198.51.100.0', 'route_map': 'RMAP_1'}, {'prefix': '192.0.2.0', 'masklen': 23}], 'address_family': [{'afi': 'ipv4', 'safi': 'unicast', 'redistribute': [{'protocol': 'ospf', 'id': 223, 'metric': 10}]}]} }}" operation="merge" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosBgp": {
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Commands


### ios-command
***
Run commands on remote devices running Cisco IOS
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_command_module.html


#### Base Command

`ios-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| commands | List of commands to send to the remote ios device over the configured provider. The resulting output from the command is returned. If the `wait_for` argument is provided, the module is not returned until the condition is satisfied or the number of retries has expired. If a command sent to the device requires answering a prompt, it is possible to pass a dict containing `command`, `answer` and `prompt`. Common answers are 'y' or "\r" (carriage return, must be double quotes). See examples. | Required | 
| wait_for | List of conditions to evaluate against the output of the command. The task will wait for each condition to be true before moving forward. If the conditional is not true within the configured number of retries, the task fails. See examples. | Optional | 
| match | The `match` argument is used in conjunction with the `wait_for` argument to specify the match policy.  Valid values are `all` or `any`.  If the value is set to `all` then all conditionals in the wait_for must be satisfied.  If the value is set to `any` then only one of the values must be satisfied. Possible values are: any, all. Default is all. | Optional | 
| retries | Specifies the number of retries a command should by tried before it is considered failed. The command is run on the target device every retry and evaluated against the `wait_for` conditions. Default is 10. | Optional | 
| interval | Configures the interval in seconds to wait between retries of the command. If the command does not pass the specified conditions, the interval indicates how long to wait before trying the command again. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosCommand.stdout | unknown | The set of responses from the commands | 
| CiscoIOS.IosCommand.stdout_lines | unknown | The value of stdout split into a list | 
| CiscoIOS.IosCommand.failed_conditions | unknown | The list of conditionals that have failed | 


#### Command Example
```!ios-command host="123.123.123.123" commands="show version"```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosCommand": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS",
            "stdout": [
                "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.7(3)M3, RELEASE SOFTWARE (fc2)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2018 by Cisco Systems, Inc.\nCompiled Wed 01-Aug-18 16:45 by prod_rel_team\n\n\nROM: Bootstrap program is IOSv\n\nIOSv01 uptime is 1 hour, 33 minutes\nSystem returned to ROM by reload\nSystem image file is \"flash0:/vios-adventerprisek9-m\"\nLast reload reason: Unknown reason\n\n\n\nThis product contains cryptographic features and is subject to United\nStates and local country laws governing import, export, transfer and\nuse. Delivery of Cisco cryptographic products does not imply\nthird-party authority to import, export, distribute or use encryption.\nImporters, exporters, distributors and users are responsible for\ncompliance with U.S. and local country laws. By using this product you\nagree to comply with applicable laws and regulations. If you are unable\nto comply with U.S. and local laws, return this product immediately.\n\nA summary of U.S. laws governing Cisco cryptographic products may be found at:\nhttp://www.cisco.com/wwl/export/crypto/tool/stqrg.html\n\nIf you require further assistance please contact us by sending email to\nexport@cisco.com.\n\nCisco IOSv (revision 1.0) with  with 460009K/62464K bytes of memory.\nProcessor board ID XXXX\n4 Gigabit Ethernet interfaces\nDRAM configuration is 72 bits wide with parity disabled.\n256K bytes of non-volatile configuration memory.\n2097152K bytes of ATA System CompactFlash 0 (Read/Write)\n0K bytes of ATA CompactFlash 1 (Read/Write)\n1024K bytes of ATA CompactFlash 2 (Read/Write)\n0K bytes of ATA CompactFlash 3 (Read/Write)\n\n\n\nConfiguration register is 0x0"
            ],
            "stdout_lines": [
                [
                    "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.7(3)M3, RELEASE SOFTWARE (fc2)",
                    "Technical Support: http://www.cisco.com/techsupport",
                    "Copyright (c) 1986-2018 by Cisco Systems, Inc.",
                    "Compiled Wed 01-Aug-18 16:45 by prod_rel_team",
                    "",
                    "",
                    "ROM: Bootstrap program is IOSv",
                    "",
                    "IOSv01 uptime is 1 hour, 33 minutes",
                    "System returned to ROM by reload",
                    "System image file is \"flash0:/vios-adventerprisek9-m\"",
                    "Last reload reason: Unknown reason",
                    "",
                    "",
                    "",
                    "This product contains cryptographic features and is subject to United",
                    "States and local country laws governing import, export, transfer and",
                    "use. Delivery of Cisco cryptographic products does not imply",
                    "third-party authority to import, export, distribute or use encryption.",
                    "Importers, exporters, distributors and users are responsible for",
                    "compliance with U.S. and local country laws. By using this product you",
                    "agree to comply with applicable laws and regulations. If you are unable",
                    "to comply with U.S. and local laws, return this product immediately.",
                    "",
                    "A summary of U.S. laws governing Cisco cryptographic products may be found at:",
                    "http://www.cisco.com/wwl/export/crypto/tool/stqrg.html",
                    "",
                    "If you require further assistance please contact us by sending email to",
                    "export@cisco.com.",
                    "",
                    "Cisco IOSv (revision 1.0) with  with 460009K/62464K bytes of memory.",
                    "Processor board ID XXXX",
                    "4 Gigabit Ethernet interfaces",
                    "DRAM configuration is 72 bits wide with parity disabled.",
                    "256K bytes of non-volatile configuration memory.",
                    "2097152K bytes of ATA System CompactFlash 0 (Read/Write)",
                    "0K bytes of ATA CompactFlash 1 (Read/Write)",
                    "1024K bytes of ATA CompactFlash 2 (Read/Write)",
                    "0K bytes of ATA CompactFlash 3 (Read/Write)",
                    "",
                    "",
                    "",
                    "Configuration register is 0x0"
                ]
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Stdout
>    * 0: Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.7(3)M3, RELEASE SOFTWARE (fc2)
>Technical Support: http://www.cisco.com/techsupport
>Copyright (c) 1986-2018 by Cisco Systems, Inc.
>Compiled Wed 01-Aug-18 16:45 by prod_rel_team
>
>
>ROM: Bootstrap program is IOSv
>
>IOSv01 uptime is 1 hour, 33 minutes
>System returned to ROM by reload
>System image file is "flash0:/vios-adventerprisek9-m"
>Last reload reason: Unknown reason
>
>
>
>This product contains cryptographic features and is subject to United
>States and local country laws governing import, export, transfer and
>use. Delivery of Cisco cryptographic products does not imply
>third-party authority to import, export, distribute or use encryption.
>Importers, exporters, distributors and users are responsible for
>compliance with U.S. and local country laws. By using this product you
>agree to comply with applicable laws and regulations. If you are unable
>to comply with U.S. and local laws, return this product immediately.
>
>A summary of U.S. laws governing Cisco cryptographic products may be found at:
>http://www.cisco.com/wwl/export/crypto/tool/stqrg.html
>
>If you require further assistance please contact us by sending email to
>export@cisco.com.
>
>Cisco IOSv (revision 1.0) with  with 460009K/62464K bytes of memory.
>Processor board ID XXXX
>4 Gigabit Ethernet interfaces
>DRAM configuration is 72 bits wide with parity disabled.
>256K bytes of non-volatile configuration memory.
>2097152K bytes of ATA System CompactFlash 0 (Read/Write)
>0K bytes of ATA CompactFlash 1 (Read/Write)
>1024K bytes of ATA CompactFlash 2 (Read/Write)
>0K bytes of ATA CompactFlash 3 (Read/Write)
>
>
>
>Configuration register is 0x0
>  * ## Stdout_Lines
>  * ## List
>    * 0: Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.7(3)M3, RELEASE SOFTWARE (fc2)
>    * 1: Technical Support: http://www.cisco.com/techsupport
>    * 2: Copyright (c) 1986-2018 by Cisco Systems, Inc.
>    * 3: Compiled Wed 01-Aug-18 16:45 by prod_rel_team
>    * 4: 
>    * 4: 
>    * 6: ROM: Bootstrap program is IOSv
>    * 4: 
>    * 8: IOSv01 uptime is 1 hour, 33 minutes
>    * 9: System returned to ROM by reload
>    * 10: System image file is "flash0:/vios-adventerprisek9-m"
>    * 11: Last reload reason: Unknown reason
>    * 4: 
>    * 4: 
>    * 4: 
>    * 15: This product contains cryptographic features and is subject to United
>    * 16: States and local country laws governing import, export, transfer and
>    * 17: use. Delivery of Cisco cryptographic products does not imply
>    * 18: third-party authority to import, export, distribute or use encryption.
>    * 19: Importers, exporters, distributors and users are responsible for
>    * 20: compliance with U.S. and local country laws. By using this product you
>    * 21: agree to comply with applicable laws and regulations. If you are unable
>    * 22: to comply with U.S. and local laws, return this product immediately.
>    * 4: 
>    * 24: A summary of U.S. laws governing Cisco cryptographic products may be found at:
>    * 25: http://www.cisco.com/wwl/export/crypto/tool/stqrg.html
>    * 4: 
>    * 27: If you require further assistance please contact us by sending email to
>    * 28: export@cisco.com.
>    * 4: 
>    * 30: Cisco IOSv (revision 1.0) with  with 460009K/62464K bytes of memory.
>    * 31: Processor board ID XXXX
>    * 32: 4 Gigabit Ethernet interfaces
>    * 33: DRAM configuration is 72 bits wide with parity disabled.
>    * 34: 256K bytes of non-volatile configuration memory.
>    * 35: 2097152K bytes of ATA System CompactFlash 0 (Read/Write)
>    * 36: 0K bytes of ATA CompactFlash 1 (Read/Write)
>    * 37: 1024K bytes of ATA CompactFlash 2 (Read/Write)
>    * 38: 0K bytes of ATA CompactFlash 3 (Read/Write)
>    * 4: 
>    * 4: 
>    * 4: 
>    * 42: Configuration register is 0x0


### ios-config
***
Manage Cisco IOS configuration sections
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_config_module.html


#### Base Command

`ios-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| lines | The ordered set of commands that should be configured in the section.  The commands must be the exact same commands as found in the device running-config.  Be sure to note the configuration command syntax as some commands are automatically modified by the device config parser. | Optional | 
| parents | The ordered set of parents that uniquely identify the section or hierarchy the commands should be checked against.  If the parents argument is omitted, the commands are checked against the set of top level or global commands. | Optional | 
| src | Specifies the source path to the file that contains the configuration or configuration template to load.  The path to the source file can either be the full path on the Ansible control host or a relative path from the playbook or role root directory.  This argument is mutually exclusive with `lines`, `parents`. | Optional | 
| before | The ordered set of commands to push on to the command stack if a change needs to be made.  This allows the playbook designer the opportunity to perform configuration commands prior to pushing any changes without affecting how the set of commands are matched against the system. | Optional | 
| after | The ordered set of commands to append to the end of the command stack if a change needs to be made.  Just like with `before` this allows the playbook designer to append a set of commands to be executed after the command set. | Optional | 
| match | Instructs the module on the way to perform the matching of the set of commands against the current device config.  If match is set to `line`, commands are matched line by line.  If match is set to `strict`, command lines are matched with respect to position.  If match is set to `exact`, command lines must be an equal match.  Finally, if match is set to `none`, the module will not attempt to compare the source configuration with the running configuration on the remote device. Possible values are: line, strict, exact, none. Default is line. | Optional | 
| replace | Instructs the module on the way to perform the configuration on the device. If the replace argument is set to `line` then the modified lines are pushed to the device in configuration mode.  If the replace argument is set to `block` then the entire command block is pushed to the device in configuration mode if any line is not correct. Possible values are: line, block. Default is line. | Optional | 
| multiline_delimiter | This argument is used when pushing a multiline configuration element to the IOS device.  It specifies the character to use as the delimiting character.  This only applies to the configuration action. Default is @. | Optional | 
| backup | This argument will cause the module to create a full backup of the current `running-config` from the remote device before any changes are made. If the `backup_options` value is not given, the backup file is written to the `backup` folder in the playbook root directory or role root directory, if playbook is part of an ansible role. If the directory does not exist, it is created. Default is no. | Optional | 
| running_config | The module, by default, will connect to the remote device and retrieve the current running-config to use as a base for comparing against the contents of source. There are times when it is not desirable to have the task get the current running-config for every task in a playbook.  The `running_config` argument allows the implementer to pass in the configuration to use as the base config for comparison. | Optional | 
| defaults | This argument specifies whether or not to collect all defaults when getting the remote device running config.  When enabled, the module will get the current config by issuing the command `show running-config all`. Default is no. | Optional | 
| save_when | When changes are made to the device running-configuration, the changes are not copied to non-volatile storage by default.  Using this argument will change that before.  If the argument is set to `always`, then the running-config will always be copied to the startup-config and the `modified` flag will always be set to True.  If the argument is set to `modified`, then the running-config will only be copied to the startup-config if it has changed since the last save to startup-config.  If the argument is set to `never`, the running-config will never be copied to the startup-config.  If the argument is set to `changed`, then the running-config will only be copied to the startup-config if the task has made a change. `changed` was added in Ansible 2.5. Possible values are: always, never, modified, changed. Default is never. | Optional | 
| diff_against | When using the `ansible-playbook --diff` command line argument the module can generate diffs against different sources. When this option is configure as `startup`, the module will return the diff of the running-config against the startup-config. When this option is configured as `intended`, the module will return the diff of the running-config against the configuration provided in the `intended_config` argument. When this option is configured as `running`, the module will return the before and after diff of the running-config with respect to any changes made to the device configuration. Possible values are: running, startup, intended. | Optional | 
| diff_ignore_lines | Use this argument to specify one or more lines that should be ignored during the diff.  This is used for lines in the configuration that are automatically updated by the system.  This argument takes a list of regular expressions or exact line matches. | Optional | 
| intended_config | The `intended_config` provides the master configuration that the node should conform to and is used to check the final running-config against. This argument will not modify any settings on the remote device and is strictly used to check the compliance of the current device's configuration against.  When specifying this argument, the task should also modify the `diff_against` value and set it to `intended`. | Optional | 
| backup_options | This is a dict object containing configurable options related to backup file path. The value of this option is read only when `backup` is set to `yes`, if `backup` is set to `no` this option will be silently ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosConfig.updates | unknown | The set of commands that will be pushed to the remote device | 
| CiscoIOS.IosConfig.commands | unknown | The set of commands that will be pushed to the remote device | 
| CiscoIOS.IosConfig.backup_path | string | The full path to the backup file | 
| CiscoIOS.IosConfig.filename | string | The name of the backup file | 
| CiscoIOS.IosConfig.shortname | string | The full path to the backup file excluding the timestamp | 
| CiscoIOS.IosConfig.date | string | The date extracted from the backup file name | 
| CiscoIOS.IosConfig.time | string | The time extracted from the backup file name | 


#### Command Example
```!ios-config host="123.123.123.123" lines="hostname IOSv01" backup="yes"```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosConfig": {
            "backup_path": "./backup/123.123.123.123_config.2021-07-11@09:08:02",
            "changed": true,
            "date": "2021-07-11",
            "filename": "123.123.123.123_config.2021-07-11@09:08:02",
            "host": "123.123.123.123",
            "shortname": "./backup/123.123.123.123_config",
            "status": "CHANGED",
            "time": "09:08:02"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * backup_path: ./backup/123.123.123.123_config.2021-07-11@09:08:02
>  * changed: True
>  * date: 2021-07-11
>  * filename: 123.123.123.123_config.2021-07-11@09:08:02
>  * shortname: ./backup/123.123.123.123_config
>  * time: 09:08:02


### ios-facts
***
Collect facts from remote devices running Cisco IOS
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_facts_module.html


#### Base Command

`ios-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| gather_subset | When supplied, this argument restricts the facts collected to a given subset. Possible values for this argument include `all`, `min`, `hardware`, `config`, and `interfaces`. Specify a list of values to include a larger subset. Use a value with an initial `!` to collect all facts except that subset. Default is !config. | Optional | 
| gather_network_resources | When supplied, this argument will restrict the facts collected to a given subset. Possible values for this argument include all and the resources like interfaces, vlans etc. Can specify a list of values to include a larger subset. Values can also be used with an initial `M(!`) to specify that a specific subset should not be collected. Valid subsets are 'all', 'interfaces', 'l2_interfaces', 'vlans', 'lag_interfaces', 'lacp', 'lacp_interfaces', 'lldp_global', 'lldp_interfaces', 'l3_interfaces'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosFacts.net_gather_subset | unknown | The list of fact subsets collected from the device | 
| CiscoIOS.IosFacts.net_gather_network_resources | unknown | The list of fact for network resource subsets collected from the device | 
| CiscoIOS.IosFacts.net_model | string | The model name returned from the device | 
| CiscoIOS.IosFacts.net_serialnum | string | The serial number of the remote device | 
| CiscoIOS.IosFacts.net_version | string | The operating system version running on the remote device | 
| CiscoIOS.IosFacts.net_iostype | string | The operating system type \(IOS or IOS-XE\) running on the remote device | 
| CiscoIOS.IosFacts.net_hostname | string | The configured hostname of the device | 
| CiscoIOS.IosFacts.net_image | string | The image file the device is running | 
| CiscoIOS.IosFacts.net_stacked_models | unknown | The model names of each device in the stack | 
| CiscoIOS.IosFacts.net_stacked_serialnums | unknown | The serial numbers of each device in the stack | 
| CiscoIOS.IosFacts.net_api | string | The name of the transport | 
| CiscoIOS.IosFacts.net_python_version | string | The Python version Ansible controller is using | 
| CiscoIOS.IosFacts.net_filesystems | unknown | All file system names available on the device | 
| CiscoIOS.IosFacts.net_filesystems_info | unknown | A hash of all file systems containing info about each file system \(e.g. free and total space\) | 
| CiscoIOS.IosFacts.net_memfree_mb | number | The available free memory on the remote device in Mb | 
| CiscoIOS.IosFacts.net_memtotal_mb | number | The total memory on the remote device in Mb | 
| CiscoIOS.IosFacts.net_config | string | The current active config from the device | 
| CiscoIOS.IosFacts.net_all_ipv4_addresses | unknown | All IPv4 addresses configured on the device | 
| CiscoIOS.IosFacts.net_all_ipv6_addresses | unknown | All IPv6 addresses configured on the device | 
| CiscoIOS.IosFacts.net_interfaces | unknown | A hash of all interfaces running on the system | 
| CiscoIOS.IosFacts.net_neighbors | unknown | The list of CDP and LLDP neighbors from the remote device. If both, CDP and LLDP neighbor data is present on one port, CDP is preferred. | 


#### Command Example
```!ios-facts host="123.123.123.123" gather_subset="all" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosFacts": {
            "discovered_interpreter_python": "/usr/local/bin/python",
            "host": "123.123.123.123",
            "net_all_ipv4_addresses": [
                "123.123.123.123",
                "192.168.0.2"
            ],
            "net_all_ipv6_addresses": [
                "1:11:11:11"
            ],
            "net_api": "cliconf",
            "net_config": "!\n! Last configuration change at 08:56:26 UTC Sun Jul 11 2021 by admin\n!\nversion 15.7\nservice timestamps debug datetime msec\nservice timestamps log datetime msec\nno service password-encryption\n!\nhostname IOSv01\n!\nboot-start-marker\nboot-end-marker\n!\n!\nenable secret 5 $1$abcdefghijklmnopqrstuvwxyz.\n!\nno aaa new-model\n!\n!\n!\nmmi polling-interval 60\nno mmi auto-configure\nno mmi pvc\nmmi snmp-timeout 180\n!\n!\n!\n!\n!\nno ip icmp rate-limit unreachable\n!\n!\n!\n!\n!\n!\nip domain list ansible.com\nip domain list redhat.com\nip domain list cisco.com\nno ip domain lookup\nip domain name test.example.com\nip cef\nno ipv6 cef\n!\nmultilink bundle-name authenticated\n!\n!\n!\n!\nusername admin password 0 abcdef\nusername ansible nopassword\n!\nredundancy\n!\nlldp timer 10\nlldp holdtime 10\nlldp reinit 3\nlldp run\nno cdp log mismatch duplex\n!\nip tcp synwait-time 5\n! \n!\n!\n!\n!\n!\n!\n!\n!\n!\n!\n!\n!\ninterface GigabitEthernet0/0\n ip address 123.123.123.123 255.255.255.0\n duplex auto\n speed auto\n media-type rj45\n!\ninterface GigabitEthernet0/1\n no ip address\n shutdown\n duplex auto\n speed auto\n media-type rj45\n!\ninterface GigabitEthernet0/2\n description Configured and Merged by Ansible Network\n ip address 192.168.0.2 255.255.255.0\n duplex auto\n speed auto\n media-type rj45\n!\ninterface GigabitEthernet0/3\n description Configured and Merged by Ansible Network\n mtu 2800\n no ip address\n shutdown\n duplex full\n speed 100\n media-type rj45\n ipv6 address 1:11:11:11/64\n!\ninterface GigabitEthernet0/3.100\n!\nrouter bgp 64496\n bgp router-id 192.0.2.1\n bgp log-neighbor-changes\n neighbor 1.1.1.2 remote-as 64498\n neighbor 1.1.1.1 remote-as 64511\n neighbor 1.1.1.1 timers 300 360 360\n !\n address-family ipv4\n  network 192.0.2.0 mask 255.255.254.0\n  network 198.51.100.0 route-map RMAP_1\n  redistribute ospf 223 metric 10\n  neighbor 1.1.1.2 activate\n  neighbor 1.1.1.1 activate\n exit-address-family\n!\nip default-gateway 192.168.1.1\nip forward-protocol nd\n!\n!\nno ip http server\nno ip http secure-server\nip route 192.168.2.0 255.255.255.0 10.0.0.1\nip ssh version 2\nip ssh pubkey-chain\n  username ansible\n   key-hash ssh-rsa B1E29F17C950E2FEAB5BC3AC2A760208 \nip ssh server algorithm mac hmac-sha2-256\n!\nlogging host 172.16.0.1\nipv6 ioam timestamp\n!\n!\n!\ncontrol-plane\n!\nbanner exec ^C\n**************************************************************************\n* IOSv is strictly limited to use for evaluation, demonstration and IOS  *\n* education. IOSv is provided as-is and is not supported by Cisco's      *\n* Technical Advisory Center. Any use or disclosure, in whole or in part, *\n* of the IOSv Software or Documentation to any third party for any       *\n* purposes is expressly prohibited except as otherwise authorized by     *\n* Cisco in writing.                                                      *\n**************************************************************************^C\nbanner incoming ^C\n**************************************************************************\n* IOSv is strictly limited to use for evaluation, demonstration and IOS  *\n* education. IOSv is provided as-is and is not supported by Cisco's      *\n* Technical Advisory Center. Any use or disclosure, in whole or in part, *\n* of the IOSv Software or Documentation to any third party for any       *\n* purposes is expressly prohibited except as otherwise authorized by     *\n* Cisco in writing.                                                      *\n**************************************************************************^C\nbanner login ^C\nthis is my login banner\n^C\n!\nline con 0\n exec-timeout 0 0\n privilege level 15\n logging synchronous\nline aux 0\n exec-timeout 0 0\n privilege level 15\n logging synchronous\nline vty 0 4\n login local\n transport input ssh\n!\nno scheduler allocate\nntp server 1.1.1.3\n!\nend",
            "net_filesystems": [
                "flash0:"
            ],
            "net_filesystems_info": {
                "flash0:": {
                    "spacefree_kb": 1941968,
                    "spacetotal_kb": 2092496
                }
            },
            "net_gather_network_resources": [],
            "net_gather_subset": [
                "interfaces",
                "default",
                "hardware",
                "config"
            ],
            "net_hostname": "IOSv01",
            "net_image": "flash0:/vios-adventerprisek9-m",
            "net_interfaces": {
                "GigabitEthernet0/0": {
                    "bandwidth": 1000000,
                    "description": null,
                    "duplex": "Auto",
                    "ipv4": [
                        {
                            "address": "123.123.123.123",
                            "subnet": "24"
                        }
                    ],
                    "lineprotocol": "up",
                    "macaddress": "0c05.2bf9.3e00",
                    "mediatype": "RJ45",
                    "mtu": 1500,
                    "operstatus": "up",
                    "type": "iGbE"
                },
                "GigabitEthernet0/1": {
                    "bandwidth": 1000000,
                    "description": null,
                    "duplex": "Auto",
                    "ipv4": [],
                    "lineprotocol": "down",
                    "macaddress": "0c05.2bf9.3e01",
                    "mediatype": "RJ45",
                    "mtu": 1500,
                    "operstatus": "administratively down",
                    "type": "iGbE"
                },
                "GigabitEthernet0/2": {
                    "bandwidth": 1000000,
                    "description": "Configured and Merged by Ansible Network",
                    "duplex": "Auto",
                    "ipv4": [
                        {
                            "address": "192.168.0.2",
                            "subnet": "24"
                        }
                    ],
                    "lineprotocol": "down",
                    "macaddress": "0c05.2bf9.3e02",
                    "mediatype": "RJ45",
                    "mtu": 1500,
                    "operstatus": "down",
                    "type": "iGbE"
                },
                "GigabitEthernet0/3": {
                    "bandwidth": 100000,
                    "description": "Configured and Merged by Ansible Network",
                    "duplex": "Full",
                    "ipv4": [],
                    "ipv6": [
                        {
                            "address": "1:11:11:11",
                            "subnet": "11:11:11:11:11:11:11:11/64 [TEN]"
                        }
                    ],
                    "lineprotocol": "down",
                    "macaddress": "0c05.2bf9.3e03",
                    "mediatype": "RJ45",
                    "mtu": 2800,
                    "operstatus": "administratively down",
                    "type": "iGbE"
                },
                "GigabitEthernet0/3.100": {
                    "bandwidth": 100000,
                    "description": null,
                    "duplex": null,
                    "ipv4": [],
                    "lineprotocol": "down",
                    "macaddress": "0c05.2bf9.3e03",
                    "mediatype": null,
                    "mtu": 2800,
                    "operstatus": "administratively down",
                    "type": "iGbE"
                }
            },
            "net_iostype": "IOS",
            "net_memfree_mb": 244233.24609375,
            "net_memtotal_mb": 310087.16796875,
            "net_model": "IOSv",
            "net_neighbors": {},
            "net_python_version": "3.9.5",
            "net_serialnum": "XXXX",
            "net_system": "ios",
            "net_version": "15.7(3)M3",
            "network_resources": {},
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * net_api: cliconf
>  * net_config: !
>! Last configuration change at 08:56:26 UTC Sun Jul 11 2021 by admin
>!
>version 15.7
>service timestamps debug datetime msec
>service timestamps log datetime msec
>no service password-encryption
>!
>hostname IOSv01
>!
>boot-start-marker
>boot-end-marker
>!
>!
>enable secret 5 $1$abcdefghijklmnopqrstuvwxyz.
>!
>no aaa new-model
>!
>!
>!
>mmi polling-interval 60
>no mmi auto-configure
>no mmi pvc
>mmi snmp-timeout 180
>!
>no ip icmp rate-limit unreachable
>!
>ip domain list ansible.com
>ip domain list redhat.com
>ip domain list cisco.com
>no ip domain lookup
>ip domain name test.example.com
>ip cef
>no ipv6 cef
>!
>multilink bundle-name authenticated
>!
>!
>!
>!
>username admin password 0 abcdef
>username ansible nopassword
>!
>redundancy
>!
>lldp timer 10
>lldp holdtime 10
>lldp reinit 3
>lldp run
>no cdp log mismatch duplex
>!
>ip tcp synwait-time 5
>! 
>interface GigabitEthernet0/0
> ip address 123.123.123.123 255.255.255.0
> duplex auto
> speed auto
> media-type rj45
>!
>interface GigabitEthernet0/1
> no ip address
> shutdown
> duplex auto
> speed auto
> media-type rj45
>!
>interface GigabitEthernet0/2
> description Configured and Merged by Ansible Network
> ip address 192.168.0.2 255.255.255.0
> duplex auto
> speed auto
> media-type rj45
>!
>interface GigabitEthernet0/3
> description Configured and Merged by Ansible Network
> mtu 2800
> no ip address
> shutdown
> duplex full
> speed 100
> media-type rj45
> ipv6 address 1:11:11:11/64
>!
>interface GigabitEthernet0/3.100
>!
>router bgp 64496
> bgp router-id 192.0.2.1
> bgp log-neighbor-changes
> neighbor 1.1.1.2 remote-as 64498
> neighbor 1.1.1.1 remote-as 64511
> neighbor 1.1.1.1 timers 300 360 360
> !
> address-family ipv4
>  network 192.0.2.0 mask 255.255.254.0
>  network 198.51.100.0 route-map RMAP_1
>  redistribute ospf 223 metric 10
>  neighbor 1.1.1.2 activate
>  neighbor 1.1.1.1 activate
> exit-address-family
>!
>ip default-gateway 192.168.1.1
>ip forward-protocol nd
>!
>!
>no ip http server
>no ip http secure-server
>ip route 192.168.2.0 255.255.255.0 10.0.0.1
>ip ssh version 2
>ip ssh pubkey-chain
>  username ansible
>   key-hash ssh-rsa B1E29F17C950E2FEAB5BC3AC2A760208 
>ip ssh server algorithm mac hmac-sha2-256
>!
>logging host 172.16.0.1
>ipv6 ioam timestamp
>!
>!
>!
>control-plane
>!
>banner exec ^C
>**************************************************************************
>* IOSv is strictly limited to use for evaluation, demonstration and IOS  *
>* education. IOSv is provided as-is and is not supported by Cisco's      *
>* Technical Advisory Center. Any use or disclosure, in whole or in part, *
>* of the IOSv Software or Documentation to any third party for any       *
>* purposes is expressly prohibited except as otherwise authorized by     *
>* Cisco in writing.                                                      *
>**************************************************************************^C
>banner incoming ^C
>**************************************************************************
>* IOSv is strictly limited to use for evaluation, demonstration and IOS  *
>* education. IOSv is provided as-is and is not supported by Cisco's      *
>* Technical Advisory Center. Any use or disclosure, in whole or in part, *
>* of the IOSv Software or Documentation to any third party for any       *
>* purposes is expressly prohibited except as otherwise authorized by     *
>* Cisco in writing.                                                      *
>**************************************************************************^C
>banner login ^C
>this is my login banner
>^C
>!
>line con 0
> exec-timeout 0 0
> privilege level 15
> logging synchronous
>line aux 0
> exec-timeout 0 0
> privilege level 15
> logging synchronous
>line vty 0 4
> login local
> transport input ssh
>!
>no scheduler allocate
>ntp server 1.1.1.3
>!
>end
>  * net_hostname: IOSv01
>  * net_image: flash0:/vios-adventerprisek9-m
>  * net_iostype: IOS
>  * net_memfree_mb: 244233.24609375
>  * net_memtotal_mb: 310087.16796875
>  * net_model: IOSv
>  * net_python_version: 3.9.5
>  * net_serialnum: XXXX
>  * net_system: ios
>  * net_version: 15.7(3)M3
>  * discovered_interpreter_python: /usr/local/bin/python
>  * ## Net_All_Ipv4_Addresses
>    * 0: 123.123.123.123
>    * 1: 192.168.0.2
>  * ## Net_All_Ipv6_Addresses
>    * 0: 1:11:11:11
>  * ## Net_Filesystems
>    * 0: flash0:
>  * ## Net_Filesystems_Info
>    * ### Flash0:
>      * spacefree_kb: 1941968.0
>      * spacetotal_kb: 2092496.0
>  * ## Net_Gather_Network_Resources
>  * ## Net_Gather_Subset
>    * 0: interfaces
>    * 1: default
>    * 2: hardware
>    * 3: config
>  * ## Net_Interfaces
>    * ### Gigabitethernet0/0
>      * bandwidth: 1000000
>      * description: None
>      * duplex: Auto
>      * lineprotocol: up
>      * macaddress: 0c05.2bf9.3e00
>      * mediatype: RJ45
>      * mtu: 1500
>      * operstatus: up
>      * type: iGbE
>      * #### Ipv4
>      * #### List
>        * address: 123.123.123.123
>        * subnet: 24
>    * ### Gigabitethernet0/1
>      * bandwidth: 1000000
>      * description: None
>      * duplex: Auto
>      * lineprotocol: down
>      * macaddress: 0c05.2bf9.3e01
>      * mediatype: RJ45
>      * mtu: 1500
>      * operstatus: administratively down
>      * type: iGbE
>      * #### Ipv4
>    * ### Gigabitethernet0/2
>      * bandwidth: 1000000
>      * description: Configured and Merged by Ansible Network
>      * duplex: Auto
>      * lineprotocol: down
>      * macaddress: 0c05.2bf9.3e02
>      * mediatype: RJ45
>      * mtu: 1500
>      * operstatus: down
>      * type: iGbE
>      * #### Ipv4
>      * #### List
>        * address: 192.168.0.2
>        * subnet: 24
>    * ### Gigabitethernet0/3
>      * bandwidth: 100000
>      * description: Configured and Merged by Ansible Network
>      * duplex: Full
>      * lineprotocol: down
>      * macaddress: 0c05.2bf9.3e03
>      * mediatype: RJ45
>      * mtu: 2800
>      * operstatus: administratively down
>      * type: iGbE
>      * #### Ipv4
>      * #### Ipv6
>      * #### List
>        * address: 1:11:11:11
>        * subnet: 11:11:11:11:11:11:11:11/64 [TEN]
>    * ### Gigabitethernet0/3.100
>      * bandwidth: 100000
>      * description: None
>      * duplex: None
>      * lineprotocol: down
>      * macaddress: 0c05.2bf9.3e03
>      * mediatype: None
>      * mtu: 2800
>      * operstatus: administratively down
>      * type: iGbE
>      * #### Ipv4
>  * ## Net_Neighbors
>  * ## Network_Resources


### ios-interfaces
***
Manages interface attributes of Cisco IOS network devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_interfaces_module.html


#### Base Command

`ios-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of interface options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosInterfaces.commands | unknown | The set of commands pushed to the remote device | 


#### Command Example
```!ios-interfaces host="123.123.123.123" config="{{ [{'name': 'GigabitEthernet0/2', 'description': 'Configured and Merged by Ansible Network', 'enabled': True}, {'name': 'GigabitEthernet0/3', 'description': 'Configured and Merged by Ansible Network', 'mtu': 2800, 'enabled': False, 'speed': 100, 'duplex': 'full'}] }}" state="merged" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosInterfaces": {
            "before": [
                {
                    "duplex": "auto",
                    "enabled": true,
                    "name": "GigabitEthernet0/0",
                    "speed": "auto"
                },
                {
                    "duplex": "auto",
                    "enabled": false,
                    "name": "GigabitEthernet0/1",
                    "speed": "auto"
                },
                {
                    "description": "Configured and Merged by Ansible Network",
                    "duplex": "auto",
                    "enabled": true,
                    "name": "GigabitEthernet0/2",
                    "speed": "auto"
                },
                {
                    "description": "Configured and Merged by Ansible Network",
                    "duplex": "full",
                    "enabled": false,
                    "mtu": 2800,
                    "name": "GigabitEthernet0/3",
                    "speed": "100"
                },
                {
                    "enabled": true,
                    "name": "GigabitEthernet0/3.100"
                }
            ],
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Before
>  * ## Gigabitethernet0/0
>    * duplex: auto
>    * enabled: True
>    * name: GigabitEthernet0/0
>    * speed: auto
>  * ## Gigabitethernet0/1
>    * duplex: auto
>    * enabled: False
>    * name: GigabitEthernet0/1
>    * speed: auto
>  * ## Gigabitethernet0/2
>    * description: Configured and Merged by Ansible Network
>    * duplex: auto
>    * enabled: True
>    * name: GigabitEthernet0/2
>    * speed: auto
>  * ## Gigabitethernet0/3
>    * description: Configured and Merged by Ansible Network
>    * duplex: full
>    * enabled: False
>    * mtu: 2800
>    * name: GigabitEthernet0/3
>    * speed: 100
>  * ## Gigabitethernet0/3.100
>    * enabled: True
>    * name: GigabitEthernet0/3.100
>  * ## Commands


### ios-l2-interfaces
***
Manage Layer-2 interface on Cisco IOS devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_l2_interfaces_module.html


#### Base Command

`ios-l2-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of Layer-2 interface options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosL2Interfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosL2Interfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosL2Interfaces.commands | unknown | The set of commands pushed to the remote device | 



### ios-l3-interfaces
***
Manage Layer-3 interface on Cisco IOS devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_l3_interfaces_module.html


#### Base Command

`ios-l3-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of Layer-3 interface options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosL3Interfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosL3Interfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosL3Interfaces.commands | unknown | The set of commands pushed to the remote device | 


#### Command Example
```!ios-l3-interfaces host="123.123.123.123" config="{{ [{'name': 'GigabitEthernet0/3', 'ipv4': [{'address': '192.168.0.1/24', 'secondary': True}]}, {'name': 'GigabitEthernet0/2', 'ipv4': [{'address': '192.168.0.2/24'}]}, {'name': 'GigabitEthernet0/3', 'ipv6': [{'address': '1:11:11:11/64'}]}, {'name': 'GigabitEthernet0/3.100', 'ipv4': [{'address': '192.168.0.3/24'}]}] }}" state="merged" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosL3Interfaces": {
            "after": [
                {
                    "ipv4": [
                        {
                            "address": "123.123.123.123 255.255.255.0"
                        }
                    ],
                    "name": "GigabitEthernet0/0"
                },
                {
                    "name": "GigabitEthernet0/1"
                },
                {
                    "ipv4": [
                        {
                            "address": "192.168.0.2 255.255.255.0"
                        }
                    ],
                    "name": "GigabitEthernet0/2"
                },
                {
                    "ipv6": [
                        {
                            "address": "1:11:11:11/64"
                        }
                    ],
                    "name": "GigabitEthernet0/3"
                },
                {
                    "name": "GigabitEthernet0/3.100"
                }
            ],
            "before": [
                {
                    "ipv4": [
                        {
                            "address": "123.123.123.123 255.255.255.0"
                        }
                    ],
                    "name": "GigabitEthernet0/0"
                },
                {
                    "name": "GigabitEthernet0/1"
                },
                {
                    "ipv4": [
                        {
                            "address": "192.168.0.2 255.255.255.0"
                        }
                    ],
                    "name": "GigabitEthernet0/2"
                },
                {
                    "ipv6": [
                        {
                            "address": "1:11:11:11/64"
                        }
                    ],
                    "name": "GigabitEthernet0/3"
                },
                {
                    "name": "GigabitEthernet0/3.100"
                }
            ],
            "changed": true,
            "commands": [
                "interface GigabitEthernet0/3",
                "ip address 192.168.0.1 255.255.255.0 secondary",
                "interface GigabitEthernet0/3.100",
                "ip address 192.168.0.3 255.255.255.0"
            ],
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## After
>  * ## Gigabitethernet0/0
>    * name: GigabitEthernet0/0
>    * ### Ipv4
>    * ### List
>      * address: 123.123.123.123 255.255.255.0
>  * ## Gigabitethernet0/1
>    * name: GigabitEthernet0/1
>  * ## Gigabitethernet0/2
>    * name: GigabitEthernet0/2
>    * ### Ipv4
>    * ### List
>      * address: 192.168.0.2 255.255.255.0
>  * ## Gigabitethernet0/3
>    * name: GigabitEthernet0/3
>    * ### Ipv6
>    * ### List
>      * address: 1:11:11:11/64
>  * ## Gigabitethernet0/3.100
>    * name: GigabitEthernet0/3.100
>  * ## Before
>  * ## Gigabitethernet0/0
>    * name: GigabitEthernet0/0
>    * ### Ipv4
>    * ### List
>      * address: 123.123.123.123 255.255.255.0
>  * ## Gigabitethernet0/1
>    * name: GigabitEthernet0/1
>  * ## Gigabitethernet0/2
>    * name: GigabitEthernet0/2
>    * ### Ipv4
>    * ### List
>      * address: 192.168.0.2 255.255.255.0
>  * ## Gigabitethernet0/3
>    * name: GigabitEthernet0/3
>    * ### Ipv6
>    * ### List
>      * address: 1:11:11:11/64
>  * ## Gigabitethernet0/3.100
>    * name: GigabitEthernet0/3.100
>  * ## Commands
>    * 0: interface GigabitEthernet0/3
>    * 1: ip address 192.168.0.1 255.255.255.0 secondary
>    * 2: interface GigabitEthernet0/3.100
>    * 3: ip address 192.168.0.3 255.255.255.0


### ios-lacp
***
Manage Global Link Aggregation Control Protocol (LACP) on Cisco IOS devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_lacp_module.html


#### Base Command

`ios-lacp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | The provided configurations. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLacp.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosLacp.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosLacp.commands | unknown | The set of commands pushed to the remote device. | 



### ios-lacp-interfaces
***
Manage Link Aggregation Control Protocol (LACP) on Cisco IOS devices interface.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_lacp_interfaces_module.html


#### Base Command

`ios-lacp-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of LACP lacp_interfaces option. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLacpInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosLacpInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosLacpInterfaces.commands | unknown | The set of commands pushed to the remote device. | 



### ios-lag-interfaces
***
Manage Link Aggregation on Cisco IOS devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_lag_interfaces_module.html


#### Base Command

`ios-lag-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A list of link aggregation group configurations. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLagInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosLagInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosLagInterfaces.commands | unknown | The set of commands pushed to the remote device | 



### ios-linkagg
***
Manage link aggregation groups on Cisco IOS network devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_linkagg_module.html


#### Base Command

`ios-linkagg`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| group | Channel-group number for the port-channel Link aggregation group. Range 1-255. | Optional | 
| mode | Mode of the link aggregation group. Possible values are: active, on, passive, auto, desirable. | Optional | 
| members | List of members of the link aggregation group. | Optional | 
| aggregate | List of link aggregation definitions. | Optional | 
| state | State of the link aggregation group. Possible values are: present, absent. Default is present. | Optional | 
| purge | Purge links not defined in the `aggregate` parameter. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLinkagg.commands | unknown | The list of configuration mode commands to send to the device | 



### ios-lldp
***
Manage LLDP configuration on Cisco IOS network devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_lldp_module.html


#### Base Command

`ios-lldp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | State of the LLDP configuration. If value is `present` lldp will be enabled else if it is `absent` it will be disabled. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLldp.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-lldp host="123.123.123.123" state="present" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosLldp": {
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Commands


### ios-lldp-global
***
Configure and manage Link Layer Discovery Protocol(LLDP) attributes on IOS platforms.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_lldp_global_module.html


#### Base Command

`ios-lldp-global`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of LLDP options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLldpGlobal.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosLldpGlobal.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosLldpGlobal.commands | unknown | The set of commands pushed to the remote device | 


#### Command Example
```!ios-lldp-global host="123.123.123.123" config="{{ {'holdtime': 10, 'enabled': True, 'reinit': 3, 'timer': 10} }}" state="merged" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosLldpGlobal": {
            "before": {
                "enabled": true,
                "holdtime": 10,
                "reinit": 3,
                "timer": 10
            },
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Before
>    * enabled: True
>    * holdtime: 10
>    * reinit: 3
>    * timer: 10
>  * ## Commands


### ios-lldp-interfaces
***
Manage link layer discovery protocol (LLDP) attributes of interfaces on Cisco IOS devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_lldp_interfaces_module.html


#### Base Command

`ios-lldp-interfaces`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of LLDP options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLldpInterfaces.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosLldpInterfaces.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosLldpInterfaces.commands | unknown | The set of commands pushed to the remote device. | 


#### Command Example
```!ios-lldp-interfaces host="123.123.123.123" config="{{ [{'name': 'GigabitEthernet0/1', 'receive': True, 'transmit': True}, {'name': 'GigabitEthernet0/2', 'receive': True}, {'name': 'GigabitEthernet0/3', 'transmit': True}] }}" state="merged" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosLldpInterfaces": {
            "before": [
                {
                    "name": "GigabitEthernet0/0",
                    "receive": true,
                    "transmit": true
                },
                {
                    "name": "GigabitEthernet0/1",
                    "receive": true,
                    "transmit": true
                },
                {
                    "name": "GigabitEthernet0/2",
                    "receive": true,
                    "transmit": true
                },
                {
                    "name": "GigabitEthernet0/3",
                    "receive": true,
                    "transmit": true
                },
                {
                    "name": "GigabitEthernet0/3.100",
                    "receive": true,
                    "transmit": true
                }
            ],
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Before
>  * ## Gigabitethernet0/0
>    * name: GigabitEthernet0/0
>    * receive: True
>    * transmit: True
>  * ## Gigabitethernet0/1
>    * name: GigabitEthernet0/1
>    * receive: True
>    * transmit: True
>  * ## Gigabitethernet0/2
>    * name: GigabitEthernet0/2
>    * receive: True
>    * transmit: True
>  * ## Gigabitethernet0/3
>    * name: GigabitEthernet0/3
>    * receive: True
>    * transmit: True
>  * ## Gigabitethernet0/3.100
>    * name: GigabitEthernet0/3.100
>    * receive: True
>    * transmit: True
>  * ## Commands


### ios-logging
***
Manage logging on network devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_logging_module.html


#### Base Command

`ios-logging`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dest | Destination of the logs. Possible values are: on, host, console, monitor, buffered, trap. | Optional | 
| name | The hostname or IP address of the destination. Required when `dest=host`. | Optional | 
| size | Size of buffer. The acceptable value is in range from 4096 to 4294967295 bytes. Default is 4096. | Optional | 
| facility | Set logging facility. | Optional | 
| level | Set logging severity levels. Possible values are: emergencies, alerts, critical, errors, warnings, notifications, informational, debugging. Default is debugging. | Optional | 
| aggregate | List of logging definitions. | Optional | 
| state | State of the logging configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosLogging.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-logging host="123.123.123.123" dest="host" name="172.16.0.1" state="present" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosLogging": {
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Commands


### ios-ntp
***
Manages core NTP configuration.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_ntp_module.html


#### Base Command

`ios-ntp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| server | Network address of NTP server. | Optional | 
| source_int | Source interface for NTP packets. | Optional | 
| acl | ACL for peer/server access restricition. | Optional | 
| logging | Enable NTP logs. Data type boolean. Possible values are: Yes, No. Default is No. | Optional | 
| auth | Enable NTP authentication. Data type boolean. Possible values are: Yes, No. Default is No. | Optional | 
| auth_key | md5 NTP authentication key of type 7. | Optional | 
| key_id | auth_key id. Data type string. | Optional | 
| state | Manage the state of the resource. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosNtp.commands | unknown | command sent to the device | 


#### Command Example
```!ios-ntp host="123.123.123.123" server="1.1.1.3" source_int="GigabitEthernet0/1" logging="False" state="present" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosNtp": {
            "changed": true,
            "commands": [
                "ntp source GigabitEthernet0/1"
            ],
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: ntp source GigabitEthernet0/1


### ios-ping
***
Tests reachability using ping from Cisco IOS network devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_ping_module.html


#### Base Command

`ios-ping`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| count | Number of packets to send. Default is 5. | Optional | 
| dest | The IP Address or hostname (resolvable by switch) of the remote node. | Required | 
| source | The source IP Address. | Optional | 
| state | Determines if the expected result is success or fail. Possible values are: absent, present. Default is present. | Optional | 
| vrf | The VRF to use for forwarding. Default is default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosPing.commands | unknown | Show the command sent. | 
| CiscoIOS.IosPing.packet_loss | string | Percentage of packets lost. | 
| CiscoIOS.IosPing.packets_rx | number | Packets successfully received. | 
| CiscoIOS.IosPing.packets_tx | number | Packets successfully transmitted. | 
| CiscoIOS.IosPing.rtt | unknown | Show RTT stats. | 



### ios-static-route
***
Manage static IP routes on Cisco IOS network devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_static_route_module.html


#### Base Command

`ios-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| prefix | Network prefix of the static route. | Optional | 
| mask | Network prefix mask of the static route. | Optional | 
| next_hop | Next hop IP of the static route. | Optional | 
| vrf | VRF of the static route. | Optional | 
| interface | Interface of the static route. | Optional | 
| name | Name of the static route. | Optional | 
| admin_distance | Admin distance of the static route. | Optional | 
| tag | Set tag of the static route. | Optional | 
| track | Tracked item to depend on for the static route. | Optional | 
| aggregate | List of static route definitions. | Optional | 
| state | State of the static route configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosStaticRoute.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-static-route host="123.123.123.123" prefix="192.168.2.0" mask="255.255.255.0" next_hop="10.0.0.1" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosStaticRoute": {
            "changed": false,
            "commands": [],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Commands


### ios-system
***
Manage the system attributes on Cisco IOS devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_system_module.html


#### Base Command

`ios-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| hostname | Configure the device hostname parameter. This option takes an ASCII string value. | Optional | 
| domain_name | Configure the IP domain name on the remote device to the provided value. Value should be in the dotted name form and will be appended to the `hostname` to create a fully-qualified domain name. | Optional | 
| domain_search | Provides the list of domain suffixes to append to the hostname for the purpose of doing name resolution. This argument accepts a list of names and will be reconciled with the current active configuration on the running node. | Optional | 
| lookup_source | Provides one or more source interfaces to use for performing DNS lookups.  The interface provided in `lookup_source` must be a valid interface configured on the device. | Optional | 
| lookup_enabled | Administrative control for enabling or disabling DNS lookups.  When this argument is set to True, lookups are performed and when it is set to False, lookups are not performed. | Optional | 
| name_servers | List of DNS name servers by IP address to use to perform name resolution lookups.  This argument accepts either a list of DNS servers See examples. | Optional | 
| state | State of the configuration values in the device's current active configuration.  When set to `present`, the values should be configured in the device active configuration and when set to `absent` the values should not be in the device active configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosSystem.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-system host="123.123.123.123" hostname="ios01" domain_name="test.example.com" domain_search="{{ ['ansible.com', 'redhat.com', 'cisco.com'] }}" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosSystem": {
            "changed": true,
            "commands": [
                "hostname ios01"
            ],
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: hostname ios01


### ios-user
***
Manage the aggregate of local users on Cisco IOS device
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_user_module.html


#### Base Command

`ios-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| aggregate | The set of username objects to be configured on the remote Cisco IOS device. The list entries can either be the username or a hash of username and properties. This argument is mutually exclusive with the `name` argument. | Optional | 
| name | The username to be configured on the Cisco IOS device. This argument accepts a string value and is mutually exclusive with the `aggregate` argument. Please note that this option is not same as `provider username`. | Optional | 
| configured_password | The password to be configured on the Cisco IOS device. The password needs to be provided in clear and it will be encrypted on the device. Please note that this option is not same as `provider password`. | Optional | 
| update_password | Since passwords are encrypted in the device running config, this argument will instruct the module when to change the password.  When set to `always`, the password will always be updated in the device and when set to `on_create` the password will be updated only if the username is created. Possible values are: on_create, always. Default is always. | Optional | 
| password_type | This argument determines whether a 'password' or 'secret' will be configured. Possible values are: secret, password. Default is secret. | Optional | 
| hashed_password | This option allows configuring hashed passwords on Cisco IOS devices. | Optional | 
| privilege | The `privilege` argument configures the privilege level of the user when logged into the system. This argument accepts integer values in the range of 1 to 15. | Optional | 
| view | Configures the view for the username in the device running configuration. The argument accepts a string value defining the view name. This argument does not check if the view has been configured on the device. | Optional | 
| sshkey | Specifies one or more SSH public key(s) to configure for the given username. This argument accepts a valid SSH key value. | Optional | 
| nopassword | Defines the username without assigning a password. This will allow the user to login to the system without being authenticated by a password. | Optional | 
| purge | Instructs the module to consider the resource definition absolute. It will remove any previously configured usernames on the device with the exception of the `admin` user (the current defined set of users). Possible values are: Yes, No. Default is No. | Optional | 
| state | Configures the state of the username definition as it relates to the device operational configuration. When set to `present`, the username(s) should be configured in the device active configuration and when set to `absent` the username(s) should not be in the device active configuration. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosUser.commands | unknown | The list of configuration mode commands to send to the device | 


#### Command Example
```!ios-user host="123.123.123.123" name="ansible" nopassword="True" sshkey="ssh-rsa AAAA...u+DM=" state="present" ```

#### Context Example
```json
{
    "CiscoIOS": {
        "IosUser": {
            "changed": true,
            "commands": [
                "ip ssh pubkey-chain",
                "username ansible",
                "key-hash ssh-rsa B1E29F17C950E2FEAB5BC3AC2A760208",
                "exit",
                "exit"
            ],
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Commands
>    * 0: ip ssh pubkey-chain
>    * 1: username ansible
>    * 2: key-hash ssh-rsa B1E29F17C950E2FEAB5BC3AC2A760208
>    * 3: exit
>    * 3: exit


### ios-vlans
***
Manage VLANs on Cisco IOS devices.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_vlans_module.html


#### Base Command

`ios-vlans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| config | A dictionary of VLANs options. | Optional | 
| state | The state of the configuration after module completion. Possible values are: merged, replaced, overridden, deleted. Default is merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosVlans.before | unknown | The configuration as structured data prior to module invocation. | 
| CiscoIOS.IosVlans.after | unknown | The configuration as structured data after module completion. | 
| CiscoIOS.IosVlans.commands | unknown | The set of commands pushed to the remote device. | 



### ios-vrf
***
Manage the collection of VRF definitions on Cisco IOS devices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ios_vrf_module.html


#### Base Command

`ios-vrf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| vrfs | The set of VRF definition objects to be configured on the remote IOS device.  Ths list entries can either be the VRF name or a hash of VRF definitions and attributes.  This argument is mutually exclusive with the `name` argument. | Optional | 
| name | The name of the VRF definition to be managed on the remote IOS device.  The VRF definition name is an ASCII string name used to uniquely identify the VRF.  This argument is mutually exclusive with the `vrfs` argument. | Optional | 
| description | Provides a short description of the VRF definition in the current active configuration.  The VRF definition value accepts alphanumeric characters used to provide additional information about the VRF. | Optional | 
| rd | The router-distinguisher value uniquely identifies the VRF to routing processes on the remote IOS system.  The RD value takes the form of `A:B` where `A` and `B` are both numeric values. | Optional | 
| interfaces | Identifies the set of interfaces that should be configured in the VRF.  Interfaces must be routed interfaces in order to be placed into a VRF. | Optional | 
| associated_interfaces | This is a intent option and checks the operational state of the for given vrf `name` for associated interfaces. If the value in the `associated_interfaces` does not match with the operational state of vrf interfaces on device it will result in failure. | Optional | 
| delay | Time in seconds to wait before checking for the operational state on remote device. Default is 10. | Optional | 
| purge | Instructs the module to consider the VRF definition absolute.  It will remove any previously configured VRFs on the device. Possible values are: Yes, No. Default is No. | Optional | 
| state | Configures the state of the VRF definition as it relates to the device operational configuration.  When set to `present`, the VRF should be configured in the device active configuration and when set to `absent` the VRF should not be in the device active configuration. Possible values are: present, absent. Default is present. | Optional | 
| route_both | Adds an export and import list of extended route target communities to the VRF. | Optional | 
| route_export | Adds an export list of extended route target communities to the VRF. | Optional | 
| route_import | Adds an import list of extended route target communities to the VRF. | Optional | 
| route_both_ipv4 | Adds an export and import list of extended route target communities in address-family configuration submode to the VRF. | Optional | 
| route_export_ipv4 | Adds an export list of extended route target communities in address-family configuration submode to the VRF. | Optional | 
| route_import_ipv4 | Adds an import list of extended route target communities in address-family configuration submode to the VRF. | Optional | 
| route_both_ipv6 | Adds an export and import list of extended route target communities in address-family configuration submode to the VRF. | Optional | 
| route_export_ipv6 | Adds an export list of extended route target communities in address-family configuration submode to the VRF. | Optional | 
| route_import_ipv6 | Adds an import list of extended route target communities in address-family configuration submode to the VRF. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoIOS.IosVrf.commands | unknown | The list of configuration mode commands to send to the device | 
| CiscoIOS.IosVrf.start | string | The time the job started | 
| CiscoIOS.IosVrf.end | string | The time the job ended | 
| CiscoIOS.IosVrf.delta | string | The time elapsed to perform all operations | 


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
