## Netmiko SSH module integration

  This integration provides ssh-based access to network devices, servers, and other appliances that support this method of configuration. For a complete list of supported platforms, please visit the below URL:

  [Netmiko Platforms.md on Github](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md)

## Configure Netmiko Integration in Cortex XSOAR

 1. Navigate to **Settings** - **Integrations**
 2. Search for **Netmiko**
 3. Click **Add instance** to create and configure a new integration instance.
	 - **Name**: a name for the integration instance.
	 - **Platform**: the platform identifier taken from the above SSH or Telnet platform name lists (e.g., linux_ssh, paloalto_panos, etc.)
**NOTE**: Platform names are taken from the supported
[SSH](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md#supported-ssh-device_type-values) or [Telnet](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md#supported-telnet-device_type-values) device type lists on GitHub.
	 - **Hostname**: The IP address, hostname, or FQDN for the device to connect to via SSH.
	 - **Port**: The port to connect to via SSH
	 - **Credentials**: The username/password, or XSOAR credential object, to be used for the connection
	 - **Override the default timeout value**: Override the timeout value (in seconds) for a given integration instance. This is useful for devices that are slow in responding with requested output over SSH.
4. Click **Test** to validate the new instance. This performs a simple connection to the system hosting the SSH server.

## Commands

  The Netmiko integration currently only supports the netmiko-cmds command for SSH. This command can be used via the XSOAR CLI, as part of an automation, or as a task in an XSOAR playbook. Like other XSOAR commands, this object can be passed a single command, a list of commands, or an array of commands to execute in a single session. 

1. [Executes a command, or series of commands, over an SSH connection: netmiko-cmds](#netmiko-cmds)

## netmiko-cmds
Executes a command, or series of commands, over an SSH connection. Outputs from the executed commands are returned to the incident/playground context.

#### Base Command
`netmiko-cmds`

#### Input
------------------
| **Argument Name** | **Description**  | **Required** |
|--|--|--|
|cmds|The command, or commands, to execute. When commands are manually specified and executed via the XSOAR CLI or in a task, place each command after the first on a new line (no comma required)|Required|
|disable_context|The package ID. Package ID or package name is required. When both exist, ID is used.|Optional|
|exit_argument|The optional **exit** command to be executed after the **cmds** parameter. This is tied to the **requires_exit** optional parameter. (Default: **q**)|Optional|
|isConfig|Specifies whether or not the commands being executed require a **configure** command to be executed first (e.g., **conf t** for Cisco IOS). The specific configure command is handled by the Netmiko Python module, and is associated with the **Platform** parameter specified in the integration instance. (Default: **False**)|Optional|
|override_host|If specified, uses this host in place of the one specified in the instance configuration.|Optional|
|override_password|If specified, uses this password in place of the one specified in the instance configuration.|Optional|
|override_platform|If specified, uses this platform name in place of the one specified in the instance configuration.|Optional|
|override_port|If specified, uses this port in place of the one specified in the instance configuration.|Optional|
|override_username|If specified, uses this username in place of the one specified in the instance configuration.|Optional|
|raw_print|Prints the raw output directly to the war room (Default: **False**)|Optional|
|require_enable|Specifies whether or not the **enable** command must be executed before the commands specified in the cmds parameter. (Default: **False**)|Optional|
|require_exit|Specifies an optional command that must be executed upon completion of the cmds parameter being executed. (Default: **False**)|Optional|

#### Context Output 
|**Path**|**Type**|**Description**|
|--|--|--|
|Netmiko.Command|String|The executed command(s)|
|Netmiko.DateTimeUTC|DateTime|The datetime at which the command(s) were executed (in UTC)|
|Netmiko.Hostname|String|The hostname used for this execution of the integration|
|Netmiko.Output|String|The results of the command(s) that were executed|

#### Command Example (Single command)
`!netmiko-cmds cmds="whoami"`
#### Context Example

>{<br> 	
>&emsp;"Command": "whoami",<br>
>&emsp;"DateTimeUTC": "2023-04-24T21:40:21.755985",<br>
>&emsp;"Hostname": "192.168.0.1",<br>
>&emsp;"Output": "[someuser@someserver ~]$ root"<br>
>}<br>

#### Human Readable Output
#### Command(s) against 192.168.0.1 (linux)
|**Command**|**DateTimeUTC**|**Hostname**|**Output**|
|--|--|--|--|
|whoami|2023-04-24T21:40:21.755985|192.168.0.1|root|

### Command Example (Multiple commands)
#### As multiple commands via CLI or task

`!netmiko-cmds cmds="whoami`
`who"`

#### As multiple commands via CLI or task using an array 
`array context key = ["whoami", "who"]`
`!netmiko-cmds cmds=${array}`

#### Context Example

>{<br>
>&emsp;"Netmiko": [{<br>
>&emsp;&emsp;"Command": "whoami",<br>
>&emsp;&emsp;"DateTimeUTC": "2023-04-24T21:59:02.177240",<br>
>&emsp;&emsp;"Hostname": "192.168.0.1",<br>
>&emsp;&emsp;"Output": "[someuser@somehost ~]$ root"<br>
>&emsp;},<br>
>&emsp;{<br>
>&emsp;&emsp;"Command": "who",<br>
>&emsp;&emsp;"DateTimeUTC": "2023-04-24T21:59:04.882842",<br>
>&emsp;&emsp;"Hostname": "192.168.0.1",<br>
>&emsp;&emsp;"Output": "[someuser@somehost ~]$ root pts/0        2023-04-24 17:58 (192.168.0.1)"<br>
>&emsp;}]<br>
>}<br>

#### Human Readable Output
#### Command(s) against 192.168.0.1 (linux)
|**Command**|**DateTimeUTC**|**Hostname**|**Output**|
|--|--|--|--|
|whoami|2023-04-24T21:59:02.177240|192.168.0.1|root|
|who|2023-04-24T21:59:04.882842|192.168.0.1|[someuser@somehost ~]$ root pts/0        2023-04-24 17:58 (192.168.0.1)|