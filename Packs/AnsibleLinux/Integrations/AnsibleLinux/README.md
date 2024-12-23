This integration enables the management of Linux hosts directly from XSOAR using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the hosts by utilising SSH combined with Python.

To use this integration, configure an instance of this integration. This will associate a credential to be used to access hosts when commands are run. The commands from this integration will take the Linux host address(es) as an input, and use the saved credential associated to the instance to execute. Create separate instances if multiple credentials are required.

## Requirements
The Linux host(s) being managed requires Python >= 2.6. Different commands will use different underlying Ansible modules, and may have their own unique package requirements. Refer to the individual command documentation for further information.

## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the Linux host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.

## Credentials
This integration supports a number of methods of authenticating with the Linux Host:
1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions
Whilst un-privileged Linux user privileges can be used, a SuperUser account is recommended as most commands will require elevated permissions to execute.

## Privilege Escalation
Ansible can use existing privilege escalation systems to allow a user to execute tasks as another. Different from the user that logged into the machine (remote user). This is done using existing privilege escalation tools, which you probably already use or have configured, like sudo, su, or doas. Unless you are remoting into the system as root (uid 0) you will need to escalate your privileges to a super user. Use the Integration parameters `Escalate Privileges`, `Privilege Escalation Method`, `Privilege Escalation User`, `Privileges Escalation Password` to configure this.

## Concurrency
This integration supports execution of commands against multiple hosts concurrently. The `host` parameter accepts a list of addresses, and will run the command in parallel as per the **Concurrency Factor** value.

## Further information
This integration is powered by Ansible 2.9. Further information can be found on that the following locations:
* [Ansible Getting Started](https://docs.ansible.com/ansible/latest/user_guide/intro_getting_started.html)
* [Module Documentation](https://docs.ansible.com/ansible/2.9/modules/list_of_all_modules.html)

## Configure Ansible Linux in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | The credentials to associate with the instance. SSH keys can be configured using the credential manager. | True |
| Password |  | True |
| Default SSH Port | The default port to use if one is not specified in the commands \`host\` argument. | True |
| Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |
| Escalate Privileges | Ansible allows you to ‘become’ another user, different from the user that<br/>logged into the machine \(remote user\).<br/> | True |
| Privilege Escalation Method | Which privilege escalation method should be used. | True |
| Privilege Escalation User | Set the user you become through privilege escalation | False |
| Privilege Escalation Password | Set the privilege escalation password. | False |

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!linux-gather-facts`command providing an example `host` as the command argument. This command will connect to the specified host with the configured credentials in the integration, and if successful output general information about the host.

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
### linux-alternatives
***
Manages alternative programs for common commands
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/alternatives_module.html


#### Base Command

`linux-alternatives`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The generic name of the link. | Required | 
| path | The path to the real executable that the link should point to. | Required | 
| link | The path to the symbolic link that should point to the real executable.<br/>This option is always required on RHEL-based distributions. On Debian-based distributions this option is required when the alternative `name` is unknown to the system. | Optional | 
| priority | The priority of the alternative. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-alternatives host="123.123.123.123" name="java" path="/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_3.x86_64/jre/bin/java" ```

#### Context Example
```json
{
    "Linux": {
        "Alternatives": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-at
***
Schedule the execution of a command or script file via the at command
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/at_module.html


#### Base Command

`linux-at`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| command | A command to be executed in the future. | Optional | 
| script_file | An existing script file to be executed in the future. | Optional | 
| count | The count of units in the future to execute the command or script file. | Required | 
| units | The type of units in the future to execute the command or script file. Possible values are: minutes, hours, days, weeks. | Required | 
| state | The state dictates if the command or script file should be evaluated as present(added) or absent(deleted). Possible values are: absent, present. Default is present. | Optional | 
| unique | If a matching job is present a new job will not be added. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-at host="123.123.123.123" command="ls -d / >/dev/null" count="20" units="minutes" ```

#### Context Example
```json
{
    "Linux": {
        "At": {
            "changed": true,
            "count": 20,
            "host": "123.123.123.123",
            "script_file": "/tmp/at248vavr9",
            "state": "present",
            "status": "CHANGED",
            "units": "minutes"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * count: 20
>  * script_file: /tmp/at248vavr9
>  * state: present
>  * units: minutes


### linux-authorized-key
***
Adds or removes an SSH authorized key
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/authorized_key_module.html


#### Base Command

`linux-authorized-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| user | The username on the remote host whose authorized_keys file will be modified. | Required | 
| key | The SSH public key(s), as a string or (since Ansible 1.9) url (https://github.com/username.keys). | Required | 
| path | Alternate path to the authorized_keys file.<br/>When unset, this value defaults to `~/.ssh/authorized_keys`. | Optional | 
| manage_dir | Whether this module should manage the directory of the authorized key file.<br/>If set to `yes`, the module will create the directory, as well as set the owner and permissions of an existing directory.<br/>Be sure to set `manage_dir=no` if you are using an alternate directory for authorized_keys, as set with `path`, since you could lock yourself out of SSH access.<br/>See the example below. Possible values are: Yes, No. Default is Yes. | Optional | 
| state | Whether the given key (with the given key_options) should or should not be in the file. Possible values are: absent, present. Default is present. | Optional | 
| key_options | A string of ssh key options to be prepended to the key in the authorized_keys file. | Optional | 
| exclusive | Whether to remove all other non-specified keys from the authorized_keys file.<br/>Multiple keys can be specified in a single `key` string value by separating them by newlines.<br/>This option is not loop aware, so if you use `with_` , it will be exclusive per iteration of the loop.<br/>If you want multiple keys in the file you need to pass them all to `key` in a single batch as mentioned above. Possible values are: Yes, No. Default is No. | Optional | 
| validate_certs | This only applies if using a https url as the source of the keys.<br/>If set to `no`, the SSL certificates will not be validated.<br/>This should only set to `no` used on personally controlled sites using self-signed certificates as it avoids verifying the source site.<br/>Prior to 2.1 the code worked as if this was set to `yes`. Possible values are: Yes, No. Default is Yes. | Optional | 
| comment | Change the comment on the public key.<br/>Rewriting the comment is useful in cases such as fetching it from GitHub or GitLab.<br/>If no comment is specified, the existing comment will be kept. | Optional | 
| follow | Follow path symlink instead of replacing it. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.AuthorizedKey.exclusive | boolean | If the key has been forced to be exclusive or not. | 
| Linux.AuthorizedKey.key | string | The key that the module was running against. | 
| Linux.AuthorizedKey.key_option | string | Key options related to the key. | 
| Linux.AuthorizedKey.keyfile | string | Path for authorized key file. | 
| Linux.AuthorizedKey.manage_dir | boolean | Whether this module managed the directory of the authorized key file. | 
| Linux.AuthorizedKey.path | string | Alternate path to the authorized_keys file | 
| Linux.AuthorizedKey.state | string | Whether the given key \(with the given key_options\) should or should not be in the file | 
| Linux.AuthorizedKey.unique | boolean | Whether the key is unique | 
| Linux.AuthorizedKey.user | string | The username on the remote host whose authorized_keys file will be modified | 
| Linux.AuthorizedKey.validate_certs | boolean | This only applies if using a https url as the source of the keys. If set to \`no\`, the SSL certificates will not be validated. | 


#### Command Example
```!linux-authorized-key host="123.123.123.123" user="charlie" state="present" key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/...REDACTED..uH04Ef2RICcn1iCtsqQcMZfoqFftRcGi2MyYFyRQrFs= charlie@web01" ```

#### Context Example
```json
{
    "Linux": {
        "AuthorizedKey": {
            "changed": true,
            "comment": null,
            "exclusive": false,
            "follow": false,
            "host": "123.123.123.123",
            "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/...REDACTED..uH04Ef2RICcn1iCtsqQcMZfoqFftRcGi2MyYFyRQrFs= charlie@web01",
            "key_options": null,
            "keyfile": "/home/charlie/.ssh/authorized_keys",
            "manage_dir": true,
            "path": null,
            "state": "present",
            "status": "CHANGED",
            "user": "charlie",
            "validate_certs": true
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * comment: None
>  * exclusive: False
>  * follow: False
>  * key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/...REDACTED..uH04Ef2RICcn1iCtsqQcMZfoqFftRcGi2MyYFyRQrFs= charlie@web01
>  * key_options: None
>  * keyfile: /home/charlie/.ssh/authorized_keys
>  * manage_dir: True
>  * path: None
>  * state: present
>  * user: charlie
>  * validate_certs: True


### linux-capabilities
***
Manage Linux capabilities
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/capabilities_module.html


#### Base Command

`linux-capabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Specifies the path to the file to be managed. | Required | 
| capability | Desired capability to set (with operator and flags, if state is `present`) or remove (if state is `absent`). | Required | 
| state | Whether the entry should be present or absent in the file's capabilities. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


### linux-cron
***
Manage cron.d and crontab entries
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/cron_module.html


#### Base Command

`linux-cron`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Description of a crontab entry or, if env is set, the name of environment variable.<br/>Required if `state=absent`.<br/>Note that if name is not set and `state=present`, then a new crontab entry will always be created, regardless of existing ones.<br/>This parameter will always be required in future releases. | Optional | 
| user | The specific user whose crontab should be modified.<br/>When unset, this parameter defaults to using `root`. | Optional | 
| job | The command to execute or, if env is set, the value of environment variable.<br/>The command should not contain line breaks.<br/>Required if `state=present`. | Optional | 
| state | Whether to ensure the job or environment variable is present or absent. Possible values are: absent, present. Default is present. | Optional | 
| cron_file | If specified, uses this file instead of an individual user's crontab.<br/>If this is a relative path, it is interpreted with respect to `/etc/cron.d`.<br/>If it is absolute, it will typically be `/etc/crontab`.<br/>Many linux distros expect (and some require) the filename portion to consist solely of upper- and lower-case letters, digits, underscores, and hyphens.<br/>To use the `cron_file` parameter you must specify the `user` as well. | Optional | 
| backup | If set, create a backup of the crontab before it is modified. The location of the backup is returned in the `backup_file` variable by this module. Possible values are: Yes, No. Default is No. | Optional | 
| minute | Minute when the job should run ( 0-59, *, */2, etc ). Default is *. | Optional | 
| hour | Hour when the job should run ( 0-23, *, */2, etc ). Default is *. | Optional | 
| day | Day of the month the job should run ( 1-31, *, */2, etc ). Default is *. | Optional | 
| month | Month of the year the job should run ( 1-12, *, */2, etc ). Default is *. | Optional | 
| weekday | Day of the week that the job should run ( 0-6 for Sunday-Saturday, *, etc ). Default is *. | Optional | 
| reboot | If the job should be run at reboot. This option is deprecated. Users should use special_time. Possible values are: Yes, No. Default is No. | Optional | 
| special_time | Special time specification nickname. Possible values are: annually, daily, hourly, monthly, reboot, weekly, yearly. | Optional | 
| disabled | If the job should be disabled (commented out) in the crontab.<br/>Only has effect if `state=present`. Possible values are: Yes, No. Default is No. | Optional | 
| env | If set, manages a crontab's environment variable.<br/>New variables are added on top of crontab.<br/>`name` and `value` parameters are the name and the value of environment variable. Possible values are: Yes, No. Default is No. | Optional | 
| insertafter | Used with `state=present` and `env`.<br/>If specified, the environment variable will be inserted after the declaration of specified environment variable. | Optional | 
| insertbefore | Used with `state=present` and `env`.<br/>If specified, the environment variable will be inserted before the declaration of specified environment variable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-cron host="123.123.123.123" name="check dirs" minute="0" hour="5,2" job="ls -alh > /dev/null" ```

#### Context Example
```json
{
    "Linux": {
        "Cron": {
            "changed": false,
            "envs": [
                "EMAIL"
            ],
            "host": "123.123.123.123",
            "jobs": [
                "check dirs"
            ],
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Envs
>    * 0: EMAIL
>  * ## Jobs
>    * 0: check dirs


### linux-cronvar
***
Manage variables in crontabs
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/cronvar_module.html


#### Base Command

`linux-cronvar`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the crontab variable. | Required | 
| value | The value to set this variable to.<br/>Required if `state=present`. | Optional | 
| insertafter | If specified, the variable will be inserted after the variable specified.<br/>Used with `state=present`. | Optional | 
| insertbefore | Used with `state=present`. If specified, the variable will be inserted just before the variable specified. | Optional | 
| state | Whether to ensure that the variable is present or absent. Possible values are: absent, present. Default is present. | Optional | 
| user | The specific user whose crontab should be modified.<br/>This parameter defaults to `root` when unset. | Optional | 
| cron_file | If specified, uses this file instead of an individual user's crontab.<br/>Without a leading `/`, this is assumed to be in `/etc/cron.d`.<br/>With a leading `/`, this is taken as absolute. | Optional | 
| backup | If set, create a backup of the crontab before it is modified. The location of the backup is returned in the `backup` variable by this module. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-cronvar host="123.123.123.123" name="EMAIL" value="doug@ansibmod.con.com" ```

#### Context Example
```json
{
    "Linux": {
        "Cronvar": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS",
            "vars": [
                "EMAIL"
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Vars
>    * 0: EMAIL


### linux-dconf
***
Modify and read dconf database
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/dconf_module.html


#### Base Command

`linux-dconf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| key | A dconf key to modify or read from the dconf database. | Required | 
| value | Value to set for the specified dconf key. Value should be specified in GVariant format. Due to complexity of this format, it is best to have a look at existing values in the dconf database. Required for `state=present`. | Optional | 
| state | The action to take upon the key/value. Possible values are: read, present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Dconf.value | string | value associated with the requested key | 


#### Command Example
```!linux-dconf host="123.123.123.123" key="/org/gnome/desktop/input-sources/sources" value="[('xkb', 'us'), ('xkb', 'se')]" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "Dconf": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-debconf
***
Configure a .deb package
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/debconf_module.html


#### Base Command

`linux-debconf`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of package to configure. | Required | 
| question | A debconf configuration setting. | Optional | 
| vtype | The type of the value supplied.<br/>It is highly recommended to add `no_log=True` to task while specifying `vtype=password`.<br/>`seen` was added in Ansible 2.2. Possible values are: boolean, error, multiselect, note, password, seen, select, string, text, title. | Optional | 
| value | Value to set the configuration to. | Optional | 
| unseen | Do not set 'seen' flag when pre-seeding. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-filesystem
***
Makes a filesystem
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/filesystem_module.html


#### Base Command

`linux-filesystem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| fstype | Filesystem type to be created.<br/>reiserfs support was added in 2.2.<br/>lvm support was added in 2.5.<br/>since 2.5, `dev` can be an image file.<br/>vfat support was added in 2.5<br/>ocfs2 support was added in 2.6<br/>f2fs support was added in 2.7<br/>swap support was added in 2.8. Possible values are: btrfs, ext2, ext3, ext4, ext4dev, f2fs, lvm, ocfs2, reiserfs, xfs, vfat, swap. | Required | 
| dev | Target path to device or image file. | Required | 
| force | If `yes`, allows to create new filesystem on devices that already has filesystem. Default is no. | Optional | 
| resizefs | If `yes`, if the block device and filesystem size differ, grow the filesystem into the space.<br/>Supported for `ext2`, `ext3`, `ext4`, `ext4dev`, `f2fs`, `lvm`, `xfs`, `vfat`, `swap` filesystems.<br/>XFS Will only grow if mounted.<br/>vFAT will likely fail if fatresize &lt; 1.04. Default is no. | Optional | 
| opts | List of options to be passed to mkfs command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-filesystem host="123.123.123.123" fstype="ext2" dev="/dev/sdb1" ```

#### Context Example
```json
{
    "Linux": {
        "Filesystem": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-firewalld
***
Manage arbitrary ports/services with firewalld
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/firewalld_module.html


#### Base Command

`linux-firewalld`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| service | Name of a service to add/remove to/from firewalld.<br/>The service must be listed in output of firewall-cmd --get-services. | Optional | 
| port | Name of a port or port range to add/remove to/from firewalld.<br/>Must be in the form PORT/PROTOCOL or PORT-PORT/PROTOCOL for port ranges. | Optional | 
| rich_rule | Rich rule to add/remove to/from firewalld. | Optional | 
| source | The source/network you would like to add/remove to/from firewalld. | Optional | 
| interface | The interface you would like to add/remove to/from a zone in firewalld. | Optional | 
| icmp_block | The ICMP block you would like to add/remove to/from a zone in firewalld. | Optional | 
| icmp_block_inversion | Enable/Disable inversion of ICMP blocks for a zone in firewalld. | Optional | 
| zone | The firewalld zone to add/remove to/from.<br/>Note that the default zone can be configured per system but `public` is default from upstream.<br/>Available choices can be extended based on per-system configs, listed here are "out of the box" defaults.<br/>Possible values include `block`, `dmz`, `drop`, `external`, `home`, `internal`, `public`, `trusted`, `work`. | Optional | 
| permanent | Should this configuration be in the running firewalld configuration or persist across reboots.<br/>As of Ansible 2.3, permanent operations can operate on firewalld configs when it is not running (requires firewalld &gt;= 3.0.9).<br/>Note that if this is `no`, immediate is assumed `yes`. | Optional | 
| immediate | Should this configuration be applied immediately, if set as permanent. Possible values are: Yes, No. Default is No. | Optional | 
| state | Enable or disable a setting.<br/>For ports: Should this port accept (enabled) or reject (disabled) connections.<br/>The states `present` and `absent` can only be used in zone level operations (i.e. when no other parameters but zone and state are set). Possible values are: absent, disabled, enabled, present. | Required | 
| timeout | The amount of time the rule should be in effect for when non-permanent. Default is 0. | Optional | 
| masquerade | The masquerade setting you would like to enable/disable to/from zones within firewalld. | Optional | 
| offline | Whether to run this module even when firewalld is offline. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-firewalld host="123.123.123.123" service="https" permanent="True" state="enabled" ```

#### Context Example
```json
{
    "Linux": {
        "Firewalld": {
            "changed": false,
            "host": "123.123.123.123",
            "msg": "Permanent operation",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * msg: Permanent operation


### linux-gather-facts
***
Gathers facts about remote hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/gather_facts_module.html


#### Base Command

`linux-gather-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| parallel | A toggle that controls if the fact modules are executed in parallel or serially and in order. This can guarantee the merge order of module facts at the expense of performance.<br/>By default it will be true if more than one fact module is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-gather-facts host="123.123.123.123"```

#### Context Example
```json
{
    "Linux": {
        "GatherFacts": {
            "all_ipv4_addresses": [
                "123.123.123.123"
            ],
            "all_ipv6_addresses": [
                "11:11:11:11:11:11:11:11",
                "11:11:11:11:11:11:11:12"
            ],
            "apparmor": {
                "status": "disabled"
            },
            "architecture": "x86_64",
            "bios_date": "04/05/2016",
            "bios_vendor": "Phoenix Technologies LTD",
            "bios_version": "6.00",
            "board_asset_tag": "NA",
            "board_name": "440BX Desktop Reference Platform",
            "board_serial": "None",
            "board_vendor": "Intel Corporation",
            "board_version": "None",
            "chassis_asset_tag": "No Asset Tag",
            "chassis_serial": "None",
            "chassis_vendor": "No Enclosure",
            "chassis_version": "N/A",
            "cmdline": {
                "BOOT_IMAGE": "(hd0,msdos1)/vmlinuz-4.18.0-193.28.1.el8_2.x86_64",
                "quiet": true,
                "rd.lvm.lv": "cs/swap",
                "resume": "/dev/mapper/cs-swap",
                "rhgb": true,
                "ro": true,
                "root": "/dev/mapper/cs-root"
            },
            "date_time": {
                "date": "2021-07-08",
                "day": "08",
                "epoch": "1625721772",
                "hour": "14",
                "iso8601": "2021-07-08T05:22:52Z",
                "iso8601_basic": "20210708T142252659998",
                "iso8601_basic_short": "20210708T142252",
                "iso8601_micro": "2021-07-08T05:22:52.659998Z",
                "minute": "22",
                "month": "07",
                "second": "52",
                "time": "14:22:52",
                "tz": "JST",
                "tz_offset": "+0900",
                "weekday": "Thursday",
                "weekday_number": "4",
                "weeknumber": "27",
                "year": "2021"
            },
            "default_ipv4": {
                "address": "123.123.123.123",
                "alias": "ens192",
                "broadcast": "192.168.1.255",
                "gateway": "192.168.1.1",
                "interface": "ens192",
                "macaddress": "00:0c:29:bb:37:cb",
                "mtu": 1500,
                "netmask": "255.255.255.0",
                "network": "192.168.1.0",
                "type": "ether"
            },
            "default_ipv6": {},
            "device_links": {
                "ids": {
                    "dm-0": [
                        "dm-name-cs-root",
                        "dm-uuid-LVM-YhrXQybKNO1NfDqL2i4yG9N2vQ9W5Ix0PcUDF884ZLUhBT5nET1F2IFZs8MpqFoT"
                    ]
                },
                "labels": {},
                "masters": {
                    "sda2": [
                        "dm-0",
                        "dm-1"
                    ]
                },
                "uuids": {
                    "dm-0": [
                        "9cf80eb1-50cf-48e5-af07-49d65717fab7"
                    ]
                }
            },
            "devices": {
                "dm-0": {
                    "holders": [],
                    "host": "",
                    "links": {
                        "ids": [
                            "dm-name-cs-root",
                            "dm-uuid-LVM-YhrXQybKNO1NfDqL2i4yG9N2vQ9W5Ix0PcUDF884ZLUhBT5nET1F2IFZs8MpqFoT"
                        ],
                        "labels": [],
                        "masters": [],
                        "uuids": [
                            "9cf80eb1-50cf-48e5-af07-49d65717fab7"
                        ]
                    },
                    "model": null,
                    "partitions": {},
                    "removable": "0",
                    "rotational": "0",
                    "sas_address": null,
                    "sas_device_handle": null,
                    "scheduler_mode": "",
                    "sectors": "28090368",
                    "sectorsize": "512",
                    "size": "13.39 GB",
                    "support_discard": "0",
                    "vendor": null,
                    "virtual": 1
                }
            },
            "discovered_interpreter_python": "/usr/libexec/platform-python",
            "distribution": "CentOS",
            "distribution_file_parsed": true,
            "distribution_file_path": "/etc/redhat-release",
            "distribution_file_variety": "RedHat",
            "distribution_major_version": "8",
            "distribution_release": "Core",
            "distribution_version": "8.2",
            "dns": {
                "nameservers": [
                    "192.168.1.1",
                    "fe80::1213:31ff:fec2:926c%ens192"
                ],
                "search": [
                    "lan"
                ]
            },
            "domain": "lan",
            "effective_group_id": 0,
            "effective_user_id": 0,
            "ens192": {
                "active": true,
                "device": "ens192",
                "features": {
                    "esp_hw_offload": "off [fixed]",
                    "esp_tx_csum_hw_offload": "off [fixed]",
                    "fcoe_mtu": "off [fixed]",
                    "generic_receive_offload": "on",
                    "generic_segmentation_offload": "on",
                    "highdma": "on",
                    "hw_tc_offload": "off [fixed]",
                    "l2_fwd_offload": "off [fixed]",
                    "large_receive_offload": "on",
                    "loopback": "off [fixed]",
                    "netns_local": "off [fixed]",
                    "ntuple_filters": "off [fixed]",
                    "receive_hashing": "off [fixed]",
                    "rx_all": "off [fixed]",
                    "rx_checksumming": "on",
                    "rx_fcs": "off [fixed]",
                    "rx_gro_hw": "off [fixed]",
                    "rx_udp_tunnel_port_offload": "off [fixed]",
                    "rx_vlan_filter": "on [fixed]",
                    "rx_vlan_offload": "on",
                    "rx_vlan_stag_filter": "off [fixed]",
                    "rx_vlan_stag_hw_parse": "off [fixed]",
                    "scatter_gather": "on",
                    "tcp_segmentation_offload": "on",
                    "tls_hw_record": "off [fixed]",
                    "tls_hw_rx_offload": "off [fixed]",
                    "tls_hw_tx_offload": "off [fixed]",
                    "tx_checksum_fcoe_crc": "off [fixed]",
                    "tx_checksum_ip_generic": "on",
                    "tx_checksum_ipv4": "off [fixed]",
                    "tx_checksum_ipv6": "off [fixed]",
                    "tx_checksum_sctp": "off [fixed]",
                    "tx_checksumming": "on",
                    "tx_esp_segmentation": "off [fixed]",
                    "tx_fcoe_segmentation": "off [fixed]",
                    "tx_gre_csum_segmentation": "off [fixed]",
                    "tx_gre_segmentation": "off [fixed]",
                    "tx_gso_partial": "off [fixed]",
                    "tx_gso_robust": "off [fixed]",
                    "tx_ipxip4_segmentation": "off [fixed]",
                    "tx_ipxip6_segmentation": "off [fixed]",
                    "tx_lockless": "off [fixed]",
                    "tx_nocache_copy": "off",
                    "tx_scatter_gather": "on",
                    "tx_scatter_gather_fraglist": "off [fixed]",
                    "tx_sctp_segmentation": "off [fixed]",
                    "tx_tcp6_segmentation": "on",
                    "tx_tcp_ecn_segmentation": "off [fixed]",
                    "tx_tcp_mangleid_segmentation": "off",
                    "tx_tcp_segmentation": "on",
                    "tx_udp_segmentation": "off [fixed]",
                    "tx_udp_tnl_csum_segmentation": "off [fixed]",
                    "tx_udp_tnl_segmentation": "off [fixed]",
                    "tx_vlan_offload": "on",
                    "tx_vlan_stag_hw_insert": "off [fixed]",
                    "vlan_challenged": "off [fixed]"
                },
                "hw_timestamp_filters": [],
                "ipv4": {
                    "address": "123.123.123.123",
                    "broadcast": "192.168.1.255",
                    "netmask": "255.255.255.0",
                    "network": "192.168.1.0"
                },
                "ipv6": [
                    {
                        "address": "11:11:11:11:11:11:11:11",
                        "prefix": "64",
                        "scope": "global"
                    },
                    {
                        "address": "11:11:11:11:11:11:11:12",
                        "prefix": "64",
                        "scope": "link"
                    }
                ],
                "macaddress": "00:0c:29:bb:37:cb",
                "module": "vmxnet3",
                "mtu": 1500,
                "pciid": "0000:0b:00.0",
                "promisc": false,
                "speed": 10000,
                "timestamping": [
                    "rx_software",
                    "software"
                ],
                "type": "ether"
            },
            "fibre_channel_wwn": [],
            "fips": false,
            "form_factor": "Other",
            "fqdn": "web01.lan",
            "gather_subset": [
                "all"
            ],
            "host": "123.123.123.123",
            "hostname": "web01",
            "hostnqn": "",
            "interfaces": [
                "lo",
                "ens192"
            ],
            "is_chroot": false,
            "iscsi_iqn": "",
            "kernel": "4.18.0-193.28.1.el8_2.x86_64",
            "kernel_version": "#1 SMP Thu Oct 22 00:20:22 UTC 2020",
            "lo": {
                "active": true,
                "device": "lo",
                "features": {
                    "esp_hw_offload": "off [fixed]",
                    "esp_tx_csum_hw_offload": "off [fixed]",
                    "fcoe_mtu": "off [fixed]",
                    "generic_receive_offload": "on",
                    "generic_segmentation_offload": "on",
                    "highdma": "on [fixed]",
                    "hw_tc_offload": "off [fixed]",
                    "l2_fwd_offload": "off [fixed]",
                    "large_receive_offload": "off [fixed]",
                    "loopback": "on [fixed]",
                    "netns_local": "on [fixed]",
                    "ntuple_filters": "off [fixed]",
                    "receive_hashing": "off [fixed]",
                    "rx_all": "off [fixed]",
                    "rx_checksumming": "on [fixed]",
                    "rx_fcs": "off [fixed]",
                    "rx_gro_hw": "off [fixed]",
                    "rx_udp_tunnel_port_offload": "off [fixed]",
                    "rx_vlan_filter": "off [fixed]",
                    "rx_vlan_offload": "off [fixed]",
                    "rx_vlan_stag_filter": "off [fixed]",
                    "rx_vlan_stag_hw_parse": "off [fixed]",
                    "scatter_gather": "on",
                    "tcp_segmentation_offload": "on",
                    "tls_hw_record": "off [fixed]",
                    "tls_hw_rx_offload": "off [fixed]",
                    "tls_hw_tx_offload": "off [fixed]",
                    "tx_checksum_fcoe_crc": "off [fixed]",
                    "tx_checksum_ip_generic": "on [fixed]",
                    "tx_checksum_ipv4": "off [fixed]",
                    "tx_checksum_ipv6": "off [fixed]",
                    "tx_checksum_sctp": "on [fixed]",
                    "tx_checksumming": "on",
                    "tx_esp_segmentation": "off [fixed]",
                    "tx_fcoe_segmentation": "off [fixed]",
                    "tx_gre_csum_segmentation": "off [fixed]",
                    "tx_gre_segmentation": "off [fixed]",
                    "tx_gso_partial": "off [fixed]",
                    "tx_gso_robust": "off [fixed]",
                    "tx_ipxip4_segmentation": "off [fixed]",
                    "tx_ipxip6_segmentation": "off [fixed]",
                    "tx_lockless": "on [fixed]",
                    "tx_nocache_copy": "off [fixed]",
                    "tx_scatter_gather": "on [fixed]",
                    "tx_scatter_gather_fraglist": "on [fixed]",
                    "tx_sctp_segmentation": "on",
                    "tx_tcp6_segmentation": "on",
                    "tx_tcp_ecn_segmentation": "on",
                    "tx_tcp_mangleid_segmentation": "on",
                    "tx_tcp_segmentation": "on",
                    "tx_udp_segmentation": "off [fixed]",
                    "tx_udp_tnl_csum_segmentation": "off [fixed]",
                    "tx_udp_tnl_segmentation": "off [fixed]",
                    "tx_vlan_offload": "off [fixed]",
                    "tx_vlan_stag_hw_insert": "off [fixed]",
                    "vlan_challenged": "on [fixed]"
                },
                "hw_timestamp_filters": [],
                "ipv4": {
                    "address": "127.0.0.1",
                    "broadcast": "",
                    "netmask": "255.0.0.0",
                    "network": "127.0.0.0"
                },
                "ipv6": [
                    {
                        "address": "::1",
                        "prefix": "128",
                        "scope": "host"
                    }
                ],
                "mtu": 65536,
                "promisc": false,
                "timestamping": [
                    "tx_software",
                    "rx_software",
                    "software"
                ],
                "type": "loopback"
            },
            "local": {},
            "lsb": {},
            "lvm": {
                "lvs": {
                    "root": {
                        "size_g": "13.39",
                        "vg": "cs"
                    },
                    "swap": {
                        "size_g": "1.60",
                        "vg": "cs"
                    }
                },
                "pvs": {
                    "/dev/sda2": {
                        "free_g": "0",
                        "size_g": "15.00",
                        "vg": "cs"
                    }
                },
                "vgs": {
                    "cs": {
                        "free_g": "0",
                        "num_lvs": "2",
                        "num_pvs": "1",
                        "size_g": "15.00"
                    }
                }
            },
            "machine": "x86_64",
            "machine_id": "c919c21e349f4cbe8cf16333aae4701d",
            "memfree_mb": 1412,
            "memory_mb": {
                "nocache": {
                    "free": 1709,
                    "used": 277
                },
                "real": {
                    "free": 1412,
                    "total": 1986,
                    "used": 574
                },
                "swap": {
                    "cached": 0,
                    "free": 1639,
                    "total": 1639,
                    "used": 0
                }
            },
            "memtotal_mb": 1986,
            "module_setup": true,
            "mounts": [
                {
                    "block_available": 3057926,
                    "block_size": 4096,
                    "block_total": 3508736,
                    "block_used": 450810,
                    "device": "/dev/mapper/cs-root",
                    "fstype": "xfs",
                    "inode_available": 6985488,
                    "inode_total": 7022592,
                    "inode_used": 37104,
                    "mount": "/",
                    "options": "rw,seclabel,relatime,attr2,inode64,noquota",
                    "size_available": 12525264896,
                    "size_total": 14371782656,
                    "uuid": "9cf80eb1-50cf-48e5-af07-49d65717fab7"
                }
            ],
            "nodename": "web01",
            "os_family": "RedHat",
            "pkg_mgr": "dnf",
            "proc_cmdline": {
                "BOOT_IMAGE": "(hd0,msdos1)/vmlinuz-4.18.0-193.28.1.el8_2.x86_64",
                "quiet": true,
                "rd.lvm.lv": [
                    "cs/root",
                    "cs/swap"
                ],
                "resume": "/dev/mapper/cs-swap",
                "rhgb": true,
                "ro": true,
                "root": "/dev/mapper/cs-root"
            },
            "processor": [
                "0",
                "GenuineIntel",
                "Intel(R) Core(TM) i7 CPU         920  @ 2.67GHz"
            ],
            "processor_cores": 1,
            "processor_count": 1,
            "processor_nproc": 1,
            "processor_threads_per_core": 1,
            "processor_vcpus": 1,
            "product_name": "VMware Virtual Platform",
            "product_serial": "VMware-56 4d d7 77 f1 ba 7c ad-c0 15 39 73 2f bb 37 cb",
            "product_uuid": "77d74d56-baf1-ad7c-c015-39732fbb37cb",
            "product_version": "None",
            "python": {
                "executable": "/usr/libexec/platform-python",
                "has_sslcontext": true,
                "type": "cpython",
                "version": {
                    "major": 3,
                    "micro": 8,
                    "minor": 6,
                    "releaselevel": "final",
                    "serial": 0
                },
                "version_info": [
                    3,
                    6,
                    8,
                    "final",
                    0
                ]
            },
            "python_version": "3.6.8",
            "real_group_id": 0,
            "real_user_id": 0,
            "selinux": {
                "config_mode": "enforcing",
                "mode": "enforcing",
                "policyvers": 31,
                "status": "enabled",
                "type": "targeted"
            },
            "selinux_python_present": true,
            "service_mgr": "systemd",
            "ssh_host_key_ecdsa_public": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCjaVzeB+MYtwIxrdDDkNbnVktX/g7yWTJsEKq7ccOVo2JbfnB1rYlVKK52faQvw/W34LG7u3MArRV7mGtll4Gc=",
            "ssh_host_key_ecdsa_public_keytype": "ecdsa-sha2-nistp256",
            "ssh_host_key_ed25519_public": "AAAAC3NzaC1lZDI1NTE5AAAAIEqirZU8jupDZ8wJylI4U2fqx3cFNfCUhZB1u4PKnJnW",
            "ssh_host_key_ed25519_public_keytype": "ssh-ed25519",
            "ssh_host_key_rsa_public": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDR3MCoxjeeZzPx+bhSkYBC7naJddiDaKB8v9WNqhDlrdu4AkNK1jqdBgWY4pfTG4+x3ZF//rWgAVVVD2Laih8ErlGmhJOPB4hO9SfB7OBUK5uZaD5jRIl5tvqca9GZboXL4WczjQFTA/0mJJ1uAdGiolkmdyv8tKU92C4OioU4UN9q0bOk+H1yuiwKY3EjRxxrcC3Sxjr63Ojew5SJZsqG+J5dGJI7M63NaePTS3rjrIWcmGjfUQa0vLuZ8uTqsxh3IB2tyNuOlov0ybrKPk5JGmtpvhA2Z6D5TmNOgyHEYqM1CrArcZmCX9EVfly+YQ7NCOLoPKKGOqqKOTuw2ygIZuTOt4IGLDXMiMUgkTECAwUuWykeUwhXOeVSyiMknIuCn/ui1/gQU5JKvhsqNko4hNZKerBGe1wu4upZd7tAsQ63ppEO+tQvy5o4BUudZQtdSQc01WzO0RyRcx1NRIJaezzhGa22naKgaf9zER/hRyypNZNmuLlHhVs6fyXvjPM=",
            "ssh_host_key_rsa_public_keytype": "ssh-rsa",
            "status": "SUCCESS",
            "swapfree_mb": 1639,
            "swaptotal_mb": 1639,
            "system": "Linux",
            "system_capabilities": [
                "cap_chown"
            ],
            "system_capabilities_enforced": "True",
            "system_vendor": "VMware, Inc.",
            "uptime_seconds": 331832,
            "user_dir": "/root",
            "user_gecos": "root",
            "user_gid": 0,
            "user_id": "root",
            "user_shell": "/bin/bash",
            "user_uid": 0,
            "userspace_architecture": "x86_64",
            "userspace_bits": "64",
            "virtualization_role": "guest",
            "virtualization_type": "VMware"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * architecture: x86_64
>  * bios_date: 04/05/2016
>  * bios_vendor: Phoenix Technologies LTD
>  * bios_version: 6.00
>  * board_asset_tag: NA
>  * board_name: 440BX Desktop Reference Platform
>  * board_serial: None
>  * board_vendor: Intel Corporation
>  * board_version: None
>  * chassis_asset_tag: No Asset Tag
>  * chassis_serial: None
>  * chassis_vendor: No Enclosure
>  * chassis_version: N/A
>  * distribution: CentOS
>  * distribution_file_parsed: True
>  * distribution_file_path: /etc/redhat-release
>  * distribution_file_variety: RedHat
>  * distribution_major_version: 8
>  * distribution_release: Core
>  * distribution_version: 8.2
>  * domain: lan
>  * effective_group_id: 0
>  * effective_user_id: 0
>  * fips: False
>  * form_factor: Other
>  * fqdn: web01.lan
>  * hostname: web01
>  * hostnqn: 
>  * is_chroot: False
>  * iscsi_iqn: 
>  * kernel: 4.18.0-193.28.1.el8_2.x86_64
>  * kernel_version: #1 SMP Thu Oct 22 00:20:22 UTC 2020
>  * machine: x86_64
>  * machine_id: c919c21e349f4cbe8cf16333aae4701d
>  * memfree_mb: 1412
>  * memtotal_mb: 1986
>  * nodename: web01
>  * os_family: RedHat
>  * pkg_mgr: dnf
>  * processor_cores: 1
>  * processor_count: 1
>  * processor_nproc: 1
>  * processor_threads_per_core: 1
>  * processor_vcpus: 1
>  * product_name: VMware Virtual Platform
>  * product_serial: VMware-56 4d d7 77 f1 ba 7c ad-c0 15 39 73 2f bb 37 cb
>  * product_uuid: 77d74d56-baf1-ad7c-c015-39732fbb37cb
>  * product_version: None
>  * python_version: 3.6.8
>  * real_group_id: 0
>  * real_user_id: 0
>  * selinux_python_present: True
>  * service_mgr: systemd
>  * ssh_host_key_ecdsa_public: AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCjaVzeB+MYtwIxrdDDkNbnVktX/g7yWTJsEKq7ccOVo2JbfnB1rYlVKK52faQvw/W34LG7u3MArRV7mGtll4Gc=
>  * ssh_host_key_ecdsa_public_keytype: ecdsa-sha2-nistp256
>  * ssh_host_key_ed25519_public: AAAAC3NzaC1lZDI1NTE5AAAAIEqirZU8jupDZ8wJylI4U2fqx3cFNfCUhZB1u4PKnJnW
>  * ssh_host_key_ed25519_public_keytype: ssh-ed25519
>  * ssh_host_key_rsa_public: AAAAB3NzaC1yc2EAAAADAQABAAABgQDR3MCoxjeeZzPx+bhSkYBC7naJddiDaKB8v9WNqhDlrdu4AkNK1jqdBgWY4pfTG4+x3ZF//rWgAVVVD2Laih8ErlGmhJOPB4hO9SfB7OBUK5uZaD5jRIl5tvqca9GZboXL4WczjQFTA/0mJJ1uAdGiolkmdyv8tKU92C4OioU4UN9q0bOk+H1yuiwKY3EjRxxrcC3Sxjr63Ojew5SJZsqG+J5dGJI7M63NaePTS3rjrIWcmGjfUQa0vLuZ8uTqsxh3IB2tyNuOlov0ybrKPk5JGmtpvhA2Z6D5TmNOgyHEYqM1CrArcZmCX9EVfly+YQ7NCOLoPKKGOqqKOTuw2ygIZuTOt4IGLDXMiMUgkTECAwUuWykeUwhXOeVSyiMknIuCn/ui1/gQU5JKvhsqNko4hNZKerBGe1wu4upZd7tAsQ63ppEO+tQvy5o4BUudZQtdSQc01WzO0RyRcx1NRIJaezzhGa22naKgaf9zER/hRyypNZNmuLlHhVs6fyXvjPM=
>  * ssh_host_key_rsa_public_keytype: ssh-rsa
>  * swapfree_mb: 1639
>  * swaptotal_mb: 1639
>  * system: Linux
>  * system_capabilities_enforced: True
>  * system_vendor: VMware, Inc.
>  * uptime_seconds: 331832
>  * user_dir: /root
>  * user_gecos: root
>  * user_gid: 0
>  * user_id: root
>  * user_shell: /bin/bash
>  * user_uid: 0
>  * userspace_architecture: x86_64
>  * userspace_bits: 64
>  * virtualization_role: guest
>  * virtualization_type: VMware
>  * discovered_interpreter_python: /usr/libexec/platform-python
>  * module_setup: True
>  * ## All_Ipv4_Addresses
>    * 0: 123.123.123.123
>  * ## All_Ipv6_Addresses
>    * 0: 11:11:11:11:11:11:11:11
>    * 1: 11:11:11:11:11:11:11:12
>  * ## Apparmor
>    * status: disabled
>  * ## Cmdline
>    * BOOT_IMAGE: (hd0,msdos1)/vmlinuz-4.18.0-193.28.1.el8_2.x86_64
>    * quiet: True
>    * rd.lvm.lv: cs/swap
>    * resume: /dev/mapper/cs-swap
>    * rhgb: True
>    * ro: True
>    * root: /dev/mapper/cs-root
>  * ## Date_Time
>    * date: 2021-07-08
>    * day: 08
>    * epoch: 1625721772
>    * hour: 14
>    * iso8601: 2021-07-08T05:22:52Z
>    * iso8601_basic: 20210708T142252659998
>    * iso8601_basic_short: 20210708T142252
>    * iso8601_micro: 2021-07-08T05:22:52.659998Z
>    * minute: 22
>    * month: 07
>    * second: 52
>    * time: 14:22:52
>    * tz: JST
>    * tz_offset: +0900
>    * weekday: Thursday
>    * weekday_number: 4
>    * weeknumber: 27
>    * year: 2021
>  * ## Default_Ipv4
>    * address: 123.123.123.123
>    * alias: ens192
>    * broadcast: 192.168.1.255
>    * gateway: 192.168.1.1
>    * interface: ens192
>    * macaddress: 00:0c:29:bb:37:cb
>    * mtu: 1500
>    * netmask: 255.255.255.0
>    * network: 192.168.1.0
>    * type: ether
>  * ## Default_Ipv6
>  * ## Device_Links
>    * ### Ids
>      * #### Dm-0
>        * 0: dm-name-cs-root
>        * 1: dm-uuid-LVM-YhrXQybKNO1NfDqL2i4yG9N2vQ9W5Ix0PcUDF884ZLUhBT5nET1F2IFZs8MpqFoT
>    * ### Labels
>    * ### Masters
>      * #### Sda2
>        * 0: dm-0
>        * 1: dm-1
>    * ### Uuids
>      * #### Dm-0
>        * 0: 9cf80eb1-50cf-48e5-af07-49d65717fab7
>  * ## Devices
>    * ### Dm-0
>      * host: 
>      * model: None
>      * removable: 0
>      * rotational: 0
>      * sas_address: None
>      * sas_device_handle: None
>      * scheduler_mode: 
>      * sectors: 28090368
>      * sectorsize: 512
>      * size: 13.39 GB
>      * support_discard: 0
>      * vendor: None
>      * virtual: 1
>      * #### Holders
>      * #### Links
>        * ##### Ids
>          * 0: dm-name-cs-root
>          * 1: dm-uuid-LVM-YhrXQybKNO1NfDqL2i4yG9N2vQ9W5Ix0PcUDF884ZLUhBT5nET1F2IFZs8MpqFoT
>        * ##### Labels
>        * ##### Masters
>        * ##### Uuids
>          * 0: 9cf80eb1-50cf-48e5-af07-49d65717fab7
>      * #### Partitions
>  * ## Dns
>    * ### Nameservers
>      * 0: 192.168.1.1
>      * 1: fe80::1213:31ff:fec2:926c%ens192
>    * ### Search
>      * 0: lan
>  * ## Ens192
>    * active: True
>    * device: ens192
>    * macaddress: 00:0c:29:bb:37:cb
>    * module: vmxnet3
>    * mtu: 1500
>    * pciid: 0000:0b:00.0
>    * promisc: False
>    * speed: 10000
>    * type: ether
>    * ### Features
>      * esp_hw_offload: off [fixed]
>      * esp_tx_csum_hw_offload: off [fixed]
>      * fcoe_mtu: off [fixed]
>      * generic_receive_offload: on
>      * generic_segmentation_offload: on
>      * highdma: on
>      * hw_tc_offload: off [fixed]
>      * l2_fwd_offload: off [fixed]
>      * large_receive_offload: on
>      * loopback: off [fixed]
>      * netns_local: off [fixed]
>      * ntuple_filters: off [fixed]
>      * receive_hashing: off [fixed]
>      * rx_all: off [fixed]
>      * rx_checksumming: on
>      * rx_fcs: off [fixed]
>      * rx_gro_hw: off [fixed]
>      * rx_udp_tunnel_port_offload: off [fixed]
>      * rx_vlan_filter: on [fixed]
>      * rx_vlan_offload: on
>      * rx_vlan_stag_filter: off [fixed]
>      * rx_vlan_stag_hw_parse: off [fixed]
>      * scatter_gather: on
>      * tcp_segmentation_offload: on
>      * tls_hw_record: off [fixed]
>      * tls_hw_rx_offload: off [fixed]
>      * tls_hw_tx_offload: off [fixed]
>      * tx_checksum_fcoe_crc: off [fixed]
>      * tx_checksum_ip_generic: on
>      * tx_checksum_ipv4: off [fixed]
>      * tx_checksum_ipv6: off [fixed]
>      * tx_checksum_sctp: off [fixed]
>      * tx_checksumming: on
>      * tx_esp_segmentation: off [fixed]
>      * tx_fcoe_segmentation: off [fixed]
>      * tx_gre_csum_segmentation: off [fixed]
>      * tx_gre_segmentation: off [fixed]
>      * tx_gso_partial: off [fixed]
>      * tx_gso_robust: off [fixed]
>      * tx_ipxip4_segmentation: off [fixed]
>      * tx_ipxip6_segmentation: off [fixed]
>      * tx_lockless: off [fixed]
>      * tx_nocache_copy: off
>      * tx_scatter_gather: on
>      * tx_scatter_gather_fraglist: off [fixed]
>      * tx_sctp_segmentation: off [fixed]
>      * tx_tcp6_segmentation: on
>      * tx_tcp_ecn_segmentation: off [fixed]
>      * tx_tcp_mangleid_segmentation: off
>      * tx_tcp_segmentation: on
>      * tx_udp_segmentation: off [fixed]
>      * tx_udp_tnl_csum_segmentation: off [fixed]
>      * tx_udp_tnl_segmentation: off [fixed]
>      * tx_vlan_offload: on
>      * tx_vlan_stag_hw_insert: off [fixed]
>      * vlan_challenged: off [fixed]
>    * ### Hw_Timestamp_Filters
>    * ### Ipv4
>      * address: 123.123.123.123
>      * broadcast: 192.168.1.255
>      * netmask: 255.255.255.0
>      * network: 192.168.1.0
>    * ### Ipv6
>    * ### List
>      * address: 11:11:11:11:11:11:11:11
>      * prefix: 64
>      * scope: global
>    * ### List
>      * address: 11:11:11:11:11:11:11:12
>      * prefix: 64
>      * scope: link
>    * ### Timestamping
>      * 0: rx_software
>      * 1: software
>  * ## Fibre_Channel_Wwn
>  * ## Interfaces
>    * 0: lo
>    * 1: ens192
>  * ## Lo
>    * active: True
>    * device: lo
>    * mtu: 65536
>    * promisc: False
>    * type: loopback
>    * ### Features
>      * esp_hw_offload: off [fixed]
>      * esp_tx_csum_hw_offload: off [fixed]
>      * fcoe_mtu: off [fixed]
>      * generic_receive_offload: on
>      * generic_segmentation_offload: on
>      * highdma: on [fixed]
>      * hw_tc_offload: off [fixed]
>      * l2_fwd_offload: off [fixed]
>      * large_receive_offload: off [fixed]
>      * loopback: on [fixed]
>      * netns_local: on [fixed]
>      * ntuple_filters: off [fixed]
>      * receive_hashing: off [fixed]
>      * rx_all: off [fixed]
>      * rx_checksumming: on [fixed]
>      * rx_fcs: off [fixed]
>      * rx_gro_hw: off [fixed]
>      * rx_udp_tunnel_port_offload: off [fixed]
>      * rx_vlan_filter: off [fixed]
>      * rx_vlan_offload: off [fixed]
>      * rx_vlan_stag_filter: off [fixed]
>      * rx_vlan_stag_hw_parse: off [fixed]
>      * scatter_gather: on
>      * tcp_segmentation_offload: on
>      * tls_hw_record: off [fixed]
>      * tls_hw_rx_offload: off [fixed]
>      * tls_hw_tx_offload: off [fixed]
>      * tx_checksum_fcoe_crc: off [fixed]
>      * tx_checksum_ip_generic: on [fixed]
>      * tx_checksum_ipv4: off [fixed]
>      * tx_checksum_ipv6: off [fixed]
>      * tx_checksum_sctp: on [fixed]
>      * tx_checksumming: on
>      * tx_esp_segmentation: off [fixed]
>      * tx_fcoe_segmentation: off [fixed]
>      * tx_gre_csum_segmentation: off [fixed]
>      * tx_gre_segmentation: off [fixed]
>      * tx_gso_partial: off [fixed]
>      * tx_gso_robust: off [fixed]
>      * tx_ipxip4_segmentation: off [fixed]
>      * tx_ipxip6_segmentation: off [fixed]
>      * tx_lockless: on [fixed]
>      * tx_nocache_copy: off [fixed]
>      * tx_scatter_gather: on [fixed]
>      * tx_scatter_gather_fraglist: on [fixed]
>      * tx_sctp_segmentation: on
>      * tx_tcp6_segmentation: on
>      * tx_tcp_ecn_segmentation: on
>      * tx_tcp_mangleid_segmentation: on
>      * tx_tcp_segmentation: on
>      * tx_udp_segmentation: off [fixed]
>      * tx_udp_tnl_csum_segmentation: off [fixed]
>      * tx_udp_tnl_segmentation: off [fixed]
>      * tx_vlan_offload: off [fixed]
>      * tx_vlan_stag_hw_insert: off [fixed]
>      * vlan_challenged: on [fixed]
>    * ### Hw_Timestamp_Filters
>    * ### Ipv4
>      * address: 127.0.0.1
>      * broadcast: 
>      * netmask: 255.0.0.0
>      * network: 127.0.0.0
>    * ### Ipv6
>    * ### List
>      * address: ::1
>      * prefix: 128
>      * scope: host
>    * ### Timestamping
>      * 0: tx_software
>      * 1: rx_software
>      * 2: software
>  * ## Local
>  * ## Lsb
>  * ## Lvm
>    * ### Lvs
>      * #### Root
>        * size_g: 13.39
>        * vg: cs
>      * #### Swap
>        * size_g: 1.60
>        * vg: cs
>    * ### Pvs
>      * #### /Dev/Sda2
>        * free_g: 0
>        * size_g: 15.00
>        * vg: cs
>    * ### Vgs
>      * #### Cs
>        * free_g: 0
>        * num_lvs: 2
>        * num_pvs: 1
>        * size_g: 15.00
>  * ## Memory_Mb
>    * ### Nocache
>      * free: 1709
>      * used: 277
>    * ### Real
>      * free: 1412
>      * total: 1986
>      * used: 574
>    * ### Swap
>      * cached: 0
>      * free: 1639
>      * total: 1639
>      * used: 0
>  * ## Mounts
>  * ## 9Cf80Eb1-50Cf-48E5-Af07-49D65717Fab7
>    * block_available: 3057926
>    * block_size: 4096
>    * block_total: 3508736
>    * block_used: 450810
>    * device: /dev/mapper/cs-root
>    * fstype: xfs
>    * inode_available: 6985488
>    * inode_total: 7022592
>    * inode_used: 37104
>    * mount: /
>    * options: rw,seclabel,relatime,attr2,inode64,noquota
>    * size_available: 12525264896
>    * size_total: 14371782656
>    * uuid: 9cf80eb1-50cf-48e5-af07-49d65717fab7
>  * ## 99851642-260F-4D7E-83Dd-7Cc990D49126
>    * block_available: 201086
>    * block_size: 4096
>    * block_total: 249830
>    * block_used: 48744
>    * device: /dev/sda1
>    * fstype: ext4
>    * inode_available: 65227
>    * inode_total: 65536
>    * inode_used: 309
>    * mount: /boot
>    * options: rw,seclabel,relatime
>    * size_available: 823648256
>    * size_total: 1023303680
>    * uuid: 99851642-260f-4d7e-83dd-7cc990d49126
>  * ## Proc_Cmdline
>    * BOOT_IMAGE: (hd0,msdos1)/vmlinuz-4.18.0-193.28.1.el8_2.x86_64
>    * quiet: True
>    * resume: /dev/mapper/cs-swap
>    * rhgb: True
>    * ro: True
>    * root: /dev/mapper/cs-root
>    * ### Rd.Lvm.Lv
>      * 0: cs/root
>      * 1: cs/swap
>  * ## Processor
>    * 0: 0
>    * 1: GenuineIntel
>    * 2: Intel(R) Core(TM) i7 CPU         920  @ 2.67GHz
>  * ## Python
>    * executable: /usr/libexec/platform-python
>    * has_sslcontext: True
>    * type: cpython
>    * ### Version
>      * major: 3
>      * micro: 8
>      * minor: 6
>      * releaselevel: final
>      * serial: 0
>    * ### Version_Info
>      * 0: 3
>      * 1: 6
>      * 2: 8
>      * 3: final
>      * 4: 0
>  * ## Selinux
>    * config_mode: enforcing
>    * mode: enforcing
>    * policyvers: 31
>    * status: enabled
>    * type: targeted
>  * ## System_Capabilities
>    * 0: cap_chown
>  * ## Gather_Subset
>    * 0: all


### linux-gconftool2
***
Edit GNOME Configurations
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/gconftool2_module.html


#### Base Command

`linux-gconftool2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| key | A GConf preference key is an element in the GConf repository that corresponds to an application preference. See man gconftool-2(1). | Required | 
| value | Preference keys typically have simple values such as strings, integers, or lists of strings and integers. This is ignored if the state is "get". See man gconftool-2(1). | Optional | 
| value_type | The type of value being set. This is ignored if the state is "get". Possible values are: bool, float, int, string. | Optional | 
| state | The action to take upon the key/value. Possible values are: absent, get, present. | Required | 
| config_source | Specify a configuration source to use rather than the default path. See man gconftool-2(1). | Optional | 
| direct | Access the config database directly, bypassing server.  If direct is specified then the config_source must be specified as well. See man gconftool-2(1). Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Gconftool2.key | string | The key specified in the module parameters | 
| Linux.Gconftool2.value_type | string | The type of the value that was changed | 
| Linux.Gconftool2.value | string | The value of the preference key after executing the module | 


#### Command Example
```!linux-gconftool2 host="123.123.123.123" key="/desktop/gnome/interface/font_name" value_type="string" value="Serif 12" state=present```

#### Context Example
```json
{
    "Linux": {
        "Gconftool2": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-getent
***
A wrapper to the unix getent utility
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/getent_module.html


#### Base Command

`linux-getent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| database | The name of a getent database supported by the target system (passwd, group, hosts, etc). | Required | 
| key | Key from which to return values from the specified database, otherwise the full contents are returned. | Optional | 
| service | Override all databases with the specified service<br/>The underlying system must support the service flag which is not always available. | Optional | 
| split | Character used to split the database values into lists/arrays such as ':' or '	', otherwise  it will try to pick one depending on the database. | Optional | 
| fail_key | If a supplied key is missing this will make the task fail if `yes`. Default is yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-getent host="123.123.123.123" database="passwd" key="root" ```

#### Context Example
```json
{
    "Linux": {
        "Getent": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-group
***
Add or remove groups
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/group_module.html


#### Base Command

`linux-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the group to manage. | Required | 
| gid | Optional `GID` to set for the group. | Optional | 
| state | Whether the group should be present or not on the remote host. Possible values are: absent, present. Default is present. | Optional | 
| system | If `yes`, indicates that the group created is a system group. Possible values are: Yes, No. Default is No. | Optional | 
| local | Forces the use of "local" command alternatives on platforms that implement it.<br/>This is useful in environments that use centralized authentication when you want to manipulate the local groups. (e.g. it uses `lgroupadd` instead of `groupadd`).<br/>This requires that these commands exist on the targeted host, otherwise it will be a fatal error. Possible values are: Yes, No. Default is No. | Optional | 
| non_unique | This option allows to change the group ID to a non-unique value. Requires `gid`.<br/>Not supported on macOS or BusyBox distributions. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-group host="123.123.123.123" name="somegroup" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "Group": {
            "changed": false,
            "gid": 1000,
            "host": "123.123.123.123",
            "name": "somegroup",
            "state": "present",
            "status": "SUCCESS",
            "system": false
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * gid: 1000
>  * name: somegroup
>  * state: present
>  * system: False


### linux-hostname
***
Manage hostname
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/hostname_module.html


#### Base Command

`linux-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the host. | Required | 
| use | Which strategy to use to update the hostname.<br/>If not set we try to autodetect, but this can be problematic, specially with containers as they can present misleading information. Possible values are: generic, debian, sles, redhat, alpine, systemd, openrc, openbsd, solaris, freebsd. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-hostname host="123.123.123.123" name="web01" ```

#### Context Example
```json
{
    "Linux": {
        "Hostname": {
            "changed": false,
            "host": "123.123.123.123",
            "name": "web01",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * name: web01


### linux-interfaces-file
***
Tweak settings in /etc/network/interfaces files
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/interfaces_file_module.html


#### Base Command

`linux-interfaces-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dest | Path to the interfaces file. Default is /etc/network/interfaces. | Optional | 
| iface | Name of the interface, required for value changes or option remove. | Optional | 
| address_family | Address family of the interface, useful if same interface name is used for both inet and inet6. | Optional | 
| option | Name of the option, required for value changes or option remove. | Optional | 
| value | If `option` is not presented for the `interface` and `state` is `present` option will be added. If `option` already exists and is not `pre-up`, `up`, `post-up` or `down`, it's value will be updated. `pre-up`, `up`, `post-up` and `down` options can't be updated, only adding new options, removing existing ones or cleaning the whole option set are supported. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Default is no. | Optional | 
| state | If set to `absent` the option or section will be removed if present instead of created. Possible values are: present, absent. Default is present. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.InterfacesFile.dest | string | destination file/path | 
| Linux.InterfacesFile.ifaces | unknown | interfaces dictionary | 



### linux-iptables
***
Modify iptables rules
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/iptables_module.html


#### Base Command

`linux-iptables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| table | This option specifies the packet matching table which the command should operate on.<br/>If the kernel is configured with automatic module loading, an attempt will be made to load the appropriate module for that table if it is not already there. Possible values are: filter, nat, mangle, raw, security. Default is filter. | Optional | 
| state | Whether the rule should be absent or present. Possible values are: absent, present. Default is present. | Optional | 
| action | Whether the rule should be appended at the bottom or inserted at the top.<br/>If the rule already exists the chain will not be modified. Possible values are: append, insert. Default is append. | Optional | 
| rule_num | Insert the rule as the given rule number.<br/>This works only with `action=insert`. | Optional | 
| ip_version | Which version of the IP protocol this rule should apply to. Possible values are: ipv4, ipv6. Default is ipv4. | Optional | 
| chain | Specify the iptables chain to modify.<br/>This could be a user-defined chain or one of the standard iptables chains, like `INPUT`, `FORWARD`, `OUTPUT`, `PREROUTING`, `POSTROUTING`, `SECMARK` or `CONNSECMARK`. | Optional | 
| protocol | The protocol of the rule or of the packet to check.<br/>The specified protocol can be one of `tcp`, `udp`, `udplite`, `icmp`, `esp`, `ah`, `sctp` or the special keyword `all`, or it can be a numeric value, representing one of these protocols or a different one.<br/>A protocol name from `/etc/protocols` is also allowed.<br/>A `!` argument before the protocol inverts the test.<br/>The number zero is equivalent to all.<br/>`all` will match with all protocols and is taken as default when this option is omitted. | Optional | 
| source | Source specification.<br/>Address can be either a network name, a hostname, a network IP address (with /mask), or a plain IP address.<br/>Hostnames will be resolved once only, before the rule is submitted to the kernel. Please note that specifying any name to be resolved with a remote query such as DNS is a really bad idea.<br/>The mask can be either a network mask or a plain number, specifying the number of 1's at the left side of the network mask. Thus, a mask of 24 is equivalent to 255.255.255.0. A `!` argument before the address specification inverts the sense of the address. | Optional | 
| destination | Destination specification.<br/>Address can be either a network name, a hostname, a network IP address (with /mask), or a plain IP address.<br/>Hostnames will be resolved once only, before the rule is submitted to the kernel. Please note that specifying any name to be resolved with a remote query such as DNS is a really bad idea.<br/>The mask can be either a network mask or a plain number, specifying the number of 1's at the left side of the network mask. Thus, a mask of 24 is equivalent to 255.255.255.0. A `!` argument before the address specification inverts the sense of the address. | Optional | 
| tcp_flags | TCP flags specification.<br/>`tcp_flags` expects a dict with the two keys `flags` and `flags_set`. | Optional | 
| match | Specifies a match to use, that is, an extension module that tests for a specific property.<br/>The set of matches make up the condition under which a target is invoked.<br/>Matches are evaluated first to last if specified as an array and work in short-circuit fashion, i.e. if one extension yields false, evaluation will stop. | Optional | 
| jump | This specifies the target of the rule; i.e., what to do if the packet matches it.<br/>The target can be a user-defined chain (other than the one this rule is in), one of the special builtin targets which decide the fate of the packet immediately, or an extension (see EXTENSIONS below).<br/>If this option is omitted in a rule (and the goto parameter is not used), then matching the rule will have no effect on the packet's fate, but the counters on the rule will be incremented. | Optional | 
| gateway | This specifies the IP address of host to send the cloned packets.<br/>This option is only valid when `jump` is set to `TEE`. | Optional | 
| log_prefix | Specifies a log text for the rule. Only make sense with a LOG jump. | Optional | 
| log_level | Logging level according to the syslogd-defined priorities.<br/>The value can be strings or numbers from 1-8.<br/>This parameter is only applicable if `jump` is set to `LOG`. Possible values are: 0, 1, 2, 3, 4, 5, 6, 7, emerg, alert, crit, error, warning, notice, info, debug. | Optional | 
| goto | This specifies that the processing should continue in a user specified chain.<br/>Unlike the jump argument return will not continue processing in this chain but instead in the chain that called us via jump. | Optional | 
| in_interface | Name of an interface via which a packet was received (only for packets entering the `INPUT`, `FORWARD` and `PREROUTING` chains).<br/>When the `!` argument is used before the interface name, the sense is inverted.<br/>If the interface name ends in a `+`, then any interface which begins with this name will match.<br/>If this option is omitted, any interface name will match. | Optional | 
| out_interface | Name of an interface via which a packet is going to be sent (for packets entering the `FORWARD`, `OUTPUT` and `POSTROUTING` chains).<br/>When the `!` argument is used before the interface name, the sense is inverted.<br/>If the interface name ends in a `+`, then any interface which begins with this name will match.<br/>If this option is omitted, any interface name will match. | Optional | 
| fragment | This means that the rule only refers to second and further fragments of fragmented packets.<br/>Since there is no way to tell the source or destination ports of such a packet (or ICMP type), such a packet will not match any rules which specify them.<br/>When the "!" argument precedes fragment argument, the rule will only match head fragments, or unfragmented packets. | Optional | 
| set_counters | This enables the administrator to initialize the packet and byte counters of a rule (during `INSERT`, `APPEND`, `REPLACE` operations). | Optional | 
| source_port | Source port or port range specification.<br/>This can either be a service name or a port number.<br/>An inclusive range can also be specified, using the format `first:last`.<br/>If the first port is omitted, `0` is assumed; if the last is omitted, `65535` is assumed.<br/>If the first port is greater than the second one they will be swapped. | Optional | 
| destination_port | Destination port or port range specification. This can either be a service name or a port number. An inclusive range can also be specified, using the format first:last. If the first port is omitted, '0' is assumed; if the last is omitted, '65535' is assumed. If the first port is greater than the second one they will be swapped. This is only valid if the rule also specifies one of the following protocols: tcp, udp, dccp or sctp. | Optional | 
| to_ports | This specifies a destination port or range of ports to use, without this, the destination port is never altered.<br/>This is only valid if the rule also specifies one of the protocol `tcp`, `udp`, `dccp` or `sctp`. | Optional | 
| to_destination | This specifies a destination address to use with `DNAT`.<br/>Without this, the destination address is never altered. | Optional | 
| to_source | This specifies a source address to use with `SNAT`.<br/>Without this, the source address is never altered. | Optional | 
| syn | This allows matching packets that have the SYN bit set and the ACK and RST bits unset.<br/>When negated, this matches all packets with the RST or the ACK bits set. Possible values are: ignore, match, negate. Default is ignore. | Optional | 
| set_dscp_mark | This allows specifying a DSCP mark to be added to packets. It takes either an integer or hex value.<br/>Mutually exclusive with `set_dscp_mark_class`. | Optional | 
| set_dscp_mark_class | This allows specifying a predefined DiffServ class which will be translated to the corresponding DSCP mark.<br/>Mutually exclusive with `set_dscp_mark`. | Optional | 
| comment | This specifies a comment that will be added to the rule. | Optional | 
| ctstate | `ctstate` is a list of the connection states to match in the conntrack module.<br/>Possible states are `INVALID`, `NEW`, `ESTABLISHED`, `RELATED`, `UNTRACKED`, `SNAT`, `DNAT`. | Optional | 
| src_range | Specifies the source IP range to match in the iprange module. | Optional | 
| dst_range | Specifies the destination IP range to match in the iprange module. | Optional | 
| limit | Specifies the maximum average number of matches to allow per second.<br/>The number can specify units explicitly, using `/second', `/minute', `/hour' or `/day', or parts of them (so `5/second' is the same as `5/s'). | Optional | 
| limit_burst | Specifies the maximum burst before the above limit kicks in. | Optional | 
| uid_owner | Specifies the UID or username to use in match by owner rule.<br/>From Ansible 2.6 when the `!` argument is prepended then the it inverts the rule to apply instead to all users except that one specified. | Optional | 
| gid_owner | Specifies the GID or group to use in match by owner rule. | Optional | 
| reject_with | Specifies the error packet type to return while rejecting. It implies "jump: REJECT". | Optional | 
| icmp_type | This allows specification of the ICMP type, which can be a numeric ICMP type, type/code pair, or one of the ICMP type names shown by the command 'iptables -p icmp -h'. | Optional | 
| flush | Flushes the specified table and chain of all rules.<br/>If no chain is specified then the entire table is purged.<br/>Ignores all other parameters. | Optional | 
| policy | Set the policy for the chain to the given target.<br/>Only built-in chains can have policies.<br/>This parameter requires the `chain` parameter.<br/>Ignores all other parameters. Possible values are: ACCEPT, DROP, QUEUE, RETURN. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-iptables host="123.123.123.123" chain="INPUT" source="8.8.8.8" jump="DROP" ```

#### Context Example
```json
{
    "Linux": {
        "Iptables": {
            "chain": "INPUT",
            "changed": false,
            "flush": false,
            "host": "123.123.123.123",
            "ip_version": "ipv4",
            "rule": "-s 8.8.8.8 -j DROP",
            "state": "present",
            "status": "SUCCESS",
            "table": "filter"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * chain: INPUT
>  * changed: False
>  * flush: False
>  * ip_version: ipv4
>  * rule: -s 8.8.8.8 -j DROP
>  * state: present
>  * table: filter


### linux-java-cert
***
Uses keytool to import/remove key from java keystore (cacerts)
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/java_cert_module.html


#### Base Command

`linux-java-cert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| cert_url | Basic URL to fetch SSL certificate from.<br/>One of `cert_url` or `cert_path` is required to load certificate. | Optional | 
| cert_port | Port to connect to URL.<br/>This will be used to create server URL:PORT. Default is 443. | Optional | 
| cert_path | Local path to load certificate from.<br/>One of `cert_url` or `cert_path` is required to load certificate. | Optional | 
| cert_alias | Imported certificate alias.<br/>The alias is used when checking for the presence of a certificate in the keystore. | Optional | 
| pkcs12_path | Local path to load PKCS12 keystore from. | Optional | 
| pkcs12_password | Password for importing from PKCS12 keystore. | Optional | 
| pkcs12_alias | Alias in the PKCS12 keystore. | Optional | 
| keystore_path | Path to keystore. | Optional | 
| keystore_pass | Keystore password. | Required | 
| keystore_create | Create keystore if it does not exist. | Optional | 
| keystore_type | Keystore type (JCEKS, JKS). | Optional | 
| executable | Path to keytool binary if not used we search in PATH for it. Default is keytool. | Optional | 
| state | Defines action which can be either certificate import or removal. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.JavaCert.msg | string | Output from stdout of keytool command after execution of given command. | 
| Linux.JavaCert.rc | number | Keytool command execution return value. | 
| Linux.JavaCert.cmd | string | Executed command to get action done. | 


#### Command Example
```!linux-java-cert host="123.123.123.123" cert_url="google.com" cert_port="443" keystore_path="/usr/lib/jvm/jre-1.8.0/lib/security/cacerts" keystore_pass="changeit" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "JavaCert": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-java-keystore
***
Create or delete a Java keystore in JKS format.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/java_keystore_module.html


#### Base Command

`linux-java-keystore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the certificate. | Required | 
| certificate | Certificate that should be used to create the key store. | Required | 
| private_key | Private key that should be used to create the key store. | Required | 
| password | Password that should be used to secure the key store. | Required | 
| dest | Absolute path where the jks should be generated. | Required | 
| owner | Name of the user that should own jks file. | Optional | 
| group | Name of the group that should own jks file. | Optional | 
| mode | Mode the file should be. | Optional | 
| force | Key store will be created even if it already exists. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.JavaKeystore.msg | string | Output from stdout of keytool/openssl command after execution of given command or an error. | 
| Linux.JavaKeystore.rc | number | keytool/openssl command execution return value | 
| Linux.JavaKeystore.cmd | string | Executed command to get action done | 


#### Command Example
```!linux-java-keystore host="123.123.123.123" name="example" certificate="-----BEGIN CERTIFICATE-----\\nMIIB2zCCAYW...DDejA=\\n-----END CERTIFICATE-----" private_key="-----BEGIN PRIVATE KEY-----\\nMIIBVAIBADANBgkq...NGA56xjg=\\n-----END PRIVATE KEY-----"  dest="/etc/security/keystore.jks" password="changeit"```

#### Context Example
```json
{
    "Linux": {
        "JavaKeystore": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-kernel-blacklist
***
Deny list kernel modules
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/kernel_blacklist_module.html


#### Base Command

`linux-kernel-blacklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of kernel module to add to block list or allow list. | Required | 
| state | Whether the module should be present in the block list or absent. Possible values are: absent, present. Default is present. | Optional | 
| blacklist_file | If specified, use this block list file instead of `/etc/modprobe.d/blacklist-ansible.conf`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-kernel-blacklist host="123.123.123.123" name="nouveau" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "KernelBlacklist": {
            "changed": false,
            "host": "123.123.123.123",
            "name": "nouveau",
            "state": "present",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * name: nouveau
>  * state: present


### linux-known-hosts
***
Add or remove a host from the C(known_hosts) file
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/known_hosts_module.html


#### Base Command

`linux-known-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The host to add or remove (must match a host specified in key). It will be converted to lowercase so that ssh-keygen can find it.<br/>Must match with &lt;hostname&gt; or &lt;ip&gt; present in key attribute. | Required | 
| key | The SSH public host key, as a string (required if state=present, optional when state=absent, in which case all keys for the host are removed). The key must be in the right format for ssh (see sshd(8), section "SSH_KNOWN_HOSTS FILE FORMAT").<br/>Specifically, the key should not match the format that is found in an SSH pubkey file, but should rather have the hostname prepended to a line that includes the pubkey, the same way that it would appear in the known_hosts file. The value prepended to the line must also match the value of the name parameter.<br/>Should be of format `&lt;hostname[,IP]&gt; ssh-rsa &lt;pubkey&gt;`. | Optional | 
| path | The known_hosts file to edit. Default is (homedir)+/.ssh/known_hosts. | Optional | 
| hash_host | Hash the hostname in the known_hosts file. Default is no. | Optional | 
| state | `present` to add the host key, `absent` to remove it. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-known-hosts host="123.123.123.123" path="/etc/ssh/ssh_known_hosts" name="host1.example.com" key="host1.example.com,10.9.8.77 ssh-rsa ASDeararAIUHI324324" ```

#### Context Example
```json
{
    "Linux": {
        "KnownHosts": {
            "changed": false,
            "gid": 0,
            "group": "root",
            "hash_host": false,
            "host": "123.123.123.123",
            "key": "host1.example.com,10.9.8.77 ssh-rsa ASDeararAIUHI324324",
            "mode": "0644",
            "name": "host1.example.com",
            "owner": "root",
            "path": "/etc/ssh/ssh_known_hosts",
            "secontext": "system_u:object_r:etc_t:s0",
            "size": 56,
            "state": "file",
            "status": "SUCCESS",
            "uid": 0
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * gid: 0
>  * group: root
>  * hash_host: False
>  * key: host1.example.com,10.9.8.77 ssh-rsa ASDeararAIUHI324324
>  * mode: 0644
>  * name: host1.example.com
>  * owner: root
>  * path: /etc/ssh/ssh_known_hosts
>  * secontext: system_u:object_r:etc_t:s0
>  * size: 56
>  * state: file
>  * uid: 0


### linux-listen-ports-facts
***
Gather facts on processes listening on TCP and UDP ports.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/listen_ports_facts_module.html


#### Base Command

`linux-listen-ports-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.ListenPortsFacts.facts | unknown | Dictionary containing details of TCP and UDP ports with listening servers | 


#### Command Example
```!linux-listen-ports-facts host="123.123.123.123" ```

#### Context Example
```json
{
    "Linux": {
        "ListenPortsFacts": {
            "discovered_interpreter_python": "/usr/libexec/platform-python",
            "host": "123.123.123.123",
            "status": "SUCCESS",
            "tcp_listen": [
                {
                    "address": "0.0.0.0",
                    "name": "sshd",
                    "pid": 964,
                    "port": 22,
                    "protocol": "tcp",
                    "stime": "Sun Jul  4 18:12:31 2021",
                    "user": "root"
                }
            ],
            "udp_listen": [
                {
                    "address": "127.0.0.1",
                    "name": "chronyd",
                    "pid": 890,
                    "port": 323,
                    "protocol": "udp",
                    "stime": "Sun Jul  4 18:12:29 2021",
                    "user": "chrony"
                }
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * discovered_interpreter_python: /usr/libexec/platform-python
>  * ## Tcp_Listen
>  * ## Sshd
>    * address: 0.0.0.0
>    * name: sshd
>    * pid: 964
>    * port: 22
>    * protocol: tcp
>    * stime: Sun Jul  4 18:12:31 2021
>    * user: root
>  * ## Udp_Listen
>  * ## Chronyd
>    * address: 127.0.0.1
>    * name: chronyd
>    * pid: 890
>    * port: 323
>    * protocol: udp
>    * stime: Sun Jul  4 18:12:29 2021
>    * user: chrony

### linux-locale-gen
***
Creates or removes locales
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/locale_gen_module.html


#### Base Command

`linux-locale-gen`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name and encoding of the locale, such as "en_GB.UTF-8". | Required | 
| state | Whether the locale shall be present. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


### linux-modprobe
***
Load or unload kernel modules
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/modprobe_module.html


#### Base Command

`linux-modprobe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of kernel module to manage. | Required | 
| state | Whether the module should be present or absent. Possible values are: absent, present. Default is present. | Optional | 
| params | Modules parameters. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-modprobe host="123.123.123.123" name="8021q" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "Modprobe": {
            "changed": false,
            "host": "123.123.123.123",
            "name": "8021q",
            "params": "",
            "state": "present",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * name: 8021q
>  * params: 
>  * state: present


### linux-mount
***
Control active and configured mount points
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/mount_module.html


#### Base Command

`linux-mount`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the mount point (e.g. `/mnt/files`).<br/>Before Ansible 2.3 this option was only usable as `dest`, `destfile` and `name`. | Required | 
| src | Device to be mounted on `path`.<br/>Required when `state` set to `present` or `mounted`. | Optional | 
| fstype | Filesystem type.<br/>Required when `state` is `present` or `mounted`. | Optional | 
| opts | Mount options (see fstab(5), or vfstab(4) on Solaris). | Optional | 
| dump | Dump (see fstab(5)).<br/>Note that if set to `null` and `state` set to `present`, it will cease to work and duplicate entries will be made with subsequent runs.<br/>Has no effect on Solaris systems. Default is 0. | Optional | 
| passno | Passno (see fstab(5)).<br/>Note that if set to `null` and `state` set to `present`, it will cease to work and duplicate entries will be made with subsequent runs.<br/>Deprecated on Solaris systems. Default is 0. | Optional | 
| state | If `mounted`, the device will be actively mounted and appropriately configured in `fstab`. If the mount point is not present, the mount point will be created.<br/>If `unmounted`, the device will be unmounted without changing `fstab`.<br/>`present` only specifies that the device is to be configured in `fstab` and does not trigger or require a mount.<br/>`absent` specifies that the device mount's entry will be removed from `fstab` and will also unmount the device and remove the mount point.<br/>`remounted` specifies that the device will be remounted for when you want to force a refresh on the mount itself (added in 2.9). This will always return changed=true. Possible values are: absent, mounted, present, unmounted, remounted. | Required | 
| fstab | File to use instead of `/etc/fstab`.<br/>You should not use this option unless you really know what you are doing.<br/>This might be useful if you need to configure mountpoints in a chroot environment.<br/>OpenBSD does not allow specifying alternate fstab files with mount so do not use this on OpenBSD with any state that operates on the live filesystem.<br/>This parameter defaults to /etc/fstab or /etc/vfstab on Solaris. | Optional | 
| boot | Determines if the filesystem should be mounted on boot.<br/>Only applies to Solaris systems. Possible values are: Yes, No. Default is Yes. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-mount host="123.123.123.123" path="/mnt/dvd" "src"="/dev/sr0" fstype="iso9660" opts="ro,noauto" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "Mount": {
            "changed": false,
            "dump": "0",
            "fstab": "/etc/fstab",
            "fstype": "iso9660",
            "host": "123.123.123.123",
            "name": "/mnt/dvd",
            "opts": "ro,noauto",
            "passno": "0",
            "src": "/dev/sr0",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * dump: 0
>  * fstab: /etc/fstab
>  * fstype: iso9660
>  * name: /mnt/dvd
>  * opts: ro,noauto
>  * passno: 0
>  * src: /dev/sr0


### linux-open-iscsi
***
Manage iSCSI targets with Open-iSCSI
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/open_iscsi_module.html


#### Base Command

`linux-open-iscsi`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| portal | The IP address of the iSCSI target. | Optional | 
| port | The port on which the iSCSI target process listens. Default is 3260. | Optional | 
| target | The iSCSI target name. | Optional | 
| login | Whether the target node should be connected. | Optional | 
| node_auth | The value for `discovery.sendtargets.auth.authmethod`. Default is CHAP. | Optional | 
| node_user | The value for `discovery.sendtargets.auth.username`. | Optional | 
| node_pass | The value for `discovery.sendtargets.auth.password`. | Optional | 
| auto_node_startup | Whether the target node should be automatically connected at startup. | Optional | 
| discover | Whether the list of target nodes on the portal should be (re)discovered and added to the persistent iSCSI database.<br/>Keep in mind that `iscsiadm` discovery resets configuration, like `node.startup` to manual, hence combined with `auto_node_startup=yes` will always return a changed state. | Optional | 
| show_nodes | Whether the list of nodes in the persistent iSCSI database should be returned by the module. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-pam-limits
***
Modify Linux PAM limits
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/pam_limits_module.html


#### Base Command

`linux-pam-limits`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| domain | A username, @groupname, wildcard, uid/gid range. | Required | 
| limit_type | Limit type, see `man 5 limits.conf` for an explanation. Possible values are: hard, soft, -. | Required | 
| limit_item | The limit to be set. Possible values are: core, data, fsize, memlock, nofile, rss, stack, cpu, nproc, as, maxlogins, maxsyslogins, priority, locks, sigpending, msgqueue, nice, rtprio, chroot. | Required | 
| value | The value of the limit. | Required | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Default is no. | Optional | 
| use_min | If set to `yes`, the minimal value will be used or conserved. If the specified value is inferior to the value in the file, file content is replaced with the new value, else content is not modified. Default is no. | Optional | 
| use_max | If set to `yes`, the maximal value will be used or conserved. If the specified value is superior to the value in the file, file content is replaced with the new value, else content is not modified. Default is no. | Optional | 
| dest | Modify the limits.conf path. Default is /etc/security/limits.conf. | Optional | 
| comment | Comment associated with the limit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-pam-limits host="123.123.123.123" domain="joe" limit_type="soft" limit_item="nofile" value="64000" ```

#### Context Example
```json
{
    "Linux": {
        "PamLimits": {
            "changed": false,
            "host": "123.123.123.123",
            "msg": "joe\tsoft\tnofile\t64000\n",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * msg: joe	soft	nofile	64000
>


### linux-pamd
***
Manage PAM Modules
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/pamd_module.html


#### Base Command

`linux-pamd`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name generally refers to the PAM service file to change, for example system-auth. | Required | 
| type | The type of the PAM rule being modified.<br/>The `type`, `control` and `module_path` all must match a rule to be modified. Possible values are: account, -account, auth, -auth, password, -password, session, -session. | Required | 
| control | The control of the PAM rule being modified.<br/>This may be a complicated control with brackets. If this is the case, be sure to put "[bracketed controls]" in quotes.<br/>The `type`, `control` and `module_path` all must match a rule to be modified. | Required | 
| module_path | The module path of the PAM rule being modified.<br/>The `type`, `control` and `module_path` all must match a rule to be modified. | Required | 
| new_type | The new type to assign to the new rule. Possible values are: account, -account, auth, -auth, password, -password, session, -session. | Optional | 
| new_control | The new control to assign to the new rule. | Optional | 
| new_module_path | The new module path to be assigned to the new rule. | Optional | 
| module_arguments | When state is `updated`, the module_arguments will replace existing module_arguments.<br/>When state is `args_absent` args matching those listed in module_arguments will be removed.<br/>When state is `args_present` any args listed in module_arguments are added if missing from the existing rule.<br/>Furthermore, if the module argument takes a value denoted by `=`, the value will be changed to that specified in module_arguments. | Optional | 
| state | The default of `updated` will modify an existing rule if type, control and module_path all match an existing rule.<br/>With `before`, the new rule will be inserted before a rule matching type, control and module_path.<br/>Similarly, with `after`, the new rule will be inserted after an existing rulematching type, control and module_path.<br/>With either `before` or `after` new_type, new_control, and new_module_path must all be specified.<br/>If state is `args_absent` or `args_present`, new_type, new_control, and new_module_path will be ignored.<br/>State `absent` will remove the rule.  The 'absent' state was added in Ansible 2.4. Possible values are: absent, before, after, args_absent, args_present, updated. Default is updated. | Optional | 
| path | This is the path to the PAM service files. Default is /etc/pam.d. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Pamd.change_count | number | How many rules were changed. | 
| Linux.Pamd.new_rule | string | The changes to the rule.  This was available in Ansible 2.4 and Ansible 2.5.  It was removed in Ansible 2.6. | 
| Linux.Pamd.updated_rule_(n) | string | The rule\(s\) that was/were changed.  This is only available in Ansible 2.4 and was removed in Ansible 2.5. | 
| Linux.Pamd.action | string | That action that was taken and is one of: update_rule, insert_before_rule, insert_after_rule, args_present, args_absent, absent. This was available in Ansible 2.4 and removed in Ansible 2.8 | 
| Linux.Pamd.dest | string | Path to pam.d service that was changed.  This is only available in Ansible 2.3 and was removed in Ansible 2.4. | 
| Linux.Pamd.backupdest | string | The file name of the backup file, if created. | 


#### Command Example
```!linux-pamd host="123.123.123.123" name="system-auth" type="auth" control="required" module_path="pam_faillock.so" new_control="sufficient" ```

#### Context Example
```json
{
    "Linux": {
        "Pamd": {
            "backupdest": "",
            "change_count": 0,
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * backupdest: 
>  * change_count: 0
>  * changed: False


### linux-parted
***
Configure block device partitions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/parted_module.html


#### Base Command

`linux-parted`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| device | The block device (disk) where to operate. | Required | 
| align | Set alignment for newly created partitions. Possible values are: cylinder, minimal, none, optimal. Default is optimal. | Optional | 
| number | The number of the partition to work with or the number of the partition that will be created.<br/>Required when performing any action on the disk, except fetching information. | Optional | 
| unit | Selects the current default unit that Parted will use to display locations and capacities on the disk and to interpret those given by the user if they are not suffixed by an unit.<br/>When fetching information about a disk, it is always recommended to specify a unit. Possible values are: s, B, KB, KiB, MB, MiB, GB, GiB, TB, TiB, %, cyl, chs, compact. Default is KiB. | Optional | 
| label | Creates a new disk label. Possible values are: aix, amiga, bsd, dvh, gpt, loop, mac, msdos, pc98, sun. Default is msdos. | Optional | 
| part_type | May be specified only with 'msdos' or 'dvh' partition tables.<br/>A `name` must be specified for a 'gpt' partition table.<br/>Neither `part_type` nor `name` may be used with a 'sun' partition table. Possible values are: extended, logical, primary. Default is primary. | Optional | 
| part_start | Where the partition will start as offset from the beginning of the disk, that is, the "distance" from the start of the disk.<br/>The distance can be specified with all the units supported by parted (except compat) and it is case sensitive, e.g. `10GiB`, `15%`. Default is 0%. | Optional | 
| part_end | Where the partition will end as offset from the beginning of the disk, that is, the "distance" from the start of the disk.<br/>The distance can be specified with all the units supported by parted (except compat) and it is case sensitive, e.g. `10GiB`, `15%`. Default is 100%. | Optional | 
| name | Sets the name for the partition number (GPT, Mac, MIPS and PC98 only). | Optional | 
| flags | A list of the flags that has to be set on the partition. | Optional | 
| state | Whether to create or delete a partition.<br/>If set to `info` the module will only return the device information. Possible values are: absent, present, info. Default is info. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Parted.partition_info | unknown | Current partition information | 


#### Command Example
```!linux-parted host="123.123.123.123" device="/dev/sdb" number="1" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "Parted": {
            "changed": false,
            "disk": {
                "dev": "/dev/sdb",
                "logical_block": 512,
                "model": "VMware Virtual disk",
                "physical_block": 512,
                "size": 1048576,
                "table": "msdos",
                "unit": "kib"
            },
            "host": "123.123.123.123",
            "partitions": [
                {
                    "begin": 1024,
                    "end": 1048576,
                    "flags": [],
                    "fstype": "ext2",
                    "name": "",
                    "num": 1,
                    "size": 1047552,
                    "unit": "kib"
                }
            ],
            "script": "",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * script: 
>  * ## Disk
>    * dev: /dev/sdb
>    * logical_block: 512
>    * model: VMware Virtual disk
>    * physical_block: 512
>    * size: 1048576.0
>    * table: msdos
>    * unit: kib
>  * ## Partitions
>  * ## 
>    * begin: 1024.0
>    * end: 1048576.0
>    * fstype: ext2
>    * name: 
>    * num: 1
>    * size: 1047552.0
>    * unit: kib
>    * ### Flags


### linux-pids
***
Retrieves process IDs list if the process is running otherwise return empty list
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/pids_module.html


#### Base Command

`linux-pids`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | the name of the process you want to get PID for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Pids.pids | unknown | Process IDs of the given process | 


#### Command Example
```!linux-pids host="123.123.123.123" name="python" ```

#### Context Example
```json
{
    "Linux": {
        "Pids": [
            []
        ]
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 


### linux-ping
***
Try to connect to host, verify a usable python and return C(pong) on success
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ping_module.html


#### Base Command

`linux-ping`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| data | Data to return for the `ping` return value.<br/>If this parameter is set to `crash`, the module will cause an exception. Default is pong. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Ping.ping | string | value provided with the data parameter | 


#### Command Example
```!linux-ping host="123.123.123.123" ```

#### Context Example
```json
{
    "Linux": {
        "Ping": [
            "pong"
        ]
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 


### linux-python-requirements-info
***
Show python path and assert dependency versions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/python_requirements_info_module.html


#### Base Command

`linux-python-requirements-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dependencies | A list of version-likes or module names to check for installation. Supported operators: &lt;, &gt;, &lt;=, &gt;=, or ==. The bare module name like I(ansible), the module with a specific version like I(boto3==1.6.1), or a partial version like I(requests&gt;2) are all valid specifications.<br/>. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.PythonRequirementsInfo.python | string | path to python version used | 
| Linux.PythonRequirementsInfo.python_version | string | version of python | 
| Linux.PythonRequirementsInfo.python_system_path | unknown | List of paths python is looking for modules in | 
| Linux.PythonRequirementsInfo.valid | unknown | A dictionary of dependencies that matched their desired versions. If no version was specified, then \`desired\` will be null | 
| Linux.PythonRequirementsInfo.mismatched | unknown | A dictionary of dependencies that did not satisfy the desired version | 
| Linux.PythonRequirementsInfo.not_found | unknown | A list of packages that could not be imported at all, and are not installed | 


#### Command Example
```!linux-python-requirements-info host="123.123.123.123" ```

#### Context Example
```json
{
    "Linux": {
        "PythonRequirementsInfo": {
            "changed": false,
            "host": "123.123.123.123",
            "mismatched": {},
            "not_found": [],
            "python": "/usr/libexec/platform-python",
            "python_system_path": [
                "/tmp/python_requirements_info_payload_ppjh5d0o/python_requirements_info_payload.zip",
                "/usr/lib64/python36.zip",
                "/usr/lib64/python3.6",
                "/usr/lib64/python3.6/lib-dynload",
                "/usr/local/lib64/python3.6/site-packages",
                "/usr/local/lib/python3.6/site-packages",
                "/usr/lib64/python3.6/site-packages",
                "/usr/lib/python3.6/site-packages"
            ],
            "python_version": "3.6.8 (default, Aug 24 2020, 17:57:11) \n[GCC 8.3.1 20191121 (Red Hat 8.3.1-5)]",
            "status": "SUCCESS",
            "valid": {}
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * python: /usr/libexec/platform-python
>  * python_version: 3.6.8 (default, Aug 24 2020, 17:57:11) 
>[GCC 8.3.1 20191121 (Red Hat 8.3.1-5)]
>  * ## Mismatched
>  * ## Not_Found
>  * ## Python_System_Path
>    * 0: /tmp/python_requirements_info_payload_ppjh5d0o/python_requirements_info_payload.zip
>    * 1: /usr/lib64/python36.zip
>    * 2: /usr/lib64/python3.6
>    * 3: /usr/lib64/python3.6/lib-dynload
>    * 4: /usr/local/lib64/python3.6/site-packages
>    * 5: /usr/local/lib/python3.6/site-packages
>    * 6: /usr/lib64/python3.6/site-packages
>    * 7: /usr/lib/python3.6/site-packages
>  * ## Valid


### linux-reboot
***
Reboot a machine
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/reboot_module.html


#### Base Command

`linux-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| pre_reboot_delay | Seconds to wait before reboot. Passed as a parameter to the reboot command.<br/>On Linux, macOS and OpenBSD, this is converted to minutes and rounded down. If less than 60, it will be set to 0.<br/>On Solaris and FreeBSD, this will be seconds. Default is 0. | Optional | 
| post_reboot_delay | Seconds to wait after the reboot command was successful before attempting to validate the system rebooted successfully.<br/>This is useful if you want wait for something to settle despite your connection already working. Default is 0. | Optional | 
| reboot_timeout | Maximum seconds to wait for machine to reboot and respond to a test command.<br/>This timeout is evaluated separately for both reboot verification and test command success so the maximum execution time for the module is twice this amount. Default is 600. | Optional | 
| connect_timeout | Maximum seconds to wait for a successful connection to the managed hosts before trying again.<br/>If unspecified, the default setting for the underlying connection plugin is used. | Optional | 
| test_command | Command to run on the rebooted host and expect success from to determine the machine is ready for further tasks. Default is whoami. | Optional | 
| msg | Message to display to users before reboot. Default is Reboot initiated by Ansible. | Optional | 
| search_paths | Paths to search on the remote machine for the `shutdown` command.<br/>`Only` these paths will be searched for the `shutdown` command. `PATH` is ignored in the remote node when searching for the `shutdown` command. Default is ['/sbin', '/usr/sbin', '/usr/local/sbin']. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Reboot.rebooted | boolean | true if the machine was rebooted | 
| Linux.Reboot.elapsed | number | The number of seconds that elapsed waiting for the system to be rebooted. | 



### linux-seboolean
***
Toggles SELinux booleans
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/seboolean_module.html


#### Base Command

`linux-seboolean`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the boolean to configure. | Required | 
| persistent | Set to `yes` if the boolean setting should survive a reboot. Default is no. | Optional | 
| state | Desired boolean value. | Required | 
| ignore_selinux_state | Useful for scenarios (chrooted environment) that you can't get the real SELinux state. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-sefcontext
***
Manages SELinux file context mapping definitions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/sefcontext_module.html


#### Base Command

`linux-sefcontext`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| target | Target path (expression). | Required | 
| ftype | The file type that should have SELinux contexts applied.<br/>The following file type options are available:<br/>`a` for all files,<br/>`b` for block devices,<br/>`c` for character devices,<br/>`d` for directories,<br/>`f` for regular files,<br/>`l` for symbolic links,<br/>`p` for named pipes,<br/>`s` for socket files. Possible values are: a, b, c, d, f, l, p, s. Default is a. | Optional | 
| setype | SELinux type for the specified target. | Required | 
| seuser | SELinux user for the specified target. | Optional | 
| selevel | SELinux range for the specified target. | Optional | 
| state | Whether the SELinux file context must be `absent` or `present`. Possible values are: absent, present. Default is present. | Optional | 
| reload | Reload SELinux policy after commit.<br/>Note that this does not apply SELinux file contexts to existing files. Possible values are: Yes, No. Default is Yes. | Optional | 
| ignore_selinux_state | Useful for scenarios (chrooted environment) that you can't get the real SELinux state. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-selinux
***
Change policy and state of SELinux
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/selinux_module.html


#### Base Command

`linux-selinux`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| policy | The name of the SELinux policy to use (e.g. `targeted`) will be required if state is not `disabled`. | Optional | 
| state | The SELinux mode. Possible values are: disabled, enforcing, permissive. | Required | 
| configfile | The path to the SELinux configuration file, if non-standard. Default is /etc/selinux/config. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Selinux.msg | string | Messages that describe changes that were made. | 
| Linux.Selinux.configfile | string | Path to SELinux configuration file. | 
| Linux.Selinux.policy | string | Name of the SELinux policy. | 
| Linux.Selinux.state | string | SELinux mode. | 
| Linux.Selinux.reboot_required | boolean | Whether or not an reboot is required for the changes to take effect. | 


#### Command Example
```!linux-selinux host="123.123.123.123" policy="targeted" state="enforcing" ```

#### Context Example
```json
{
    "Linux": {
        "Selinux": {
            "changed": false,
            "configfile": "/etc/selinux/config",
            "host": "123.123.123.123",
            "msg": "",
            "policy": "targeted",
            "reboot_required": false,
            "state": "enforcing",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * configfile: /etc/selinux/config
>  * msg: 
>  * policy: targeted
>  * reboot_required: False
>  * state: enforcing


### linux-selinux-permissive
***
Change permissive domain in SELinux policy
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/selinux_permissive_module.html


#### Base Command

`linux-selinux-permissive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| domain | The domain that will be added or removed from the list of permissive domains. | Required | 
| permissive | Indicate if the domain should or should not be set as permissive. | Required | 
| no_reload | Disable reloading of the SELinux policy after making change to a domain's permissive setting.<br/>The default is `no`, which causes policy to be reloaded when a domain changes state.<br/>Reloading the policy does not work on older versions of the `policycoreutils-python` library, for example in EL 6.". Possible values are: Yes, No. Default is No. | Optional | 
| store | Name of the SELinux policy store to use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-selogin
***
Manages linux user to SELinux user mapping
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/selogin_module.html


#### Base Command

`linux-selogin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| login | a Linux user. | Required | 
| seuser | SELinux user name. | Required | 
| selevel | MLS/MCS Security Range (MLS/MCS Systems only) SELinux Range for SELinux login mapping defaults to the SELinux user record range. Default is s0. | Optional | 
| state | Desired mapping value. Possible values are: present, absent. Default is present. | Required | 
| reload | Reload SELinux policy after commit. Possible values are: Yes, No. Default is Yes. | Optional | 
| ignore_selinux_state | Run independent of selinux runtime state. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-seport
***
Manages SELinux network port type definitions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/seport_module.html


#### Base Command

`linux-seport`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| ports | Ports or port ranges.<br/>Can be a list (since 2.6) or comma separated string. | Required | 
| proto | Protocol for the specified port. Possible values are: tcp, udp. | Required | 
| setype | SELinux type for the specified port. | Required | 
| state | Desired boolean value. Possible values are: absent, present. Default is present. | Optional | 
| reload | Reload SELinux policy after commit. Possible values are: Yes, No. Default is Yes. | Optional | 
| ignore_selinux_state | Run independent of selinux runtime state. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-service
***
Manage services
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/service_module.html


#### Base Command

`linux-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the service. | Required | 
| state | `started`/`stopped` are idempotent actions that will not run commands unless necessary.<br/>`restarted` will always bounce the service.<br/>`reloaded` will always reload.<br/>`At least one of state and enabled are required.`<br/>Note that reloaded will start the service if it is not already started, even if your chosen init system wouldn't normally. Possible values are: reloaded, restarted, started, stopped. | Optional | 
| sleep | If the service is being `restarted` then sleep this many seconds between the stop and start command.<br/>This helps to work around badly-behaving init scripts that exit immediately after signaling a process to stop.<br/>Not all service managers support sleep, i.e when using systemd this setting will be ignored. | Optional | 
| pattern | If the service does not respond to the status command, name a substring to look for as would be found in the output of the `ps` command as a stand-in for a status result.<br/>If the string is found, the service will be assumed to be started. | Optional | 
| enabled | Whether the service should start on boot.<br/>`At least one of state and enabled are required.`. | Optional | 
| runlevel | For OpenRC init scripts (e.g. Gentoo) only.<br/>The runlevel that this service belongs to. Default is default. | Optional | 
| arguments | Additional arguments provided on the command line. | Optional | 
| use | The service module actually uses system specific modules, normally through auto detection, this setting can force a specific module.<br/>Normally it uses the value of the 'service_mgr' fact and falls back to the old 'service' module when none matching is found. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-service host="123.123.123.123" name="httpd" state="started" ```

#### Context Example
```json
{
    "Linux": {
        "Service": {
            "changed": false,
            "host": "123.123.123.123",
            "name": "httpd",
            "state": "started",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * name: httpd
>  * state: started
>  * ## Status
>    * ActiveEnterTimestamp: Thu 2021-07-08 14:12:41 JST
>    * ActiveEnterTimestampMonotonic: 331222117201
>    * ActiveExitTimestampMonotonic: 0
>    * ActiveState: active
>    * After: system.slice basic.target systemd-journald.socket systemd-tmpfiles-setup.service -.mount nss-lookup.target remote-fs.target httpd-init.service sysinit.target network.target tmp.mount
>    * AllowIsolate: no
>    * AllowedCPUs: 
>    * AllowedMemoryNodes: 
>    * AmbientCapabilities: 
>    * AssertResult: yes
>    * AssertTimestamp: Thu 2021-07-08 14:12:41 JST
>    * AssertTimestampMonotonic: 331221986103
>    * Before: shutdown.target
>    * BlockIOAccounting: no
>    * BlockIOWeight: [not set]
>    * CPUAccounting: no
>    * CPUAffinity: 
>    * CPUQuotaPerSecUSec: infinity
>    * CPUSchedulingPolicy: 0
>    * CPUSchedulingPriority: 0
>    * CPUSchedulingResetOnFork: no
>    * CPUShares: [not set]
>    * CPUUsageNSec: [not set]
>    * CPUWeight: [not set]
>    * CacheDirectoryMode: 0755
>    * CanIsolate: no
>    * CanReload: yes
>    * CanStart: yes
>    * CanStop: yes
>    * CapabilityBoundingSet: cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend
>    * CollectMode: inactive
>    * ConditionResult: yes
>    * ConditionTimestamp: Thu 2021-07-08 14:12:41 JST
>    * ConditionTimestampMonotonic: 331221986102
>    * ConfigurationDirectoryMode: 0755
>    * Conflicts: shutdown.target
>    * ControlGroup: /system.slice/httpd.service
>    * ControlPID: 0
>    * DefaultDependencies: yes
>    * Delegate: no
>    * Description: The Apache HTTP Server
>    * DevicePolicy: auto
>    * Documentation: man:httpd.service(8)
>    * DynamicUser: no
>    * EffectiveCPUs: 
>    * EffectiveMemoryNodes: 
>    * Environment: LANG=C
>    * ExecMainCode: 0
>    * ExecMainExitTimestampMonotonic: 0
>    * ExecMainPID: 7626
>    * ExecMainStartTimestamp: Thu 2021-07-08 14:12:41 JST
>    * ExecMainStartTimestampMonotonic: 331221988640
>    * ExecMainStatus: 0
>    * ExecReload: { path=/usr/sbin/httpd ; argv[]=/usr/sbin/httpd $OPTIONS -k graceful ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
>    * ExecStart: { path=/usr/sbin/httpd ; argv[]=/usr/sbin/httpd $OPTIONS -DFOREGROUND ; ignore_errors=no ; start_time=[Thu 2021-07-08 14:12:41 JST] ; stop_time=[n/a] ; pid=7626 ; code=(null) ; status=0/0 }
>    * FailureAction: none
>    * FileDescriptorStoreMax: 0
>    * FragmentPath: /usr/lib/systemd/system/httpd.service
>    * GID: [not set]
>    * GuessMainPID: yes
>    * IOAccounting: no
>    * IOSchedulingClass: 0
>    * IOSchedulingPriority: 0
>    * IOWeight: [not set]
>    * IPAccounting: no
>    * IPEgressBytes: 18446744073709551615
>    * IPEgressPackets: 18446744073709551615
>    * IPIngressBytes: 18446744073709551615
>    * IPIngressPackets: 18446744073709551615
>    * Id: httpd.service
>    * IgnoreOnIsolate: no
>    * IgnoreSIGPIPE: yes
>    * InactiveEnterTimestampMonotonic: 0
>    * InactiveExitTimestamp: Thu 2021-07-08 14:12:41 JST
>    * InactiveExitTimestampMonotonic: 331221988825
>    * InvocationID: 7bb9f1e196514d5f87dfb3602a1c9e32
>    * JobRunningTimeoutUSec: infinity
>    * JobTimeoutAction: none
>    * JobTimeoutUSec: infinity
>    * KeyringMode: private
>    * KillMode: mixed
>    * KillSignal: 28
>    * LimitAS: infinity
>    * LimitASSoft: infinity
>    * LimitCORE: infinity
>    * LimitCORESoft: infinity
>    * LimitCPU: infinity
>    * LimitCPUSoft: infinity
>    * LimitDATA: infinity
>    * LimitDATASoft: infinity
>    * LimitFSIZE: infinity
>    * LimitFSIZESoft: infinity
>    * LimitLOCKS: infinity
>    * LimitLOCKSSoft: infinity
>    * LimitMEMLOCK: 65536
>    * LimitMEMLOCKSoft: 65536
>    * LimitMSGQUEUE: 819200
>    * LimitMSGQUEUESoft: 819200
>    * LimitNICE: 0
>    * LimitNICESoft: 0
>    * LimitNOFILE: 262144
>    * LimitNOFILESoft: 1024
>    * LimitNPROC: 7805
>    * LimitNPROCSoft: 7805
>    * LimitRSS: infinity
>    * LimitRSSSoft: infinity
>    * LimitRTPRIO: 0
>    * LimitRTPRIOSoft: 0
>    * LimitRTTIME: infinity
>    * LimitRTTIMESoft: infinity
>    * LimitSIGPENDING: 7805
>    * LimitSIGPENDINGSoft: 7805
>    * LimitSTACK: infinity
>    * LimitSTACKSoft: 8388608
>    * LoadState: loaded
>    * LockPersonality: no
>    * LogLevelMax: -1
>    * LogRateLimitBurst: 0
>    * LogRateLimitIntervalUSec: 0
>    * LogsDirectoryMode: 0755
>    * MainPID: 7626
>    * MemoryAccounting: yes
>    * MemoryCurrent: 30425088
>    * MemoryDenyWriteExecute: no
>    * MemoryHigh: infinity
>    * MemoryLimit: infinity
>    * MemoryLow: 0
>    * MemoryMax: infinity
>    * MemorySwapMax: infinity
>    * MountAPIVFS: no
>    * MountFlags: 
>    * NFileDescriptorStore: 0
>    * NRestarts: 0
>    * NUMAMask: 
>    * NUMAPolicy: n/a
>    * Names: httpd.service
>    * NeedDaemonReload: no
>    * Nice: 0
>    * NoNewPrivileges: no
>    * NonBlocking: no
>    * NotifyAccess: main
>    * OOMScoreAdjust: 0
>    * OnFailureJobMode: replace
>    * PermissionsStartOnly: no
>    * Perpetual: no
>    * PrivateDevices: no
>    * PrivateMounts: no
>    * PrivateNetwork: no
>    * PrivateTmp: yes
>    * PrivateUsers: no
>    * ProtectControlGroups: no
>    * ProtectHome: no
>    * ProtectKernelModules: no
>    * ProtectKernelTunables: no
>    * ProtectSystem: no
>    * RefuseManualStart: no
>    * RefuseManualStop: no
>    * RemainAfterExit: no
>    * RemoveIPC: no
>    * Requires: system.slice sysinit.target -.mount
>    * RequiresMountsFor: /var/tmp
>    * Restart: no
>    * RestartUSec: 100ms
>    * RestrictNamespaces: no
>    * RestrictRealtime: no
>    * RestrictSUIDSGID: no
>    * Result: success
>    * RootDirectoryStartOnly: no
>    * RuntimeDirectoryMode: 0755
>    * RuntimeDirectoryPreserve: no
>    * RuntimeMaxUSec: infinity
>    * SameProcessGroup: no
>    * SecureBits: 0
>    * SendSIGHUP: no
>    * SendSIGKILL: yes
>    * Slice: system.slice
>    * StandardError: inherit
>    * StandardInput: null
>    * StandardInputData: 
>    * StandardOutput: journal
>    * StartLimitAction: none
>    * StartLimitBurst: 5
>    * StartLimitIntervalUSec: 10s
>    * StartupBlockIOWeight: [not set]
>    * StartupCPUShares: [not set]
>    * StartupCPUWeight: [not set]
>    * StartupIOWeight: [not set]
>    * StateChangeTimestamp: Thu 2021-07-08 14:12:41 JST
>    * StateChangeTimestampMonotonic: 331222165344
>    * StateDirectoryMode: 0755
>    * StatusErrno: 0
>    * StatusText: Running, listening on: port 80
>    * StopWhenUnneeded: no
>    * SubState: running
>    * SuccessAction: none
>    * SyslogFacility: 3
>    * SyslogLevel: 6
>    * SyslogLevelPrefix: yes
>    * SyslogPriority: 30
>    * SystemCallErrorNumber: 0
>    * TTYReset: no
>    * TTYVHangup: no
>    * TTYVTDisallocate: no
>    * TasksAccounting: yes
>    * TasksCurrent: 213
>    * TasksMax: 12488
>    * TimeoutStartUSec: 1min 30s
>    * TimeoutStopUSec: 1min 30s
>    * TimerSlackNSec: 50000
>    * Transient: no
>    * Type: notify
>    * UID: [not set]
>    * UMask: 0022
>    * UnitFilePreset: disabled
>    * UnitFileState: disabled
>    * UtmpMode: init
>    * Wants: httpd-init.service
>    * WatchdogTimestamp: Thu 2021-07-08 14:12:41 JST
>    * WatchdogTimestampMonotonic: 331222117198
>    * WatchdogUSec: 0


### linux-service-facts
***
Return service state information as fact data
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/service_facts_module.html


#### Base Command

`linux-service-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.ServiceFacts.facts | unknown | Facts to add to facts about the services on the system | 


#### Command Example
```!linux-service-facts host="123.123.123.123" ```

#### Context Example
```json
{
    "Linux": {
        "ServiceFacts": {
            "discovered_interpreter_python": "/usr/libexec/platform-python",
            "host": "123.123.123.123",
            "services": {
                "NetworkManager-dispatcher.service": {
                    "name": "NetworkManager-dispatcher.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "enabled"
                },
                "NetworkManager-wait-online.service": {
                    "name": "NetworkManager-wait-online.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "NetworkManager.service": {
                    "name": "NetworkManager.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "arp-ethers.service": {
                    "name": "arp-ethers.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "atd.service": {
                    "name": "atd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "auditd.service": {
                    "name": "auditd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "autovt@.service": {
                    "name": "autovt@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "enabled"
                },
                "blk-availability.service": {
                    "name": "blk-availability.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "chrony-dnssrv@.service": {
                    "name": "chrony-dnssrv@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "chrony-wait.service": {
                    "name": "chrony-wait.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "chronyd.service": {
                    "name": "chronyd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "console-getty.service": {
                    "name": "console-getty.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "container-getty@.service": {
                    "name": "container-getty@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "cpupower.service": {
                    "name": "cpupower.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "disabled"
                },
                "crond.service": {
                    "name": "crond.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "dbus-org.fedoraproject.FirewallD1.service": {
                    "name": "dbus-org.fedoraproject.FirewallD1.service",
                    "source": "systemd",
                    "state": "active",
                    "status": "enabled"
                },
                "dbus-org.freedesktop.hostname1.service": {
                    "name": "dbus-org.freedesktop.hostname1.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "dbus-org.freedesktop.locale1.service": {
                    "name": "dbus-org.freedesktop.locale1.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "dbus-org.freedesktop.login1.service": {
                    "name": "dbus-org.freedesktop.login1.service",
                    "source": "systemd",
                    "state": "active",
                    "status": "static"
                },
                "dbus-org.freedesktop.nm-dispatcher.service": {
                    "name": "dbus-org.freedesktop.nm-dispatcher.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "enabled"
                },
                "dbus-org.freedesktop.portable1.service": {
                    "name": "dbus-org.freedesktop.portable1.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "dbus-org.freedesktop.timedate1.service": {
                    "name": "dbus-org.freedesktop.timedate1.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "enabled"
                },
                "dbus.service": {
                    "name": "dbus.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "static"
                },
                "debug-shell.service": {
                    "name": "debug-shell.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "dm-event.service": {
                    "name": "dm-event.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dnf-makecache.service": {
                    "name": "dnf-makecache.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-cmdline.service": {
                    "name": "dracut-cmdline.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-initqueue.service": {
                    "name": "dracut-initqueue.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-mount.service": {
                    "name": "dracut-mount.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-pre-mount.service": {
                    "name": "dracut-pre-mount.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-pre-pivot.service": {
                    "name": "dracut-pre-pivot.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-pre-trigger.service": {
                    "name": "dracut-pre-trigger.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-pre-udev.service": {
                    "name": "dracut-pre-udev.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "dracut-shutdown.service": {
                    "name": "dracut-shutdown.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "ebtables.service": {
                    "name": "ebtables.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "disabled"
                },
                "emergency.service": {
                    "name": "emergency.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "firewalld.service": {
                    "name": "firewalld.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "fstrim.service": {
                    "name": "fstrim.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "getty@.service": {
                    "name": "getty@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "enabled"
                },
                "test@test.service": {
                    "name": "test@test.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "unknown"
                },
                "grub-boot-indeterminate.service": {
                    "name": "grub-boot-indeterminate.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "halt-local.service": {
                    "name": "halt-local.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "htcacheclean.service": {
                    "name": "htcacheclean.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "httpd.service": {
                    "name": "httpd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "disabled"
                },
                "httpd@.service": {
                    "name": "httpd@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "disabled"
                },
                "import-state.service": {
                    "name": "import-state.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "initrd-cleanup.service": {
                    "name": "initrd-cleanup.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "initrd-parse-etc.service": {
                    "name": "initrd-parse-etc.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "initrd-switch-root.service": {
                    "name": "initrd-switch-root.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "initrd-udevadm-cleanup-db.service": {
                    "name": "initrd-udevadm-cleanup-db.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "iprdump.service": {
                    "name": "iprdump.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "iprinit.service": {
                    "name": "iprinit.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "iprupdate.service": {
                    "name": "iprupdate.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "irqbalance.service": {
                    "name": "irqbalance.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "kdump.service": {
                    "name": "kdump.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "kmod-static-nodes.service": {
                    "name": "kmod-static-nodes.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "ldconfig.service": {
                    "name": "ldconfig.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "loadmodules.service": {
                    "name": "loadmodules.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "lvm2-lvmpolld.service": {
                    "name": "lvm2-lvmpolld.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "lvm2-monitor.service": {
                    "name": "lvm2-monitor.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "lvm2-pvscan@.service": {
                    "name": "lvm2-pvscan@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "lvm2-pvscan@8:2.service": {
                    "name": "lvm2-pvscan@8:2.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "man-db-cache-update.service": {
                    "name": "man-db-cache-update.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "messagebus.service": {
                    "name": "messagebus.service",
                    "source": "systemd",
                    "state": "active",
                    "status": "static"
                },
                "microcode.service": {
                    "name": "microcode.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "nftables.service": {
                    "name": "nftables.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "nis-domainname.service": {
                    "name": "nis-domainname.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "plymouth-halt.service": {
                    "name": "plymouth-halt.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "plymouth-kexec.service": {
                    "name": "plymouth-kexec.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "plymouth-poweroff.service": {
                    "name": "plymouth-poweroff.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "plymouth-quit-wait.service": {
                    "name": "plymouth-quit-wait.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "plymouth-quit.service": {
                    "name": "plymouth-quit.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "plymouth-read-write.service": {
                    "name": "plymouth-read-write.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "plymouth-reboot.service": {
                    "name": "plymouth-reboot.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "plymouth-start.service": {
                    "name": "plymouth-start.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "plymouth-switch-root.service": {
                    "name": "plymouth-switch-root.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "polkit.service": {
                    "name": "polkit.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "static"
                },
                "quotaon.service": {
                    "name": "quotaon.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "rc-local.service": {
                    "name": "rc-local.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "rdisc.service": {
                    "name": "rdisc.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "rescue.service": {
                    "name": "rescue.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "rngd-wake-threshold.service": {
                    "name": "rngd-wake-threshold.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "disabled"
                },
                "rngd.service": {
                    "name": "rngd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "rsyslog.service": {
                    "name": "rsyslog.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "selinux-autorelabel-mark.service": {
                    "name": "selinux-autorelabel-mark.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "enabled"
                },
                "selinux-autorelabel.service": {
                    "name": "selinux-autorelabel.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "serial-getty@.service": {
                    "name": "serial-getty@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "disabled"
                },
                "sshd-keygen@.service": {
                    "name": "sshd-keygen@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "disabled"
                },
                "test1@test.service": {
                    "name": "test1@test.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "test2@test.service": {
                    "name": "test2@test.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "test3@test.service": {
                    "name": "test3@test.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "sshd.service": {
                    "name": "sshd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "sshd@.service": {
                    "name": "sshd@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "sssd-autofs.service": {
                    "name": "sssd-autofs.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "indirect"
                },
                "sssd-kcm.service": {
                    "name": "sssd-kcm.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "indirect"
                },
                "sssd-nss.service": {
                    "name": "sssd-nss.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "indirect"
                },
                "sssd-pac.service": {
                    "name": "sssd-pac.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "indirect"
                },
                "sssd-pam.service": {
                    "name": "sssd-pam.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "indirect"
                },
                "sssd-ssh.service": {
                    "name": "sssd-ssh.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "indirect"
                },
                "sssd-sudo.service": {
                    "name": "sssd-sudo.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "indirect"
                },
                "sssd.service": {
                    "name": "sssd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "syslog.service": {
                    "name": "syslog.service",
                    "source": "systemd",
                    "state": "active",
                    "status": "enabled"
                },
                "system-update-cleanup.service": {
                    "name": "system-update-cleanup.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-ask-password-console.service": {
                    "name": "systemd-ask-password-console.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-ask-password-plymouth.service": {
                    "name": "systemd-ask-password-plymouth.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-ask-password-wall.service": {
                    "name": "systemd-ask-password-wall.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-backlight@.service": {
                    "name": "systemd-backlight@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "systemd-binfmt.service": {
                    "name": "systemd-binfmt.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-coredump@.service": {
                    "name": "systemd-coredump@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "test4@test.service": {
                    "name": "test4@test.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "systemd-exit.service": {
                    "name": "systemd-exit.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-firstboot.service": {
                    "name": "systemd-firstboot.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-fsck-root.service": {
                    "name": "systemd-fsck-root.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-fsck@.service": {
                    "name": "systemd-fsck@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "systemd-fsck@dev-disk-by\\x2duuid-99851642\\x2d260f\\x2d4d7e\\x2d83dd\\x2d7cc990d49126.service": {
                    "name": "systemd-fsck@dev-disk-by\\x2duuid-99851642\\x2d260f\\x2d4d7e\\x2d83dd\\x2d7cc990d49126.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "systemd-halt.service": {
                    "name": "systemd-halt.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-hibernate-resume@.service": {
                    "name": "systemd-hibernate-resume@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "systemd-hibernate.service": {
                    "name": "systemd-hibernate.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-hostnamed.service": {
                    "name": "systemd-hostnamed.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-hwdb-update.service": {
                    "name": "systemd-hwdb-update.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-hybrid-sleep.service": {
                    "name": "systemd-hybrid-sleep.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-initctl.service": {
                    "name": "systemd-initctl.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-journal-catalog-update.service": {
                    "name": "systemd-journal-catalog-update.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-journal-flush.service": {
                    "name": "systemd-journal-flush.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-journald.service": {
                    "name": "systemd-journald.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "static"
                },
                "systemd-kexec.service": {
                    "name": "systemd-kexec.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-localed.service": {
                    "name": "systemd-localed.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-logind.service": {
                    "name": "systemd-logind.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "static"
                },
                "systemd-machine-id-commit.service": {
                    "name": "systemd-machine-id-commit.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-modules-load.service": {
                    "name": "systemd-modules-load.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-portabled.service": {
                    "name": "systemd-portabled.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-poweroff.service": {
                    "name": "systemd-poweroff.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-quotacheck.service": {
                    "name": "systemd-quotacheck.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-random-seed.service": {
                    "name": "systemd-random-seed.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-reboot.service": {
                    "name": "systemd-reboot.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-remount-fs.service": {
                    "name": "systemd-remount-fs.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-resolved.service": {
                    "name": "systemd-resolved.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "systemd-rfkill.service": {
                    "name": "systemd-rfkill.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-suspend-then-hibernate.service": {
                    "name": "systemd-suspend-then-hibernate.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-suspend.service": {
                    "name": "systemd-suspend.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-sysctl.service": {
                    "name": "systemd-sysctl.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-sysusers.service": {
                    "name": "systemd-sysusers.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-timedated.service": {
                    "name": "systemd-timedated.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "masked"
                },
                "systemd-tmpfiles-clean.service": {
                    "name": "systemd-tmpfiles-clean.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-tmpfiles-setup-dev.service": {
                    "name": "systemd-tmpfiles-setup-dev.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-tmpfiles-setup.service": {
                    "name": "systemd-tmpfiles-setup.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-udev-settle.service": {
                    "name": "systemd-udev-settle.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "systemd-udev-trigger.service": {
                    "name": "systemd-udev-trigger.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-udevd.service": {
                    "name": "systemd-udevd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "static"
                },
                "systemd-update-done.service": {
                    "name": "systemd-update-done.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-update-utmp-runlevel.service": {
                    "name": "systemd-update-utmp-runlevel.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-update-utmp.service": {
                    "name": "systemd-update-utmp.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-user-sessions.service": {
                    "name": "systemd-user-sessions.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-vconsole-setup.service": {
                    "name": "systemd-vconsole-setup.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "systemd-volatile-root.service": {
                    "name": "systemd-volatile-root.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "static"
                },
                "tcsd.service": {
                    "name": "tcsd.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "disabled"
                },
                "teamd@.service": {
                    "name": "teamd@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "timedatex.service": {
                    "name": "timedatex.service",
                    "source": "systemd",
                    "state": "inactive",
                    "status": "enabled"
                },
                "tuned.service": {
                    "name": "tuned.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "unbound-anchor.service": {
                    "name": "unbound-anchor.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "static"
                },
                "user-runtime-dir@.service": {
                    "name": "user-runtime-dir@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "test5@test.service": {
                    "name": "test5@test.service",
                    "source": "systemd",
                    "state": "stopped",
                    "status": "unknown"
                },
                "user@.service": {
                    "name": "user@.service",
                    "source": "systemd",
                    "state": "unknown",
                    "status": "static"
                },
                "test6@test.service": {
                    "name": "test6@test.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "unknown"
                },
                "vgauthd.service": {
                    "name": "vgauthd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                },
                "vmtoolsd.service": {
                    "name": "vmtoolsd.service",
                    "source": "systemd",
                    "state": "running",
                    "status": "enabled"
                }
            },
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * discovered_interpreter_python: /usr/libexec/platform-python
>  * ## Services
>    * ### Networkmanager-Dispatcher.Service
>      * name: NetworkManager-dispatcher.service
>      * source: systemd
>      * state: inactive
>      * status: enabled
>    * ### Networkmanager-Wait-Online.Service
>      * name: NetworkManager-wait-online.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Networkmanager.Service
>      * name: NetworkManager.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Arp-Ethers.Service
>      * name: arp-ethers.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Atd.Service
>      * name: atd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Auditd.Service
>      * name: auditd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Autovt@.Service
>      * name: autovt@.service
>      * source: systemd
>      * state: unknown
>      * status: enabled
>    * ### Blk-Availability.Service
>      * name: blk-availability.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Chrony-Dnssrv@.Service
>      * name: chrony-dnssrv@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Chrony-Wait.Service
>      * name: chrony-wait.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Chronyd.Service
>      * name: chronyd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Console-Getty.Service
>      * name: console-getty.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Container-Getty@.Service
>      * name: container-getty@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Cpupower.Service
>      * name: cpupower.service
>      * source: systemd
>      * state: stopped
>      * status: disabled
>    * ### Crond.Service
>      * name: crond.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Dbus-Org.Fedoraproject.Firewalld1.Service
>      * name: dbus-org.fedoraproject.FirewallD1.service
>      * source: systemd
>      * state: active
>      * status: enabled
>    * ### Dbus-Org.Freedesktop.Hostname1.Service
>      * name: dbus-org.freedesktop.hostname1.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Dbus-Org.Freedesktop.Locale1.Service
>      * name: dbus-org.freedesktop.locale1.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Dbus-Org.Freedesktop.Login1.Service
>      * name: dbus-org.freedesktop.login1.service
>      * source: systemd
>      * state: active
>      * status: static
>    * ### Dbus-Org.Freedesktop.Nm-Dispatcher.Service
>      * name: dbus-org.freedesktop.nm-dispatcher.service
>      * source: systemd
>      * state: inactive
>      * status: enabled
>    * ### Dbus-Org.Freedesktop.Portable1.Service
>      * name: dbus-org.freedesktop.portable1.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Dbus-Org.Freedesktop.Timedate1.Service
>      * name: dbus-org.freedesktop.timedate1.service
>      * source: systemd
>      * state: inactive
>      * status: enabled
>    * ### Dbus.Service
>      * name: dbus.service
>      * source: systemd
>      * state: running
>      * status: static
>    * ### Debug-Shell.Service
>      * name: debug-shell.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Dm-Event.Service
>      * name: dm-event.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dnf-Makecache.Service
>      * name: dnf-makecache.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Cmdline.Service
>      * name: dracut-cmdline.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Initqueue.Service
>      * name: dracut-initqueue.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Mount.Service
>      * name: dracut-mount.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Pre-Mount.Service
>      * name: dracut-pre-mount.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Pre-Pivot.Service
>      * name: dracut-pre-pivot.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Pre-Trigger.Service
>      * name: dracut-pre-trigger.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Pre-Udev.Service
>      * name: dracut-pre-udev.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Dracut-Shutdown.Service
>      * name: dracut-shutdown.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Ebtables.Service
>      * name: ebtables.service
>      * source: systemd
>      * state: stopped
>      * status: disabled
>    * ### Emergency.Service
>      * name: emergency.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Firewalld.Service
>      * name: firewalld.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Fstrim.Service
>      * name: fstrim.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Getty@.Service
>      * name: getty@.service
>      * source: systemd
>      * state: unknown
>      * status: enabled
>    * ### test@test.service
>      * name: test@test.service
>      * source: systemd
>      * state: running
>      * status: unknown
>    * ### Grub-Boot-Indeterminate.Service
>      * name: grub-boot-indeterminate.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Halt-Local.Service
>      * name: halt-local.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Htcacheclean.Service
>      * name: htcacheclean.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Httpd.Service
>      * name: httpd.service
>      * source: systemd
>      * state: running
>      * status: disabled
>    * ### Httpd@.Service
>      * name: httpd@.service
>      * source: systemd
>      * state: unknown
>      * status: disabled
>    * ### Import-State.Service
>      * name: import-state.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Initrd-Cleanup.Service
>      * name: initrd-cleanup.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Initrd-Parse-Etc.Service
>      * name: initrd-parse-etc.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Initrd-Switch-Root.Service
>      * name: initrd-switch-root.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Initrd-Udevadm-Cleanup-Db.Service
>      * name: initrd-udevadm-cleanup-db.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Iprdump.Service
>      * name: iprdump.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Iprinit.Service
>      * name: iprinit.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Iprupdate.Service
>      * name: iprupdate.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Irqbalance.Service
>      * name: irqbalance.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Kdump.Service
>      * name: kdump.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Kmod-Static-Nodes.Service
>      * name: kmod-static-nodes.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Ldconfig.Service
>      * name: ldconfig.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Loadmodules.Service
>      * name: loadmodules.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Lvm2-Lvmpolld.Service
>      * name: lvm2-lvmpolld.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Lvm2-Monitor.Service
>      * name: lvm2-monitor.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Lvm2-Pvscan@.Service
>      * name: lvm2-pvscan@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Lvm2-Pvscan@8:2.Service
>      * name: lvm2-pvscan@8:2.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### Man-Db-Cache-Update.Service
>      * name: man-db-cache-update.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Messagebus.Service
>      * name: messagebus.service
>      * source: systemd
>      * state: active
>      * status: static
>    * ### Microcode.Service
>      * name: microcode.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Nftables.Service
>      * name: nftables.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Nis-Domainname.Service
>      * name: nis-domainname.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Plymouth-Halt.Service
>      * name: plymouth-halt.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Plymouth-Kexec.Service
>      * name: plymouth-kexec.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Plymouth-Poweroff.Service
>      * name: plymouth-poweroff.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Plymouth-Quit-Wait.Service
>      * name: plymouth-quit-wait.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Plymouth-Quit.Service
>      * name: plymouth-quit.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Plymouth-Read-Write.Service
>      * name: plymouth-read-write.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Plymouth-Reboot.Service
>      * name: plymouth-reboot.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Plymouth-Start.Service
>      * name: plymouth-start.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Plymouth-Switch-Root.Service
>      * name: plymouth-switch-root.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Polkit.Service
>      * name: polkit.service
>      * source: systemd
>      * state: running
>      * status: static
>    * ### Quotaon.Service
>      * name: quotaon.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Rc-Local.Service
>      * name: rc-local.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Rdisc.Service
>      * name: rdisc.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Rescue.Service
>      * name: rescue.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Rngd-Wake-Threshold.Service
>      * name: rngd-wake-threshold.service
>      * source: systemd
>      * state: stopped
>      * status: disabled
>    * ### Rngd.Service
>      * name: rngd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Rsyslog.Service
>      * name: rsyslog.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Selinux-Autorelabel-Mark.Service
>      * name: selinux-autorelabel-mark.service
>      * source: systemd
>      * state: stopped
>      * status: enabled
>    * ### Selinux-Autorelabel.Service
>      * name: selinux-autorelabel.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Serial-Getty@.Service
>      * name: serial-getty@.service
>      * source: systemd
>      * state: unknown
>      * status: disabled
>    * ### Sshd-Keygen@.Service
>      * name: sshd-keygen@.service
>      * source: systemd
>      * state: unknown
>      * status: disabled
>    * ### test1@test.service
>      * name: test1@test.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### test2@test.service
>      * name: test2@test.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### test3@test.service
>      * name: test3@test.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### Sshd.Service
>      * name: sshd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Sshd@.Service
>      * name: sshd@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Sssd-Autofs.Service
>      * name: sssd-autofs.service
>      * source: systemd
>      * state: inactive
>      * status: indirect
>    * ### Sssd-Kcm.Service
>      * name: sssd-kcm.service
>      * source: systemd
>      * state: stopped
>      * status: indirect
>    * ### Sssd-Nss.Service
>      * name: sssd-nss.service
>      * source: systemd
>      * state: inactive
>      * status: indirect
>    * ### Sssd-Pac.Service
>      * name: sssd-pac.service
>      * source: systemd
>      * state: inactive
>      * status: indirect
>    * ### Sssd-Pam.Service
>      * name: sssd-pam.service
>      * source: systemd
>      * state: inactive
>      * status: indirect
>    * ### Sssd-Ssh.Service
>      * name: sssd-ssh.service
>      * source: systemd
>      * state: inactive
>      * status: indirect
>    * ### Sssd-Sudo.Service
>      * name: sssd-sudo.service
>      * source: systemd
>      * state: inactive
>      * status: indirect
>    * ### Sssd.Service
>      * name: sssd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Syslog.Service
>      * name: syslog.service
>      * source: systemd
>      * state: active
>      * status: enabled
>    * ### System-Update-Cleanup.Service
>      * name: system-update-cleanup.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Ask-Password-Console.Service
>      * name: systemd-ask-password-console.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Ask-Password-Plymouth.Service
>      * name: systemd-ask-password-plymouth.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Ask-Password-Wall.Service
>      * name: systemd-ask-password-wall.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Backlight@.Service
>      * name: systemd-backlight@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Systemd-Binfmt.Service
>      * name: systemd-binfmt.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Coredump@.Service
>      * name: systemd-coredump@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### test4@test.service
>      * name: test4@test.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### Systemd-Exit.Service
>      * name: systemd-exit.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Firstboot.Service
>      * name: systemd-firstboot.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Fsck-Root.Service
>      * name: systemd-fsck-root.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Fsck@.Service
>      * name: systemd-fsck@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Systemd-Fsck@Dev-Disk-By\X2Duuid-99851642\X2D260F\X2D4D7E\X2D83Dd\X2D7Cc990D49126.Service
>      * name: systemd-fsck@dev-disk-by\x2duuid-99851642\x2d260f\x2d4d7e\x2d83dd\x2d7cc990d49126.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### Systemd-Halt.Service
>      * name: systemd-halt.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Hibernate-Resume@.Service
>      * name: systemd-hibernate-resume@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Systemd-Hibernate.Service
>      * name: systemd-hibernate.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Hostnamed.Service
>      * name: systemd-hostnamed.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Hwdb-Update.Service
>      * name: systemd-hwdb-update.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Hybrid-Sleep.Service
>      * name: systemd-hybrid-sleep.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Initctl.Service
>      * name: systemd-initctl.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Journal-Catalog-Update.Service
>      * name: systemd-journal-catalog-update.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Journal-Flush.Service
>      * name: systemd-journal-flush.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Journald.Service
>      * name: systemd-journald.service
>      * source: systemd
>      * state: running
>      * status: static
>    * ### Systemd-Kexec.Service
>      * name: systemd-kexec.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Localed.Service
>      * name: systemd-localed.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Logind.Service
>      * name: systemd-logind.service
>      * source: systemd
>      * state: running
>      * status: static
>    * ### Systemd-Machine-Id-Commit.Service
>      * name: systemd-machine-id-commit.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Modules-Load.Service
>      * name: systemd-modules-load.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Portabled.Service
>      * name: systemd-portabled.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Poweroff.Service
>      * name: systemd-poweroff.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Quotacheck.Service
>      * name: systemd-quotacheck.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Random-Seed.Service
>      * name: systemd-random-seed.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Reboot.Service
>      * name: systemd-reboot.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Remount-Fs.Service
>      * name: systemd-remount-fs.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Resolved.Service
>      * name: systemd-resolved.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Systemd-Rfkill.Service
>      * name: systemd-rfkill.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Suspend-Then-Hibernate.Service
>      * name: systemd-suspend-then-hibernate.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Suspend.Service
>      * name: systemd-suspend.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Sysctl.Service
>      * name: systemd-sysctl.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Sysusers.Service
>      * name: systemd-sysusers.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Timedated.Service
>      * name: systemd-timedated.service
>      * source: systemd
>      * state: inactive
>      * status: masked
>    * ### Systemd-Tmpfiles-Clean.Service
>      * name: systemd-tmpfiles-clean.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Tmpfiles-Setup-Dev.Service
>      * name: systemd-tmpfiles-setup-dev.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Tmpfiles-Setup.Service
>      * name: systemd-tmpfiles-setup.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Udev-Settle.Service
>      * name: systemd-udev-settle.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Systemd-Udev-Trigger.Service
>      * name: systemd-udev-trigger.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Udevd.Service
>      * name: systemd-udevd.service
>      * source: systemd
>      * state: running
>      * status: static
>    * ### Systemd-Update-Done.Service
>      * name: systemd-update-done.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Update-Utmp-Runlevel.Service
>      * name: systemd-update-utmp-runlevel.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Update-Utmp.Service
>      * name: systemd-update-utmp.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-User-Sessions.Service
>      * name: systemd-user-sessions.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Vconsole-Setup.Service
>      * name: systemd-vconsole-setup.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### Systemd-Volatile-Root.Service
>      * name: systemd-volatile-root.service
>      * source: systemd
>      * state: inactive
>      * status: static
>    * ### Tcsd.Service
>      * name: tcsd.service
>      * source: systemd
>      * state: inactive
>      * status: disabled
>    * ### Teamd@.Service
>      * name: teamd@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### Timedatex.Service
>      * name: timedatex.service
>      * source: systemd
>      * state: inactive
>      * status: enabled
>    * ### Tuned.Service
>      * name: tuned.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Unbound-Anchor.Service
>      * name: unbound-anchor.service
>      * source: systemd
>      * state: stopped
>      * status: static
>    * ### User-Runtime-Dir@.Service
>      * name: user-runtime-dir@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### test5@test.service
>      * name: test5@test.service
>      * source: systemd
>      * state: stopped
>      * status: unknown
>    * ### User@.Service
>      * name: user@.service
>      * source: systemd
>      * state: unknown
>      * status: static
>    * ### test6@test.service
>      * name: test6@test.service
>      * source: systemd
>      * state: running
>      * status: unknown
>    * ### Vgauthd.Service
>      * name: vgauthd.service
>      * source: systemd
>      * state: running
>      * status: enabled
>    * ### Vmtoolsd.Service
>      * name: vmtoolsd.service
>      * source: systemd
>      * state: running
>      * status: enabled


### linux-setup
***
Gathers facts about remote hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/setup_module.html


#### Base Command

`linux-setup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| gather_subset | If supplied, restrict the additional facts collected to the given subset. Possible values: `all`, `min`, `hardware`, `network`, `virtual`, `ohai`, and `facter`. Can specify a list of values to specify a larger subset. Values can also be used with an initial `!` to specify that that specific subset should not be collected.  For instance: `!hardware,!network,!virtual,!ohai,!facter`. If `!all` is specified then only the min subset is collected. To avoid collecting even the min subset, specify `!all,!min`. To collect only specific facts, use `!all,!min`, and specify the particular fact subsets. Use the filter parameter if you do not want to display some collected facts. Default is all. | Optional | 
| gather_timeout | Set the default timeout in seconds for individual fact gathering. Default is 10. | Optional | 
| filter | If supplied, only return facts that match this shell-style (fnmatch) wildcard. Default is *. | Optional | 
| fact_path | Path used for local ansible facts (`*.fact`) - files in this dir will be run (if executable) and their results be added to `local` facts if a file is not executable it is read. Check notes for Windows options. (from 2.1 on) File/results format can be JSON or INI-format. The default `fact_path` can be specified in `ansible.cfg` for when setup is automatically called as part of `gather_facts`. Default is /etc/ansible/facts.d. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-sysctl
***
Manage entries in sysctl.conf.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/sysctl_module.html


#### Base Command

`linux-sysctl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The dot-separated path (aka `key`) specifying the sysctl variable. | Required | 
| value | Desired value of the sysctl key. | Optional | 
| state | Whether the entry should be present or absent in the sysctl file. Possible values are: present, absent. Default is present. | Optional | 
| ignoreerrors | Use this option to ignore errors about unknown keys. Default is no. | Optional | 
| reload | If `yes`, performs a `/sbin/sysctl -p` if the `sysctl_file` is updated. If `no`, does not reload `sysctl` even if the `sysctl_file` is updated. Default is yes. | Optional | 
| sysctl_file | Specifies the absolute path to `sysctl.conf`, if not `/etc/sysctl.conf`. Default is /etc/sysctl.conf. | Optional | 
| sysctl_set | Verify token value with the sysctl command and set with -w if necessary. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-sysctl host="123.123.123.123" name="vm.swappiness" value="5" state="present" ```

#### Context Example
```json
{
    "Linux": {
        "Sysctl": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-systemd
***
Manage services
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/systemd_module.html


#### Base Command

`linux-systemd`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the service. This parameter takes the name of exactly one service to work with.<br/>When using in a chroot environment you always need to specify the full name i.e. (crond.service). | Optional | 
| state | `started`/`stopped` are idempotent actions that will not run commands unless necessary. `restarted` will always bounce the service. `reloaded` will always reload. Possible values are: reloaded, restarted, started, stopped. | Optional | 
| enabled | Whether the service should start on boot. `At least one of state and enabled are required.`. | Optional | 
| force | Whether to override existing symlinks. | Optional | 
| masked | Whether the unit should be masked or not, a masked unit is impossible to start. | Optional | 
| daemon_reload | Run daemon-reload before doing any other operations, to make sure systemd has read any changes.<br/>When set to `yes`, runs daemon-reload even if the module does not start or stop anything. Possible values are: Yes, No. Default is No. | Optional | 
| daemon_reexec | Run daemon_reexec command before doing any other operations, the systemd manager will serialize the manager state. Possible values are: Yes, No. Default is No. | Optional | 
| user | (deprecated) run ``systemctl`` talking to the service manager of the calling user, rather than the service manager of the system.<br/>This option is deprecated and will eventually be removed in 2.11. The ``scope`` option should be used instead. Possible values are: Yes, No. Default is No. | Optional | 
| scope | run systemctl within a given service manager scope, either as the default system scope (system), the current user's scope (user), or the scope of all users (global).<br/>For systemd to work with 'user', the executing user must have its own instance of dbus started (systemd requirement). The user dbus process is normally started during normal login, but not during the run of Ansible tasks. Otherwise you will probably get a 'Failed to connect to bus: no such file or directory' error. Possible values are: system, user, global. | Optional | 
| no_block | Do not synchronously wait for the requested operation to finish. Enqueued job will continue without Ansible blocking on its completion. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Systemd.status | unknown | A dictionary with the key=value pairs returned from \`systemctl show\` | 


#### Command Example
```!linux-systemd host="123.123.123.123" state="started" name="httpd" ```

#### Context Example
```json
{
    "Linux": {
        "Systemd": {
            "changed": false,
            "host": "123.123.123.123",
            "name": "httpd",
            "state": "started",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * name: httpd
>  * state: started
>  * ## Status
>    * ActiveEnterTimestamp: Thu 2021-07-08 14:12:41 JST
>    * ActiveEnterTimestampMonotonic: 331222117201
>    * ActiveExitTimestampMonotonic: 0
>    * ActiveState: active
>    * After: system.slice basic.target systemd-journald.socket systemd-tmpfiles-setup.service -.mount nss-lookup.target remote-fs.target httpd-init.service sysinit.target network.target tmp.mount
>    * AllowIsolate: no
>    * AllowedCPUs: 
>    * AllowedMemoryNodes: 
>    * AmbientCapabilities: 
>    * AssertResult: yes
>    * AssertTimestamp: Thu 2021-07-08 14:12:41 JST
>    * AssertTimestampMonotonic: 331221986103
>    * Before: shutdown.target
>    * BlockIOAccounting: no
>    * BlockIOWeight: [not set]
>    * CPUAccounting: no
>    * CPUAffinity: 
>    * CPUQuotaPerSecUSec: infinity
>    * CPUSchedulingPolicy: 0
>    * CPUSchedulingPriority: 0
>    * CPUSchedulingResetOnFork: no
>    * CPUShares: [not set]
>    * CPUUsageNSec: [not set]
>    * CPUWeight: [not set]
>    * CacheDirectoryMode: 0755
>    * CanIsolate: no
>    * CanReload: yes
>    * CanStart: yes
>    * CanStop: yes
>    * CapabilityBoundingSet: cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend
>    * CollectMode: inactive
>    * ConditionResult: yes
>    * ConditionTimestamp: Thu 2021-07-08 14:12:41 JST
>    * ConditionTimestampMonotonic: 331221986102
>    * ConfigurationDirectoryMode: 0755
>    * Conflicts: shutdown.target
>    * ControlGroup: /system.slice/httpd.service
>    * ControlPID: 0
>    * DefaultDependencies: yes
>    * Delegate: no
>    * Description: The Apache HTTP Server
>    * DevicePolicy: auto
>    * Documentation: man:httpd.service(8)
>    * DynamicUser: no
>    * EffectiveCPUs: 
>    * EffectiveMemoryNodes: 
>    * Environment: LANG=C
>    * ExecMainCode: 0
>    * ExecMainExitTimestampMonotonic: 0
>    * ExecMainPID: 7626
>    * ExecMainStartTimestamp: Thu 2021-07-08 14:12:41 JST
>    * ExecMainStartTimestampMonotonic: 331221988640
>    * ExecMainStatus: 0
>    * ExecReload: { path=/usr/sbin/httpd ; argv[]=/usr/sbin/httpd $OPTIONS -k graceful ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
>    * ExecStart: { path=/usr/sbin/httpd ; argv[]=/usr/sbin/httpd $OPTIONS -DFOREGROUND ; ignore_errors=no ; start_time=[Thu 2021-07-08 14:12:41 JST] ; stop_time=[n/a] ; pid=7626 ; code=(null) ; status=0/0 }
>    * FailureAction: none
>    * FileDescriptorStoreMax: 0
>    * FragmentPath: /usr/lib/systemd/system/httpd.service
>    * GID: [not set]
>    * GuessMainPID: yes
>    * IOAccounting: no
>    * IOSchedulingClass: 0
>    * IOSchedulingPriority: 0
>    * IOWeight: [not set]
>    * IPAccounting: no
>    * IPEgressBytes: 18446744073709551615
>    * IPEgressPackets: 18446744073709551615
>    * IPIngressBytes: 18446744073709551615
>    * IPIngressPackets: 18446744073709551615
>    * Id: httpd.service
>    * IgnoreOnIsolate: no
>    * IgnoreSIGPIPE: yes
>    * InactiveEnterTimestampMonotonic: 0
>    * InactiveExitTimestamp: Thu 2021-07-08 14:12:41 JST
>    * InactiveExitTimestampMonotonic: 331221988825
>    * InvocationID: 7bb9f1e196514d5f87dfb3602a1c9e32
>    * JobRunningTimeoutUSec: infinity
>    * JobTimeoutAction: none
>    * JobTimeoutUSec: infinity
>    * KeyringMode: private
>    * KillMode: mixed
>    * KillSignal: 28
>    * LimitAS: infinity
>    * LimitASSoft: infinity
>    * LimitCORE: infinity
>    * LimitCORESoft: infinity
>    * LimitCPU: infinity
>    * LimitCPUSoft: infinity
>    * LimitDATA: infinity
>    * LimitDATASoft: infinity
>    * LimitFSIZE: infinity
>    * LimitFSIZESoft: infinity
>    * LimitLOCKS: infinity
>    * LimitLOCKSSoft: infinity
>    * LimitMEMLOCK: 65536
>    * LimitMEMLOCKSoft: 65536
>    * LimitMSGQUEUE: 819200
>    * LimitMSGQUEUESoft: 819200
>    * LimitNICE: 0
>    * LimitNICESoft: 0
>    * LimitNOFILE: 262144
>    * LimitNOFILESoft: 1024
>    * LimitNPROC: 7805
>    * LimitNPROCSoft: 7805
>    * LimitRSS: infinity
>    * LimitRSSSoft: infinity
>    * LimitRTPRIO: 0
>    * LimitRTPRIOSoft: 0
>    * LimitRTTIME: infinity
>    * LimitRTTIMESoft: infinity
>    * LimitSIGPENDING: 7805
>    * LimitSIGPENDINGSoft: 7805
>    * LimitSTACK: infinity
>    * LimitSTACKSoft: 8388608
>    * LoadState: loaded
>    * LockPersonality: no
>    * LogLevelMax: -1
>    * LogRateLimitBurst: 0
>    * LogRateLimitIntervalUSec: 0
>    * LogsDirectoryMode: 0755
>    * MainPID: 7626
>    * MemoryAccounting: yes
>    * MemoryCurrent: 30425088
>    * MemoryDenyWriteExecute: no
>    * MemoryHigh: infinity
>    * MemoryLimit: infinity
>    * MemoryLow: 0
>    * MemoryMax: infinity
>    * MemorySwapMax: infinity
>    * MountAPIVFS: no
>    * MountFlags: 
>    * NFileDescriptorStore: 0
>    * NRestarts: 0
>    * NUMAMask: 
>    * NUMAPolicy: n/a
>    * Names: httpd.service
>    * NeedDaemonReload: no
>    * Nice: 0
>    * NoNewPrivileges: no
>    * NonBlocking: no
>    * NotifyAccess: main
>    * OOMScoreAdjust: 0
>    * OnFailureJobMode: replace
>    * PermissionsStartOnly: no
>    * Perpetual: no
>    * PrivateDevices: no
>    * PrivateMounts: no
>    * PrivateNetwork: no
>    * PrivateTmp: yes
>    * PrivateUsers: no
>    * ProtectControlGroups: no
>    * ProtectHome: no
>    * ProtectKernelModules: no
>    * ProtectKernelTunables: no
>    * ProtectSystem: no
>    * RefuseManualStart: no
>    * RefuseManualStop: no
>    * RemainAfterExit: no
>    * RemoveIPC: no
>    * Requires: system.slice sysinit.target -.mount
>    * RequiresMountsFor: /var/tmp
>    * Restart: no
>    * RestartUSec: 100ms
>    * RestrictNamespaces: no
>    * RestrictRealtime: no
>    * RestrictSUIDSGID: no
>    * Result: success
>    * RootDirectoryStartOnly: no
>    * RuntimeDirectoryMode: 0755
>    * RuntimeDirectoryPreserve: no
>    * RuntimeMaxUSec: infinity
>    * SameProcessGroup: no
>    * SecureBits: 0
>    * SendSIGHUP: no
>    * SendSIGKILL: yes
>    * Slice: system.slice
>    * StandardError: inherit
>    * StandardInput: null
>    * StandardInputData: 
>    * StandardOutput: journal
>    * StartLimitAction: none
>    * StartLimitBurst: 5
>    * StartLimitIntervalUSec: 10s
>    * StartupBlockIOWeight: [not set]
>    * StartupCPUShares: [not set]
>    * StartupCPUWeight: [not set]
>    * StartupIOWeight: [not set]
>    * StateChangeTimestamp: Thu 2021-07-08 14:12:41 JST
>    * StateChangeTimestampMonotonic: 331222165344
>    * StateDirectoryMode: 0755
>    * StatusErrno: 0
>    * StatusText: Running, listening on: port 80
>    * StopWhenUnneeded: no
>    * SubState: running
>    * SuccessAction: none
>    * SyslogFacility: 3
>    * SyslogLevel: 6
>    * SyslogLevelPrefix: yes
>    * SyslogPriority: 30
>    * SystemCallErrorNumber: 0
>    * TTYReset: no
>    * TTYVHangup: no
>    * TTYVTDisallocate: no
>    * TasksAccounting: yes
>    * TasksCurrent: 213
>    * TasksMax: 12488
>    * TimeoutStartUSec: 1min 30s
>    * TimeoutStopUSec: 1min 30s
>    * TimerSlackNSec: 50000
>    * Transient: no
>    * Type: notify
>    * UID: [not set]
>    * UMask: 0022
>    * UnitFilePreset: disabled
>    * UnitFileState: disabled
>    * UtmpMode: init
>    * Wants: httpd-init.service
>    * WatchdogTimestamp: Thu 2021-07-08 14:12:41 JST
>    * WatchdogTimestampMonotonic: 331222117198
>    * WatchdogUSec: 0


### linux-sysvinit
***
Manage SysV services.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/sysvinit_module.html


#### Base Command

`linux-sysvinit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the service. | Required | 
| state | `started`/`stopped` are idempotent actions that will not run commands unless necessary. Not all init scripts support `restarted` nor `reloaded` natively, so these will both trigger a stop and start as needed. Possible values are: started, stopped, restarted, reloaded. | Optional | 
| enabled | Whether the service should start on boot. `At least one of state and enabled are required.`. | Optional | 
| sleep | If the service is being `restarted` or `reloaded` then sleep this many seconds between the stop and start command. This helps to workaround badly behaving services. Default is 1. | Optional | 
| pattern | A substring to look for as would be found in the output of the `ps` command as a stand-in for a status result.<br/>If the string is found, the service will be assumed to be running.<br/>This option is mainly for use with init scripts that don't support the 'status' option. | Optional | 
| runlevels | The runlevels this script should be enabled/disabled from.<br/>Use this to override the defaults set by the package or init script itself. | Optional | 
| arguments | Additional arguments provided on the command line that some init scripts accept. | Optional | 
| daemonize | Have the module daemonize as the service itself might not do so properly.<br/>This is useful with badly written init scripts or daemons, which commonly manifests as the task hanging as it is still holding the tty or the service dying when the task is over as the connection closes the session. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Sysvinit.results | unknown | results from actions taken | 



### linux-timezone
***
Configure timezone setting
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/timezone_module.html


#### Base Command

`linux-timezone`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the timezone for the system clock.<br/>Default is to keep current setting.<br/>`At least one of name and hwclock are required.`. | Optional | 
| hwclock | Whether the hardware clock is in UTC or in local timezone.<br/>Default is to keep current setting.<br/>Note that this option is recommended not to change and may fail to configure, especially on virtual environments such as AWS.<br/>`At least one of name and hwclock are required.`<br/>`Only used on Linux.`. Possible values are: local, UTC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Timezone.diff | unknown | The differences about the given arguments. | 


#### Command Example
```!linux-timezone host="123.123.123.123" name="Asia/Tokyo" ```

#### Context Example
```json
{
    "Linux": {
        "Timezone": {
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False


### linux-ufw
***
Manage firewall with UFW
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ufw_module.html


#### Base Command

`linux-ufw`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | `enabled` reloads firewall and enables firewall on boot.<br/>`disabled` unloads firewall and disables firewall on boot.<br/>`reloaded` reloads firewall.<br/>`reset` disables and resets firewall to installation defaults. Possible values are: disabled, enabled, reloaded, reset. | Optional | 
| default | Change the default policy for incoming or outgoing traffic. Possible values are: allow, deny, reject. | Optional | 
| direction | Select direction for a rule or default policy command. Possible values are: in, incoming, out, outgoing, routed. | Optional | 
| logging | Toggles logging. Logged packets use the LOG_KERN syslog facility. Possible values are: on, off, low, medium, high, full. | Optional | 
| insert | Insert the corresponding rule as rule number NUM.<br/>Note that ufw numbers rules starting with 1. | Optional | 
| insert_relative_to | Allows to interpret the index in `insert` relative to a position.<br/>`zero` interprets the rule number as an absolute index (i.e. 1 is the first rule).<br/>`first-ipv4` interprets the rule number relative to the index of the first IPv4 rule, or relative to the position where the first IPv4 rule would be if there is currently none.<br/>`last-ipv4` interprets the rule number relative to the index of the last IPv4 rule, or relative to the position where the last IPv4 rule would be if there is currently none.<br/>`first-ipv6` interprets the rule number relative to the index of the first IPv6 rule, or relative to the position where the first IPv6 rule would be if there is currently none.<br/>`last-ipv6` interprets the rule number relative to the index of the last IPv6 rule, or relative to the position where the last IPv6 rule would be if there is currently none. Possible values are: first-ipv4, first-ipv6, last-ipv4, last-ipv6, zero. Default is zero. | Optional | 
| rule | Add firewall rule. Possible values are: allow, deny, limit, reject. | Optional | 
| log | Log new connections matched to this rule. | Optional | 
| from_ip | Source IP address. Default is any. | Optional | 
| from_port | Source port. | Optional | 
| to_ip | Destination IP address. Default is any. | Optional | 
| to_port | Destination port. | Optional | 
| proto | TCP/IP protocol. Possible values are: any, tcp, udp, ipv6, esp, ah, gre, igmp. | Optional | 
| name | Use profile located in `/etc/ufw/applications.d`. | Optional | 
| delete | Delete rule. | Optional | 
| interface | Specify interface for rule. | Optional | 
| route | Apply the rule to routed/forwarded packets. | Optional | 
| comment | Add a comment to the rule. Requires UFW version &gt;=0.35. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-user
***
Manage user accounts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/user_module.html


#### Base Command

`linux-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the user to create, remove or modify. | Required | 
| uid | Optionally sets the `UID` of the user. | Optional | 
| comment | Optionally sets the description (aka `GECOS`) of user account. | Optional | 
| hidden | macOS only, optionally hide the user from the login window and system preferences.<br/>The default will be `yes` if the `system` option is used. | Optional | 
| non_unique | Optionally when used with the -u option, this option allows to change the user ID to a non-unique value. Possible values are: Yes, No. Default is No. | Optional | 
| seuser | Optionally sets the seuser type (user_u) on selinux enabled systems. | Optional | 
| group | Optionally sets the user's primary group (takes a group name). | Optional | 
| groups | List of groups user will be added to. When set to an empty string `''`, the user is removed from all groups except the primary group.<br/>Before Ansible 2.3, the only input format allowed was a comma separated string.<br/>Mutually exclusive with `local`. | Optional | 
| append | If `yes`, add the user to the groups specified in `groups`.<br/>If `no`, user will only be added to the groups specified in `groups`, removing them from all other groups.<br/>Mutually exclusive with `local`. Possible values are: Yes, No. Default is No. | Optional | 
| shell | Optionally set the user's shell.<br/>On macOS, before Ansible 2.5, the default shell for non-system users was `/usr/bin/false`. Since Ansible 2.5, the default shell for non-system users on macOS is `/bin/bash`.<br/>On other operating systems, the default shell is determined by the underlying tool being used. See Notes for details. | Optional | 
| home | Optionally set the user's home directory. | Optional | 
| skeleton | Optionally set a home skeleton directory.<br/>Requires `create_home` option!. | Optional | 
| password | Optionally set the user's password to this crypted value.<br/>On macOS systems, this value has to be cleartext. Beware of security issues.<br/>To create a disabled account on Linux systems, set this to `'!'` or `'*'`.<br/>To create a disabled account on OpenBSD, set this to `'*************'`.<br/>See `https://docs.ansible.com/ansible/faq.html#how-do-i-generate-encrypted-passwords-for-the-user-module` for details on various ways to generate these password values. | Optional | 
| state | Whether the account should exist or not, taking action if the state is different from what is stated. Possible values are: absent, present. Default is present. | Optional | 
| create_home | Unless set to `no`, a home directory will be made for the user when the account is created or if the home directory does not exist.<br/>Changed from `createhome` to `create_home` in Ansible 2.5. Possible values are: Yes, No. Default is Yes. | Optional | 
| move_home | If set to `yes` when used with `home: `, attempt to move the user's old home directory to the specified directory if it isn't there already and the old home exists. Possible values are: Yes, No. Default is No. | Optional | 
| system | When creating an account `state=present`, setting this to `yes` makes the user a system account.<br/>This setting cannot be changed on existing users. Possible values are: Yes, No. Default is No. | Optional | 
| force | This only affects `state=absent`, it forces removal of the user and associated directories on supported platforms.<br/>The behavior is the same as `userdel --force`, check the man page for `userdel` on your system for details and support.<br/>When used with `generate_ssh_key=yes` this forces an existing key to be overwritten. Possible values are: Yes, No. Default is No. | Optional | 
| remove | This only affects `state=absent`, it attempts to remove directories associated with the user.<br/>The behavior is the same as `userdel --remove`, check the man page for details and support. Possible values are: Yes, No. Default is No. | Optional | 
| login_class | Optionally sets the user's login class, a feature of most BSD OSs. | Optional | 
| generate_ssh_key | Whether to generate a SSH key for the user in question.<br/>This will `not` overwrite an existing SSH key unless used with `force=yes`. Possible values are: Yes, No. Default is No. | Optional | 
| ssh_key_bits | Optionally specify number of bits in SSH key to create. Default is default set by ssh-keygen. | Optional | 
| ssh_key_type | Optionally specify the type of SSH key to generate.<br/>Available SSH key types will depend on implementation present on target host. Default is rsa. | Optional | 
| ssh_key_file | Optionally specify the SSH key filename.<br/>If this is a relative filename then it will be relative to the user's home directory.<br/>This parameter defaults to `.ssh/id_rsa`. | Optional | 
| ssh_key_comment | Optionally define the comment for the SSH key. Default is ansible-generated on $HOSTNAME. | Optional | 
| ssh_key_passphrase | Set a passphrase for the SSH key.<br/>If no passphrase is provided, the SSH key will default to having no passphrase. | Optional | 
| update_password | `always` will update passwords if they differ.<br/>`on_create` will only set the password for newly created users. Possible values are: always, on_create. Default is always. | Optional | 
| expires | An expiry time for the user in epoch, it will be ignored on platforms that do not support this.<br/>Currently supported on GNU/Linux, FreeBSD, and DragonFlyBSD.<br/>Since Ansible 2.6 you can remove the expiry time specify a negative value. Currently supported on GNU/Linux and FreeBSD. | Optional | 
| password_lock | Lock the password (`usermod -L`, `usermod -U`, `pw lock`).<br/>Implementation differs by platform. This option does not always mean the user cannot login using other methods.<br/>This option does not disable the user, only lock the password.<br/>This must be set to `False` in order to unlock a currently locked password. The absence of this parameter will not unlock a password.<br/>Currently supported on Linux, FreeBSD, DragonFlyBSD, NetBSD, OpenBSD. | Optional | 
| local | Forces the use of "local" command alternatives on platforms that implement it.<br/>This is useful in environments that use centralized authentification when you want to manipulate the local users (i.e. it uses `luseradd` instead of `useradd`).<br/>This will check `/etc/passwd` for an existing account before invoking commands. If the local account database exists somewhere other than `/etc/passwd`, this setting will not work properly.<br/>This requires that the above commands as well as `/etc/passwd` must exist on the target host, otherwise it will be a fatal error.<br/>Mutually exclusive with `groups` and `append`. Possible values are: Yes, No. Default is No. | Optional | 
| profile | Sets the profile of the user.<br/>Does nothing when used with other platforms.<br/>Can set multiple profiles using comma separation.<br/>To delete all the profiles, use `profile=''`.<br/>Currently supported on Illumos/Solaris. | Optional | 
| authorization | Sets the authorization of the user.<br/>Does nothing when used with other platforms.<br/>Can set multiple authorizations using comma separation.<br/>To delete all authorizations, use `authorization=''`.<br/>Currently supported on Illumos/Solaris. | Optional | 
| role | Sets the role of the user.<br/>Does nothing when used with other platforms.<br/>Can set multiple roles using comma separation.<br/>To delete all roles, use `role=''`.<br/>Currently supported on Illumos/Solaris. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.User.append | boolean | Whether or not to append the user to groups | 
| Linux.User.comment | string | Comment section from passwd file, usually the user name | 
| Linux.User.create_home | boolean | Whether or not to create the home directory | 
| Linux.User.force | boolean | Whether or not a user account was forcibly deleted | 
| Linux.User.group | number | Primary user group ID | 
| Linux.User.groups | string | List of groups of which the user is a member | 
| Linux.User.home | string | Path to user's home directory | 
| Linux.User.move_home | boolean | Whether or not to move an existing home directory | 
| Linux.User.name | string | User account name | 
| Linux.User.password | string | Masked value of the password | 
| Linux.User.remove | boolean | Whether or not to remove the user account | 
| Linux.User.shell | string | User login shell | 
| Linux.User.ssh_fingerprint | string | Fingerprint of generated SSH key | 
| Linux.User.ssh_key_file | string | Path to generated SSH private key file | 
| Linux.User.ssh_public_key | string | Generated SSH public key file | 
| Linux.User.stderr | string | Standard error from running commands | 
| Linux.User.stdout | string | Standard output from running commands | 
| Linux.User.system | boolean | Whether or not the account is a system account | 
| Linux.User.uid | number | User ID of the user account | 



### linux-xfs-quota
***
Manage quotas on XFS filesystems
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/xfs_quota_module.html


#### Base Command

`linux-xfs-quota`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| type | The XFS quota type. Possible values are: user, group, project. | Required | 
| name | The name of the user, group or project to apply the quota to, if other than default. | Optional | 
| mountpoint | The mount point on which to apply the quotas. | Required | 
| bhard | Hard blocks quota limit.<br/>This argument supports human readable sizes. | Optional | 
| bsoft | Soft blocks quota limit.<br/>This argument supports human readable sizes. | Optional | 
| ihard | Hard inodes quota limit. | Optional | 
| isoft | Soft inodes quota limit. | Optional | 
| rtbhard | Hard realtime blocks quota limit.<br/>This argument supports human readable sizes. | Optional | 
| rtbsoft | Soft realtime blocks quota limit.<br/>This argument supports human readable sizes. | Optional | 
| state | Whether to apply the limits or remove them.<br/>When removing limit, they are set to 0, and not quite removed. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.XfsQuota.bhard | number | the current bhard setting in bytes | 
| Linux.XfsQuota.bsoft | number | the current bsoft setting in bytes | 
| Linux.XfsQuota.ihard | number | the current ihard setting in bytes | 
| Linux.XfsQuota.isoft | number | the current isoft setting in bytes | 
| Linux.XfsQuota.rtbhard | number | the current rtbhard setting in bytes | 
| Linux.XfsQuota.rtbsoft | number | the current rtbsoft setting in bytes | 



### linux-htpasswd
***
manage user files for basic authentication
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/htpasswd_module.html


#### Base Command

`linux-htpasswd`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the file that contains the usernames and passwords. | Required | 
| name | User name to add or remove. | Required | 
| password | Password associated with user.<br/>Must be specified if user does not exist yet. | Optional | 
| crypt_scheme | Encryption scheme to be used.  As well as the four choices listed here, you can also use any other hash supported by passlib, such as md5_crypt and sha256_crypt, which are linux passwd hashes.  If you do so the password file will not be compatible with Apache or Nginx. Possible values are: apr_md5_crypt, des_crypt, ldap_sha1, plaintext. Default is apr_md5_crypt. | Optional | 
| state | Whether the user entry should be present or not. Possible values are: present, absent. Default is present. | Optional | 
| create | Used with `state=present`. If specified, the file will be created if it does not already exist. If set to "no", will fail if the file does not exist. Default is yes. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-supervisorctl
***
Manage the state of a program or group of programs running via supervisord
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/supervisorctl_module.html


#### Base Command

`linux-supervisorctl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the supervisord program or group to manage.<br/>The name will be taken as group name when it ends with a colon `:`<br/>Group support is only available in Ansible version 1.6 or later. | Required | 
| config | The supervisor configuration file path. | Optional | 
| server_url | URL on which supervisord server is listening. | Optional | 
| username | username to use for authentication. | Optional | 
| password | password to use for authentication. | Optional | 
| state | The desired state of program/group. Possible values are: present, started, stopped, restarted, absent, signalled. | Required | 
| signal | The signal to send to the program/group, when combined with the 'signalled' state. Required when l(state=signalled). | Optional | 
| supervisorctl_path | path to supervisorctl executable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-openssh-cert
***
Generate OpenSSH host or user certificates.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssh_cert_module.html


#### Base Command

`linux-openssh-cert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the host or user certificate should exist or not, taking action if the state is different from what is stated. Possible values are: present, absent. Default is present. | Optional | 
| type | Whether the module should generate a host or a user certificate.<br/>Required if `state` is `present`. Possible values are: host, user. | Optional | 
| force | Should the certificate be regenerated even if it already exists and is valid. Possible values are: Yes, No. Default is No. | Optional | 
| path | Path of the file containing the certificate. | Required | 
| signing_key | The path to the private openssh key that is used for signing the public key in order to generate the certificate.<br/>Required if `state` is `present`. | Optional | 
| public_key | The path to the public key that will be signed with the signing key in order to generate the certificate.<br/>Required if `state` is `present`. | Optional | 
| valid_from | The point in time the certificate is valid from. Time can be specified either as relative time or as absolute timestamp. Time will always be interpreted as UTC. Valid formats are: `[+-]timespec \| YYYY-MM-DD \| YYYY-MM-DDTHH:MM:SS \| YYYY-MM-DD HH:MM:SS \| always` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`. Note that if using relative time this module is NOT idempotent.<br/>Required if `state` is `present`. | Optional | 
| valid_to | The point in time the certificate is valid to. Time can be specified either as relative time or as absolute timestamp. Time will always be interpreted as UTC. Valid formats are: `[+-]timespec \| YYYY-MM-DD \| YYYY-MM-DDTHH:MM:SS \| YYYY-MM-DD HH:MM:SS \| forever` where timespec can be an integer + `[w \| d \| h \| m \| s]` (e.g. `+32w1d2h`. Note that if using relative time this module is NOT idempotent.<br/>Required if `state` is `present`. | Optional | 
| valid_at | Check if the certificate is valid at a certain point in time. If it is not the certificate will be regenerated. Time will always be interpreted as UTC. Mainly to be used with relative timespec for `valid_from` and / or `valid_to`. Note that if using relative time this module is NOT idempotent. | Optional | 
| principals | Certificates may be limited to be valid for a set of principal (user/host) names. By default, generated certificates are valid for all users or hosts. | Optional | 
| options | Specify certificate options when signing a key. The option that are valid for user certificates are:<br/>`clear`: Clear all enabled permissions.  This is useful for clearing the default set of permissions so permissions may be added individually.<br/>`force-command=command`: Forces the execution of command instead of any shell or command specified by the user when the certificate is used for authentication.<br/>`no-agent-forwarding`: Disable ssh-agent forwarding (permitted by default).<br/>`no-port-forwarding`: Disable port forwarding (permitted by default).<br/>`no-pty Disable`: PTY allocation (permitted by default).<br/>`no-user-rc`: Disable execution of `~/.ssh/rc` by sshd (permitted by default).<br/>`no-x11-forwarding`: Disable X11 forwarding (permitted by default)<br/>`permit-agent-forwarding`: Allows ssh-agent forwarding.<br/>`permit-port-forwarding`: Allows port forwarding.<br/>`permit-pty`: Allows PTY allocation.<br/>`permit-user-rc`: Allows execution of `~/.ssh/rc` by sshd.<br/>`permit-x11-forwarding`: Allows X11 forwarding.<br/>`source-address=address_list`: Restrict the source addresses from which the certificate is considered valid. The `address_list` is a comma-separated list of one or more address/netmask pairs in CIDR format.<br/>At present, no options are valid for host keys. | Optional | 
| identifier | Specify the key identity when signing a public key. The identifier that is logged by the server when the certificate is used for authentication. | Optional | 
| serial_number | Specify the certificate serial number. The serial number is logged by the server when the certificate is used for authentication. The certificate serial number may be used in a KeyRevocationList. The serial number may be omitted for checks, but must be specified again for a new certificate. Note: The default value set by ssh-keygen is 0. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.OpensshCert.type | string | type of the certificate \(host or user\) | 
| Linux.OpensshCert.filename | string | path to the certificate | 
| Linux.OpensshCert.info | unknown | Information about the certificate. Output of \`ssh-keygen -L -f\`. | 



### linux-openssh-keypair
***
Generate OpenSSH private and public keys.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/openssh_keypair_module.html


#### Base Command

`linux-openssh-keypair`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the private and public keys should exist or not, taking action if the state is different from what is stated. Possible values are: present, absent. Default is present. | Optional | 
| size | Specifies the number of bits in the private key to create. For RSA keys, the minimum size is 1024 bits and the default is 4096 bits. Generally, 2048 bits is considered sufficient.  DSA keys must be exactly 1024 bits as specified by FIPS 186-2. For ECDSA keys, size determines the key length by selecting from one of three elliptic curve sizes: 256, 384 or 521 bits. Attempting to use bit lengths other than these three values for ECDSA keys will cause this module to fail. Ed25519 keys have a fixed length and the size will be ignored. | Optional | 
| type | The algorithm used to generate the SSH private key. `rsa1` is for protocol version 1. `rsa1` is deprecated and may not be supported by every version of ssh-keygen. Possible values are: rsa, dsa, rsa1, ecdsa, ed25519. Default is rsa. | Optional | 
| force | Should the key be regenerated even if it already exists. Possible values are: Yes, No. Default is No. | Optional | 
| path | Name of the files containing the public and private key. The file containing the public key will have the extension `.pub`. | Required | 
| comment | Provides a new comment to the public key. When checking if the key is in the correct state this will be ignored. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.OpensshKeypair.size | number | Size \(in bits\) of the SSH private key | 
| Linux.OpensshKeypair.type | string | Algorithm used to generate the SSH private key | 
| Linux.OpensshKeypair.filename | string | Path to the generated SSH private key file | 
| Linux.OpensshKeypair.fingerprint | string | The fingerprint of the key. | 
| Linux.OpensshKeypair.public_key | string | The public key of the generated SSH private key | 
| Linux.OpensshKeypair.comment | string | The comment of the generated key | 


#### Command Example
```!linux-openssh-keypair host="123.123.123.123" path="/tmp/id_ssh_rsa" ```

#### Context Example
```json
{
    "Linux": {
        "OpensshKeypair": {
            "changed": false,
            "comment": "",
            "filename": "/tmp/id_ssh_rsa",
            "fingerprint": "SHA256:vlhiKW0d9Ud7gFGnUOFCEYl3c3B/XcFtEiz2JggpXnw",
            "host": "123.123.123.123",
            "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDI5EKvHE4IhXqNA5zgWqbmYXxGdTKLuU0UQ4THQCnvMGR1BnfikSK+kT33Iq9wi3btoKoeqrgE8TMPb4On69akaPNnOgi2Dk+l0OoQBzIvn9m3RqvrtUFUDLTNckt/lrNIeIk3KXu22fcp0qoIgMNJmjYcY6Qbm8pCcVbXp6X3nbqk3glI2sTkM25UxbOLnbbyGrUMfUfAWGWC1wyyQktSc/5j41aZlvUhv/x54DBL8ASa/OeMxn9DboIm2flp+JgqDIm8rZXIucZjT6tool3XYseNJ0UxykQsAx36Gw2HGOXJbukiDlS0X5ifuj412uSh+g+UDvlaEjDhYasW2m7geDlZEJkSduELPar8pDP7RAqN3YIbv+zD+bOfZeSrxSzfIF103hcv+pAVXWqCwMSN1mSVdnuI9FLmTQ6a2TGE9OBwjbn+k2Vlxn0+aMZrT6R+M6rNsfUGLZRQviN+y8tvYDhsXmJhkhHo4XmdYRJmnHzWEETvboakATbTsqUVheyLS3tPgn7guDAQw67RBc/D7zPw6fuf9Xw9IhwqwH/MySskqsz3B7leuiYPqBaijAKw3Wdn1VmhszHC8kJL2RaEmTp4gNmMMp1H4V2zfH1f+jSG4gfwqJe/3xeNlBsKDvKDik5TRt6fzSlNbgvEOfijlABRU3rjg+kEUFvzHPcp1Q==",
            "size": 4096,
            "status": "SUCCESS",
            "type": "rsa"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * comment: 
>  * filename: /tmp/id_ssh_rsa
>  * fingerprint: SHA256:vlhiKW0d9Ud7gFGnUOFCEYl3c3B/XcFtEiz2JggpXnw
>  * public_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDI5EKvHE4IhXqNA5zgWqbmYXxGdTKLuU0UQ4THQCnvMGR1BnfikSK+kT33Iq9wi3btoKoeqrgE8TMPb4On69akaPNnOgi2Dk+l0OoQBzIvn9m3RqvrtUFUDLTNckt/lrNIeIk3KXu22fcp0qoIgMNJmjYcY6Qbm8pCcVbXp6X3nbqk3glI2sTkM25UxbOLnbbyGrUMfUfAWGWC1wyyQktSc/5j41aZlvUhv/x54DBL8ASa/OeMxn9DboIm2flp+JgqDIm8rZXIucZjT6tool3XYseNJ0UxykQsAx36Gw2HGOXJbukiDlS0X5ifuj412uSh+g+UDvlaEjDhYasW2m7geDlZEJkSduELPar8pDP7RAqN3YIbv+zD+bOfZeSrxSzfIF103hcv+pAVXWqCwMSN1mSVdnuI9FLmTQ6a2TGE9OBwjbn+k2Vlxn0+aMZrT6R+M6rNsfUGLZRQviN+y8tvYDhsXmJhkhHo4XmdYRJmnHzWEETvboakATbTsqUVheyLS3tPgn7guDAQw67RBc/D7zPw6fuf9Xw9IhwqwH/MySskqsz3B7leuiYPqBaijAKw3Wdn1VmhszHC8kJL2RaEmTp4gNmMMp1H4V2zfH1f+jSG4gfwqJe/3xeNlBsKDvKDik5TRt6fzSlNbgvEOfijlABRU3rjg+kEUFvzHPcp1Q==
>  * size: 4096
>  * type: rsa


### linux-acl
***
Set and retrieve file ACL information.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/acl_module.html


#### Base Command

`linux-acl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The full path of the file or object. | Required | 
| state | Define whether the ACL should be present or not.<br/>The `query` state gets the current ACL without changing it, for use in `register` operations. Possible values are: absent, present, query. Default is query. | Optional | 
| follow | Whether to follow symlinks on the path if a symlink is encountered. Possible values are: Yes, No. Default is Yes. | Optional | 
| default | If the target is a directory, setting this to `yes` will make it the default ACL for entities created inside the directory.<br/>Setting `default` to `yes` causes an error if the path is a file. Possible values are: Yes, No. Default is No. | Optional | 
| entity | The actual user or group that the ACL applies to when matching entity types user or group are selected. | Optional | 
| etype | The entity type of the ACL to apply, see `setfacl` documentation for more info. Possible values are: group, mask, other, user. | Optional | 
| permissions | The permissions to apply/remove can be any combination of `r`, `w` and `x` (read, write and execute respectively). | Optional | 
| entry | DEPRECATED.<br/>The ACL to set or remove.<br/>This must always be quoted in the form of `&lt;etype&gt;:&lt;qualifier&gt;:&lt;perms&gt;`.<br/>The qualifier may be empty for some types, but the type and perms are always required.<br/>`-` can be used as placeholder when you do not care about permissions.<br/>This is now superseded by entity, type and permissions fields. | Optional | 
| recursive | Recursively sets the specified ACL.<br/>Incompatible with `state=query`. Possible values are: Yes, No. Default is No. | Optional | 
| use_nfsv4_acls | Use NFSv4 ACLs instead of POSIX ACLs. Possible values are: Yes, No. Default is No. | Optional | 
| recalculate_mask | Select if and when to recalculate the effective right masks of the files.<br/>See `setfacl` documentation for more info.<br/>Incompatible with `state=query`. Possible values are: default, mask, no_mask. Default is default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Acl.acl | unknown | Current ACL on provided path \(after changes, if any\) | 



### linux-archive
***
Creates a compressed archive of one or more files or trees
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/archive_module.html


#### Base Command

`linux-archive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Remote absolute path, glob, or list of paths or globs for the file or files to compress or archive. | Required | 
| format | The type of compression to use.<br/>Support for xz was added in Ansible 2.5. Possible values are: bz2, gz, tar, xz, zip. Default is gz. | Optional | 
| dest | The file name of the destination archive.<br/>This is required when `path` refers to multiple files by either specifying a glob, a directory or multiple paths in a list. | Optional | 
| exclude_path | Remote absolute path, glob, or list of paths or globs for the file or files to exclude from the archive. | Optional | 
| force_archive | Allow you to force the module to treat this as an archive even if only a single file is specified.<br/>By default behaviour is maintained. i.e A when a single file is specified it is compressed only (not archived). Possible values are: Yes, No. Default is No. | Optional | 
| remove | Remove any added source files and trees after adding to archive. Possible values are: Yes, No. Default is No. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Archive.state | string | The current state of the archived file. If 'absent', then no source files were found and the archive does not exist. If 'compress', then the file source file is in the compressed state. If 'archive', then the source file or paths are currently archived. If 'incomplete', then an archive was created, but not all source paths were found. | 
| Linux.Archive.missing | unknown | Any files that were missing from the source. | 
| Linux.Archive.archived | unknown | Any files that were compressed or added to the archive. | 
| Linux.Archive.arcroot | string | The archive root. | 
| Linux.Archive.expanded_paths | unknown | The list of matching paths from paths argument. | 
| Linux.Archive.expanded_exclude_paths | unknown | The list of matching exclude paths from the exclude_path argument. | 


### linux-assemble
***
Assemble configuration files from fragments
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/assemble_module.html


#### Base Command

`linux-assemble`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| src | An already existing directory full of source files. | Required | 
| dest | A file to create using the concatenation of all of the source files. | Required | 
| backup | Create a backup file (if `yes`), including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| delimiter | A delimiter to separate the file contents. | Optional | 
| remote_src | If `no`, it will search for src at originating/master machine.<br/>If `yes`, it will go to the remote/target machine for the src. Possible values are: Yes, No. Default is No. | Optional | 
| regexp | Assemble files only if `regex` matches the filename.<br/>If not set, all files are assembled.<br/>Every "\" (backslash) must be escaped as "\\" to comply to YAML syntax.<br/>Uses `Python regular expressions,http://docs.python.org/2/library/re.html`. | Optional | 
| ignore_hidden | A boolean that controls if files that start with a '.' will be included or not. Possible values are: Yes, No. Default is No. | Optional | 
| validate | The validation command to run before copying into place.<br/>The path to the file to validate is passed in via '%s' which must be present as in the sshd example below.<br/>The command is passed securely so shell features like expansion and pipes won't work. | Optional | 
| decrypt | This option controls the autodecryption of source files using vault. Possible values are: Yes, No. Default is Yes. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-blockinfile
***
Insert/update/remove a text block surrounded by marker lines
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/blockinfile_module.html


#### Base Command

`linux-blockinfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The file to modify.<br/>Before Ansible 2.3 this option was only usable as `dest`, `destfile` and `name`. | Required | 
| state | Whether the block should be there or not. Possible values are: absent, present. Default is present. | Optional | 
| marker | The marker line template.<br/>`{mark}` will be replaced with the values `in marker_begin` (default="BEGIN") and `marker_end` (default="END").<br/>Using a custom marker without the `{mark}` variable may result in the block being repeatedly inserted on subsequent playbook runs. Default is # {mark} ANSIBLE MANAGED BLOCK. | Optional | 
| block | The text to insert inside the marker lines.<br/>If it is missing or an empty string, the block will be removed as if `state` were specified to `absent`. | Optional | 
| insertafter | If specified, the block will be inserted after the last match of specified regular expression.<br/>A special value is available; `EOF` for inserting the block at the end of the file.<br/>If specified regular expression has no matches, `EOF` will be used instead. Possible values are: EOF, *regex*. Default is EOF. | Optional | 
| insertbefore | If specified, the block will be inserted before the last match of specified regular expression.<br/>A special value is available; `BOF` for inserting the block at the beginning of the file.<br/>If specified regular expression has no matches, the block will be inserted at the end of the file. Possible values are: BOF, *regex*. | Optional | 
| create | Create a new file if it does not exist. Possible values are: Yes, No. Default is No. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| marker_begin | This will be inserted at `{mark}` in the opening ansible block marker. Default is BEGIN. | Optional | 
| marker_end | This will be inserted at `{mark}` in the closing ansible block marker. Default is END. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 
| validate | The validation command to run before copying into place.<br/>The path to the file to validate is passed in via '%s' which must be present as in the examples below.<br/>The command is passed securely so shell features like expansion and pipes will not work. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-file
***
Manage files and file properties
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/file_module.html


#### Base Command

`linux-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the file being managed. | Required | 
| state | If `absent`, directories will be recursively deleted, and files or symlinks will be unlinked. In the case of a directory, if `diff` is declared, you will see the files and folders deleted listed under `path_contents`. Note that `absent` will not cause `file` to fail if the `path` does not exist as the state did not change.<br/>If `directory`, all intermediate subdirectories will be created if they do not exist. Since Ansible 1.7 they will be created with the supplied permissions.<br/>If `file`, without any other options this works mostly as a 'stat' and will return the current state of `path`. Even with other options (i.e `mode`), the file will be modified but will NOT be created if it does not exist; see the `touch` value or the `copy` or `template` module if you want that behavior.<br/>If `hard`, the hard link will be created or changed.<br/>If `link`, the symbolic link will be created or changed.<br/>If `touch` (new in 1.4), an empty file will be created if the `path` does not exist, while an existing file or directory will receive updated file access and modification times (similar to the way `touch` works from the command line). Possible values are: absent, directory, file, hard, link, touch. Default is file. | Optional | 
| src | Path of the file to link to.<br/>This applies only to `state=link` and `state=hard`.<br/>For `state=link`, this will also accept a non-existing path.<br/>Relative paths are relative to the file being created (`path`) which is how the Unix command `ln -s SRC DEST` treats relative paths. | Optional | 
| recurse | Recursively set the specified file attributes on directory contents.<br/>This applies only when `state` is set to `directory`. Possible values are: Yes, No. Default is No. | Optional | 
| force | Force the creation of the symlinks in two cases: the source file does not exist (but will appear later); the destination exists and is a file (so, we need to unlink the `path` file and create symlink to the `src` file in place of it). Possible values are: Yes, No. Default is No. | Optional | 
| follow | This flag indicates that filesystem links, if they exist, should be followed.<br/>Previous to Ansible 2.5, this was `no` by default. Possible values are: Yes, No. Default is Yes. | Optional | 
| modification_time | This parameter indicates the time the file's modification time should be set to.<br/>Should be `preserve` when no modification is required, `YYYYMMDDHHMM.SS` when using default time format, or `now`.<br/>Default is None meaning that `preserve` is the default for `state=[file,directory,link,hard]` and `now` is default for `state=touch`. | Optional | 
| modification_time_format | When used with `modification_time`, indicates the time format that must be used.<br/>Based on default Python format (see time.strftime doc). Default is %Y%m%d%H%M.%S. | Optional | 
| access_time | This parameter indicates the time the file's access time should be set to.<br/>Should be `preserve` when no modification is required, `YYYYMMDDHHMM.SS` when using default time format, or `now`.<br/>Default is `None` meaning that `preserve` is the default for `state=[file,directory,link,hard]` and `now` is default for `state=touch`. | Optional | 
| access_time_format | When used with `access_time`, indicates the time format that must be used.<br/>Based on default Python format (see time.strftime doc). Default is %Y%m%d%H%M.%S. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-find
***
Return a list of files based on specific criteria
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/find_module.html


#### Base Command

`linux-find`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| age | Select files whose age is equal to or greater than the specified time.<br/>Use a negative age to find files equal to or less than the specified time.<br/>You can choose seconds, minutes, hours, days, or weeks by specifying the first letter of any of those words (e.g., "1w"). | Optional | 
| patterns | One or more (shell or regex) patterns, which type is controlled by `use_regex` option.<br/>The patterns restrict the list of files to be returned to those whose basenames match at least one of the patterns specified. Multiple patterns can be specified using a list.<br/>The pattern is matched against the file base name, excluding the directory.<br/>When using regexen, the pattern MUST match the ENTIRE file name, not just parts of it. So if you are looking to match all files ending in .default, you'd need to use '.*\.default' as a regexp and not just '\.default'.<br/>This parameter expects a list, which can be either comma separated or YAML. If any of the patterns contain a comma, make sure to put them in a list to avoid splitting the patterns in undesirable ways.<br/>Defaults to '*' when `use_regex=False`, or '.*' when `use_regex=True`. | Optional | 
| excludes | One or more (shell or regex) patterns, which type is controlled by `use_regex` option.<br/>Items whose basenames match an `excludes` pattern are culled from `patterns` matches. Multiple patterns can be specified using a list. | Optional | 
| contains | A regular expression or pattern which should be matched against the file content. | Optional | 
| paths | List of paths of directories to search. All paths must be fully qualified. | Required | 
| file_type | Type of file to select.<br/>The 'link' and 'any' choices were added in Ansible 2.3. Possible values are: any, directory, file, link. Default is file. | Optional | 
| recurse | If target is a directory, recursively descend into the directory looking for files. Possible values are: Yes, No. Default is No. | Optional | 
| size | Select files whose size is equal to or greater than the specified size.<br/>Use a negative size to find files equal to or less than the specified size.<br/>Unqualified values are in bytes but b, k, m, g, and t can be appended to specify bytes, kilobytes, megabytes, gigabytes, and terabytes, respectively.<br/>Size is not evaluated for directories. | Optional | 
| age_stamp | Choose the file property against which we compare age. Possible values are: atime, ctime, mtime. Default is mtime. | Optional | 
| hidden | Set this to `yes` to include hidden files, otherwise they will be ignored. Possible values are: Yes, No. Default is No. | Optional | 
| follow | Set this to `yes` to follow symlinks in path for systems with python 2.6+. Possible values are: Yes, No. Default is No. | Optional | 
| get_checksum | Set this to `yes` to retrieve a file's SHA1 checksum. Possible values are: Yes, No. Default is No. | Optional | 
| use_regex | If `no`, the patterns are file globs (shell).<br/>If `yes`, they are python regexes. Possible values are: Yes, No. Default is No. | Optional | 
| depth | Set the maximum number of levels to descend into.<br/>Setting recurse to `no` will override this value, which is effectively depth 1.<br/>Default is unlimited depth. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Find.files | unknown | All matches found with the specified criteria \(see stat module for full output of each dictionary\) | 
| Linux.Find.matched | number | Number of matches | 
| Linux.Find.examined | number | Number of filesystem objects looked at | 


#### Command Example
```!linux-find host="123.123.123.123" paths="/tmp" age="2d" recurse="True" ```

#### Context Example
```json
{
    "Linux": {
        "Find": {
            "changed": false,
            "examined": 18,
            "files": [],
            "host": "123.123.123.123",
            "matched": 0,
            "msg": "",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * examined: 18
>  * matched: 0
>  * msg: 
>  * ## Files


### linux-ini-file
***
Tweak settings in INI files
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ini_file_module.html


#### Base Command

`linux-ini-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the INI-style file; this file is created if required.<br/>Before Ansible 2.3 this option was only usable as `dest`. | Required | 
| section | Section name in INI file. This is added if `state=present` automatically when a single value is being set.<br/>If left empty or set to `null`, the `option` will be placed before the first `section`.<br/>Using `null` is also required if the config format does not support sections. | Required | 
| option | If set (required for changing a `value`), this is the name of the option.<br/>May be omitted if adding/removing a whole `section`. | Optional | 
| value | The string value to be associated with an `option`.<br/>May be omitted when removing an `option`. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| state | If set to `absent` the option or section will be removed if present instead of created. Possible values are: absent, present. Default is present. | Optional | 
| no_extra_spaces | Do not insert spaces before and after '=' symbol. Possible values are: Yes, No. Default is No. | Optional | 
| create | If set to `no`, the module will fail if the file does not already exist.<br/>By default it will create the file if it is missing. Possible values are: Yes, No. Default is Yes. | Optional | 
| allow_no_value | Allow option without value and without '=' symbol. Possible values are: Yes, No. Default is No. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-ini-file host="123.123.123.123" path="/etc/conf" section="drinks" option="fav" value="lemonade" mode="0600" backup="True" ```

#### Context Example
```json
{
    "Linux": {
        "IniFile": {
            "changed": false,
            "gid": 0,
            "group": "root",
            "host": "123.123.123.123",
            "mode": "0600",
            "msg": "OK",
            "owner": "root",
            "path": "/etc/conf",
            "secontext": "system_u:object_r:etc_t:s0",
            "size": 25,
            "state": "file",
            "status": "SUCCESS",
            "uid": 0
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * gid: 0
>  * group: root
>  * mode: 0600
>  * msg: OK
>  * owner: root
>  * path: /etc/conf
>  * secontext: system_u:object_r:etc_t:s0
>  * size: 25
>  * state: file
>  * uid: 0


### linux-iso-extract
***
Extract files from an ISO image
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/iso_extract_module.html


#### Base Command

`linux-iso-extract`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| image | The ISO image to extract files from. | Required | 
| dest | The destination directory to extract files to. | Required | 
| files | A list of files to extract from the image.<br/>Extracting directories does not work. | Required | 
| force | If `yes`, which will replace the remote file when contents are different than the source.<br/>If `no`, the file will only be extracted and copied if the destination does not already exist.<br/>Alias `thirsty` has been deprecated and will be removed in 2.13. Possible values are: Yes, No. Default is Yes. | Optional | 
| executable | The path to the `7z` executable to use for extracting files from the ISO. Default is 7z. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-lineinfile
***
Manage lines in text files
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/lineinfile_module.html


#### Base Command

`linux-lineinfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The file to modify.<br/>Before Ansible 2.3 this option was only usable as `dest`, `destfile` and `name`. | Required | 
| regexp | The regular expression to look for in every line of the file.<br/>For `state=present`, the pattern to replace if found. Only the last line found will be replaced.<br/>For `state=absent`, the pattern of the line(s) to remove.<br/>If the regular expression is not matched, the line will be added to the file in keeping with `insertbefore` or `insertafter` settings.<br/>When modifying a line the regexp should typically match both the initial state of the line as well as its state after replacement by `line` to ensure idempotence.<br/>Uses Python regular expressions. See `http://docs.python.org/2/library/re.html`. | Optional | 
| state | Whether the line should be there or not. Possible values are: absent, present. Default is present. | Optional | 
| line | The line to insert/replace into the file.<br/>Required for `state=present`.<br/>If `backrefs` is set, may contain backreferences that will get expanded with the `regexp` capture groups if the regexp matches. | Optional | 
| backrefs | Used with `state=present`.<br/>If set, `line` can contain backreferences (both positional and named) that will get populated if the `regexp` matches.<br/>This parameter changes the operation of the module slightly; `insertbefore` and `insertafter` will be ignored, and if the `regexp` does not match anywhere in the file, the file will be left unchanged.<br/>If the `regexp` does match, the last matching line will be replaced by the expanded line parameter. Possible values are: Yes, No. Default is No. | Optional | 
| insertafter | Used with `state=present`.<br/>If specified, the line will be inserted after the last match of specified regular expression.<br/>If the first match is required, use(firstmatch=yes).<br/>A special value is available; `EOF` for inserting the line at the end of the file.<br/>If specified regular expression has no matches, EOF will be used instead.<br/>If `insertbefore` is set, default value `EOF` will be ignored.<br/>If regular expressions are passed to both `regexp` and `insertafter`, `insertafter` is only honored if no match for `regexp` is found.<br/>May not be used with `backrefs` or `insertbefore`. Possible values are: EOF, *regex*. Default is EOF. | Optional | 
| insertbefore | Used with `state=present`.<br/>If specified, the line will be inserted before the last match of specified regular expression.<br/>If the first match is required, use `firstmatch=yes`.<br/>A value is available; `BOF` for inserting the line at the beginning of the file.<br/>If specified regular expression has no matches, the line will be inserted at the end of the file.<br/>If regular expressions are passed to both `regexp` and `insertbefore`, `insertbefore` is only honored if no match for `regexp` is found.<br/>May not be used with `backrefs` or `insertafter`. Possible values are: BOF, *regex*. | Optional | 
| create | Used with `state=present`.<br/>If specified, the file will be created if it does not already exist.<br/>By default it will fail if the file is missing. Possible values are: Yes, No. Default is No. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| firstmatch | Used with `insertafter` or `insertbefore`.<br/>If set, `insertafter` and `insertbefore` will work with the first line that matches the given regular expression. Possible values are: Yes, No. Default is No. | Optional | 
| others | All arguments accepted by the `file` module also work here. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 
| validate | The validation command to run before copying into place.<br/>The path to the file to validate is passed in via '%s' which must be present as in the examples below.<br/>The command is passed securely so shell features like expansion and pipes will not work. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-lineinfile host="123.123.123.123" path="/etc/selinux/config" regexp="^SELINUX=" line="SELINUX=enforcing" ```

#### Context Example
```json
{
    "Linux": {
        "Lineinfile": {
            "backup": "",
            "changed": false,
            "host": "123.123.123.123",
            "msg": "",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * backup: 
>  * changed: False
>  * msg: 


### linux-replace
***
Replace all instances of a particular string in a file using a back-referenced regular expression
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/replace_module.html


#### Base Command

`linux-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The file to modify.<br/>Before Ansible 2.3 this option was only usable as `dest`, `destfile` and `name`. | Required | 
| regexp | The regular expression to look for in the contents of the file.<br/>Uses Python regular expressions; see `http://docs.python.org/2/library/re.html`.<br/>Uses MULTILINE mode, which means `^` and `$` match the beginning and end of the file, as well as the beginning and end respectively of `each line` of the file.<br/>Does not use DOTALL, which means the `.` special character matches any character `except newlines`. A common mistake is to assume that a negated character set like `[^#]` will also not match newlines.<br/>In order to exclude newlines, they must be added to the set like `[^#\n]`.<br/>Note that, as of Ansible 2.0, short form tasks should have any escape sequences backslash-escaped in order to prevent them being parsed as string literal escapes. See the examples. | Required | 
| replace | The string to replace regexp matches.<br/>May contain backreferences that will get expanded with the regexp capture groups if the regexp matches.<br/>If not set, matches are removed entirely.<br/>Backreferences can be used ambiguously like `\1`, or explicitly like `\g&lt;1&gt;`. | Optional | 
| after | If specified, only content after this match will be replaced/removed.<br/>Can be used in combination with `before`.<br/>Uses Python regular expressions; see `http://docs.python.org/2/library/re.html`.<br/>Uses DOTALL, which means the `.` special character `can match newlines`. | Optional | 
| before | If specified, only content before this match will be replaced/removed.<br/>Can be used in combination with `after`.<br/>Uses Python regular expressions; see `http://docs.python.org/2/library/re.html`.<br/>Uses DOTALL, which means the `.` special character `can match newlines`. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| others | All arguments accepted by the `file` module also work here. | Optional | 
| encoding | The character encoding for reading and writing the file. Default is utf-8. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 
| validate | The validation command to run before copying into place.<br/>The path to the file to validate is passed in via '%s' which must be present as in the examples below.<br/>The command is passed securely so shell features like expansion and pipes will not work. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-replace host="123.123.123.123" path="/etc/hosts" regexp="(\\s+)old\\.host\\.name(\\s+.*)?$" replace="\\1new.host.name\\2" ```

#### Context Example
```json
{
    "Linux": {
        "Replace": {
            "changed": false,
            "host": "123.123.123.123",
            "msg": "",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * msg: 


### linux-stat
***
Retrieve file or file system status
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/stat_module.html


#### Base Command

`linux-stat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The full path of the file/object to get the facts of. | Required | 
| follow | Whether to follow symlinks. Possible values are: Yes, No. Default is No. | Optional | 
| get_checksum | Whether to return a checksum of the file. Possible values are: Yes, No. Default is Yes. | Optional | 
| checksum_algorithm | Algorithm to determine checksum of file.<br/>Will throw an error if the host is unable to use specified algorithm.<br/>The remote host has to support the hashing method specified, `md5` can be unavailable if the host is FIPS-140 compliant. Possible values are: md5, sha1, sha224, sha256, sha384, sha512. Default is sha1. | Optional | 
| get_mime | Use file magic and return data about the nature of the file. this uses the 'file' utility found on most Linux/Unix systems.<br/>This will add both `mime_type` and 'charset' fields to the return, if possible.<br/>In Ansible 2.3 this option changed from 'mime' to 'get_mime' and the default changed to 'Yes'. Possible values are: Yes, No. Default is Yes. | Optional | 
| get_attributes | Get file attributes using lsattr tool if present. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Stat.stat | unknown | dictionary containing all the stat data, some platforms might add additional fields | 


#### Command Example
```!linux-stat host="123.123.123.123" path="/etc/foo.conf" ```

#### Context Example
```json
{
    "Linux": {
        "Stat": {
            "exists": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * exists: False


### linux-synchronize
***
A wrapper around rsync to make common tasks in your playbooks quick and easy
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/synchronize_module.html


#### Base Command

`linux-synchronize`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| src | Path on the source host that will be synchronized to the destination.<br/>The path can be absolute or relative. | Required | 
| dest | Path on the destination host that will be synchronized from the source.<br/>The path can be absolute or relative. | Required | 
| dest_port | Port number for ssh on the destination host.<br/>Prior to Ansible 2.0, the ssh_port inventory var took precedence over this value.<br/>This parameter defaults to the value of `ssh_port` or `port`, the `remote_port` config setting or the value from ssh client configuration if none of the former have been set. | Optional | 
| mode | Specify the direction of the synchronization.<br/>In push mode the localhost or delegate is the source.<br/>In pull mode the remote host in context is the source. Possible values are: pull, push. Default is push. | Optional | 
| archive | Mirrors the rsync archive flag, enables recursive, links, perms, times, owner, group flags and -D. Possible values are: Yes, No. Default is Yes. | Optional | 
| checksum | Skip based on checksum, rather than mod-time &amp; size; Note that that "archive" option is still enabled by default - the "checksum" option will not disable it. Possible values are: Yes, No. Default is No. | Optional | 
| compress | Compress file data during the transfer.<br/>In most cases, leave this enabled unless it causes problems. Possible values are: Yes, No. Default is Yes. | Optional | 
| existing_only | Skip creating new files on receiver. Possible values are: Yes, No. Default is No. | Optional | 
| delete | Delete files in `dest` that don't exist (after transfer, not before) in the `src` path.<br/>This option requires `recursive=yes`.<br/>This option ignores excluded files and behaves like the rsync opt --delete-excluded. Possible values are: Yes, No. Default is No. | Optional | 
| dirs | Transfer directories without recursing. Possible values are: Yes, No. Default is No. | Optional | 
| recursive | Recurse into directories.<br/>This parameter defaults to the value of the archive option. | Optional | 
| links | Copy symlinks as symlinks.<br/>This parameter defaults to the value of the archive option. | Optional | 
| copy_links | Copy symlinks as the item that they point to (the referent) is copied, rather than the symlink. Possible values are: Yes, No. Default is No. | Optional | 
| perms | Preserve permissions.<br/>This parameter defaults to the value of the archive option. | Optional | 
| times | Preserve modification times.<br/>This parameter defaults to the value of the archive option. | Optional | 
| owner | Preserve owner (super user only).<br/>This parameter defaults to the value of the archive option. | Optional | 
| group | Preserve group.<br/>This parameter defaults to the value of the archive option. | Optional | 
| rsync_path | Specify the rsync command to run on the remote host. See `--rsync-path` on the rsync man page.<br/>To specify the rsync command to run on the local host, you need to set this your task var `rsync_path`. | Optional | 
| rsync_timeout | Specify a `--timeout` for the rsync command in seconds. Default is 0. | Optional | 
| set_remote_user | Put user@ for the remote paths.<br/>If you have a custom ssh config to define the remote user for a host that does not match the inventory user, you should set this parameter to `no`. Possible values are: Yes, No. Default is Yes. | Optional | 
| use_ssh_args | Use the ssh_args specified in ansible.cfg. Possible values are: Yes, No. Default is No. | Optional | 
| rsync_opts | Specify additional rsync options by passing in an array.<br/>Note that an empty string in `rsync_opts` will end up transfer the current working directory. | Optional | 
| partial | Tells rsync to keep the partial file which should make a subsequent transfer of the rest of the file much faster. Possible values are: Yes, No. Default is No. | Optional | 
| verify_host | Verify destination host key. Possible values are: Yes, No. Default is No. | Optional | 
| private_key | Specify the private key to use for SSH-based rsync connections (e.g. `~/.ssh/id_rsa`). | Optional | 
| link_dest | Add a destination to hard link against during the rsync. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-tempfile
***
Creates temporary files and directories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/tempfile_module.html


#### Base Command

`linux-tempfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether to create file or directory. Possible values are: directory, file. Default is file. | Optional | 
| path | Location where temporary file or directory should be created.<br/>If path is not specified, the default system temporary directory will be used. | Optional | 
| prefix | Prefix of file/directory name created by module. Default is ansible.. | Optional | 
| suffix | Suffix of file/directory name created by module. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Tempfile.path | string | Path to created file or directory | 


#### Command Example
```!linux-tempfile host="123.123.123.123" state="directory" suffix="build" ```

#### Context Example
```json
{
    "Linux": {
        "Tempfile": {
            "changed": true,
            "gid": 0,
            "group": "root",
            "host": "123.123.123.123",
            "mode": "0700",
            "owner": "root",
            "path": "/tmp/ansible.eehilh3tbuild",
            "secontext": "unconfined_u:object_r:user_tmp_t:s0",
            "size": 6,
            "state": "directory",
            "status": "CHANGED",
            "uid": 0
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * gid: 0
>  * group: root
>  * mode: 0700
>  * owner: root
>  * path: /tmp/ansible.eehilh3tbuild
>  * secontext: unconfined_u:object_r:user_tmp_t:s0
>  * size: 6
>  * state: directory
>  * uid: 0


### linux-unarchive
***
Unpacks an archive after (optionally) copying it from the local machine.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/unarchive_module.html


#### Base Command

`linux-unarchive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| src | If `remote_"src"=no` (default), local path to archive file to copy to the target server; can be absolute or relative. If `remote_"src"=yes`, path on the target server to existing archive file to unpack.<br/>If `remote_"src"=yes` and `src` contains `://`, the remote machine will download the file from the URL first. (version_added 2.0). This is only for simple cases, for full download support use the `get_url` module. | Required | 
| dest | Remote absolute path where the archive should be unpacked. | Required | 
| copy | If true, the file is copied from local 'master' to the target machine, otherwise, the plugin will look for src archive at the target machine.<br/>This option has been deprecated in favor of `remote_src`.<br/>This option is mutually exclusive with `remote_src`. Possible values are: Yes, No. Default is Yes. | Optional | 
| creates | If the specified absolute path (file or directory) already exists, this step will `not` be run. | Optional | 
| list_files | If set to True, return the list of files that are contained in the tarball. Possible values are: Yes, No. Default is No. | Optional | 
| exclude | List the directory and file entries that you would like to exclude from the unarchive action. | Optional | 
| keep_newer | Do not replace existing files that are newer than files from the archive. Possible values are: Yes, No. Default is No. | Optional | 
| extra_opts | Specify additional options by passing in an array.<br/>Each space-separated command-line option should be a new element of the array. See examples.<br/>Command-line options with multiple elements must use multiple lines in the array, one for each element. | Optional | 
| remote_src | Set to `yes` to indicate the archived file is already on the remote system and not local to the Ansible controller.<br/>This option is mutually exclusive with `copy`. Possible values are: Yes, No. Default is No. | Optional | 
| validate_certs | This only applies if using a https URL as the source of the file.<br/>This should only set to `no` used on personally controlled sites using self-signed certificate.<br/>Prior to 2.2 the code worked as if this was set to `yes`. Possible values are: Yes, No. Default is Yes. | Optional | 
| decrypt | This option controls the autodecryption of source files using vault. Possible values are: Yes, No. Default is Yes. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-xml
***
Manage bits and pieces of XML files or strings
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/xml_module.html


#### Base Command

`linux-xml`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the file to operate on.<br/>This file must exist ahead of time.<br/>This parameter is required, unless `xmlstring` is given. | Required | 
| xmlstring | A string containing XML on which to operate.<br/>This parameter is required, unless `path` is given. | Required | 
| xpath | A valid XPath expression describing the item(s) you want to manipulate.<br/>Operates on the document root, `/`, by default. | Optional | 
| namespaces | The namespace `prefix:uri` mapping for the XPath expression.<br/>Needs to be a `dict`, not a `list` of items. | Optional | 
| state | Set or remove an xpath selection (node(s), attribute(s)). Possible values are: absent, present. Default is present. | Optional | 
| attribute | The attribute to select when using parameter `value`.<br/>This is a string, not prepended with `@`. | Optional | 
| value | Desired state of the selected attribute.<br/>Either a string, or to unset a value, the Python `None` keyword (YAML Equivalent, `null`).<br/>Elements default to no value (but present).<br/>Attributes default to an empty string. | Optional | 
| add_children | Add additional child-element(s) to a selected element for a given `xpath`.<br/>Child elements must be given in a list and each item may be either a string (eg. `children=ansible` to add an empty `&lt;ansible/&gt;` child element), or a hash where the key is an element name and the value is the element value.<br/>This parameter requires `xpath` to be set. | Optional | 
| set_children | Set the child-element(s) of a selected element for a given `xpath`.<br/>Removes any existing children.<br/>Child elements must be specified as in `add_children`.<br/>This parameter requires `xpath` to be set. | Optional | 
| count | Search for a given `xpath` and provide the count of any matches.<br/>This parameter requires `xpath` to be set. Possible values are: Yes, No. Default is No. | Optional | 
| print_match | Search for a given `xpath` and print out any matches.<br/>This parameter requires `xpath` to be set. Possible values are: Yes, No. Default is No. | Optional | 
| pretty_print | Pretty print XML output. Possible values are: Yes, No. Default is No. | Optional | 
| content | Search for a given `xpath` and get content.<br/>This parameter requires `xpath` to be set. Possible values are: attribute, text. | Optional | 
| input_type | Type of input for `add_children` and `set_children`. Possible values are: xml, yaml. Default is yaml. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| strip_cdata_tags | Remove CDATA tags surrounding text values.<br/>Note that this might break your XML file if text values contain characters that could be interpreted as XML. Possible values are: Yes, No. Default is No. | Optional | 
| insertbefore | Add additional child-element(s) before the first selected element for a given `xpath`.<br/>Child elements must be given in a list and each item may be either a string (eg. `children=ansible` to add an empty `&lt;ansible/&gt;` child element), or a hash where the key is an element name and the value is the element value.<br/>This parameter requires `xpath` to be set. Possible values are: Yes, No. Default is No. | Optional | 
| insertafter | Add additional child-element(s) after the last selected element for a given `xpath`.<br/>Child elements must be given in a list and each item may be either a string (eg. `children=ansible` to add an empty `&lt;ansible/&gt;` child element), or a hash where the key is an element name and the value is the element value.<br/>This parameter requires `xpath` to be set. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Xml.actions | unknown | A dictionary with the original xpath, namespaces and state. | 
| Linux.Xml.backup_file | string | The name of the backup file that was created | 
| Linux.Xml.count | number | The count of xpath matches. | 
| Linux.Xml.matches | unknown | The xpath matches found. | 
| Linux.Xml.msg | string | A message related to the performed action\(s\). | 
| Linux.Xml.xmlstring | string | An XML string of the resulting output. | 



### linux-expect
***
Executes a command and responds to prompts.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/expect_module.html


#### Base Command

`linux-expect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| command | The command module takes command to run. | Required | 
| creates | A filename, when it already exists, this step will `not` be run. | Optional | 
| removes | A filename, when it does not exist, this step will `not` be run. | Optional | 
| chdir | Change into this directory before running the command. | Optional | 
| responses | Mapping of expected string/regex and string to respond with. If the response is a list, successive matches return successive responses. List functionality is new in 2.1. | Required | 
| timeout | Amount of time in seconds to wait for the expected strings. Use `null` to disable timeout. Default is 30. | Optional | 
| echo | Whether or not to echo out your response strings. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-bower
***
Manage bower packages with bower
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/bower_module.html


#### Base Command

`linux-bower`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of a bower package to install. | Optional | 
| offline | Install packages from local cache, if the packages were installed before. Default is no. | Optional | 
| production | Install with --production flag. Default is no. | Optional | 
| path | The base path where to install the bower packages. | Required | 
| relative_execpath | Relative path to bower executable from install path. | Optional | 
| state | The state of the bower package. Possible values are: present, absent, latest. Default is present. | Optional | 
| version | The version to be installed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-bundler
***
Manage Ruby Gem dependencies with Bundler
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/bundler_module.html


#### Base Command

`linux-bundler`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| executable | The path to the bundler executable. | Optional | 
| state | The desired state of the Gem bundle. `latest` updates gems to the most recent, acceptable version. Possible values are: present, latest. Default is present. | Optional | 
| chdir | The directory to execute the bundler commands from. This directory needs to contain a valid Gemfile or .bundle/ directory. Default is temporary working directory. | Optional | 
| exclude_groups | A list of Gemfile groups to exclude during operations. This only applies when state is `present`. Bundler considers this a 'remembered' property for the Gemfile and will automatically exclude groups in future operations even if `exclude_groups` is not set. | Optional | 
| clean | Only applies if state is `present`. If set removes any gems on the target host that are not in the gemfile. Default is no. | Optional | 
| gemfile | Only applies if state is `present`. The path to the gemfile to use to install gems. Default is Gemfile in current directory. | Optional | 
| local | If set only installs gems from the cache on the target host. Default is no. | Optional | 
| deployment_mode | Only applies if state is `present`. If set it will install gems in ./vendor/bundle instead of the default location. Requires a Gemfile.lock file to have been created prior. Default is no. | Optional | 
| user_install | Only applies if state is `present`. Installs gems in the local user's cache or for all users. Default is yes. | Optional | 
| gem_path | Only applies if state is `present`. Specifies the directory to install the gems into. If `chdir` is set then this path is relative to `chdir`. Default is RubyGems gem paths. | Optional | 
| binstub_directory | Only applies if state is `present`. Specifies the directory to install any gem bins files to. When executed the bin files will run within the context of the Gemfile and fail if any required gem dependencies are not installed. If `chdir` is set then this path is relative to `chdir`. | Optional | 
| extra_args | A space separated string of additional commands that can be applied to the Bundler command. Refer to the Bundler documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-composer
***
Dependency Manager for PHP
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/composer_module.html


#### Base Command

`linux-composer`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| command | Composer command like "install", "update" and so on. Default is install. | Optional | 
| arguments | Composer arguments like required package, version and so on. | Optional | 
| executable | Path to PHP Executable on the remote host, if PHP is not in PATH. | Optional | 
| working_dir | Directory of your project (see --working-dir). This is required when the command is not run globally.<br/>Will be ignored if `global_command=true`. | Optional | 
| global_command | Runs the specified command globally. Possible values are: Yes, No. Default is No. | Optional | 
| prefer_source | Forces installation from package sources when possible (see --prefer-source). Possible values are: Yes, No. Default is No. | Optional | 
| prefer_dist | Forces installation from package dist even for dev versions (see --prefer-dist). Possible values are: Yes, No. Default is No. | Optional | 
| no_dev | Disables installation of require-dev packages (see --no-dev). Possible values are: Yes, No. Default is Yes. | Optional | 
| no_scripts | Skips the execution of all scripts defined in composer.json (see --no-scripts). Possible values are: Yes, No. Default is No. | Optional | 
| no_plugins | Disables all plugins ( see --no-plugins ). Possible values are: Yes, No. Default is No. | Optional | 
| optimize_autoloader | Optimize autoloader during autoloader dump (see --optimize-autoloader).<br/>Convert PSR-0/4 autoloading to classmap to get a faster autoloader.<br/>Recommended especially for production, but can take a bit of time to run. Possible values are: Yes, No. Default is Yes. | Optional | 
| classmap_authoritative | Autoload classes from classmap only.<br/>Implicitely enable optimize_autoloader.<br/>Recommended especially for production, but can take a bit of time to run. Possible values are: Yes, No. Default is No. | Optional | 
| apcu_autoloader | Uses APCu to cache found/not-found classes. Possible values are: Yes, No. Default is No. | Optional | 
| ignore_platform_reqs | Ignore php, hhvm, lib-* and ext-* requirements and force the installation even if the local machine does not fulfill these. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-cpanm
***
Manages Perl library dependencies.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/cpanm_module.html


#### Base Command

`linux-cpanm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the Perl library to install. You may use the "full distribution path", e.g.  MIYAGAWA/Plack-0.99_05.tar.gz. | Optional | 
| from_path | The local directory from where to install. | Optional | 
| notest | Do not run unit tests. Possible values are: Yes, No. Default is No. | Optional | 
| locallib | Specify the install base to install modules. | Optional | 
| mirror | Specifies the base URL for the CPAN mirror to use. | Optional | 
| mirror_only | Use the mirror's index file instead of the CPAN Meta DB. Possible values are: Yes, No. Default is No. | Optional | 
| installdeps | Only install dependencies. Possible values are: Yes, No. Default is No. | Optional | 
| version | minimum version of perl module to consider acceptable. | Optional | 
| system_lib | Use this if you want to install modules to the system perl include path. You must be root or have "passwordless" sudo for this to work.<br/>This uses the cpanm commandline option '--sudo', which has nothing to do with ansible privilege escalation. Possible values are: Yes, No. Default is No. | Optional | 
| executable | Override the path to the cpanm executable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-gem
***
Manage Ruby gems
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/gem_module.html


#### Base Command

`linux-gem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the gem to be managed. | Required | 
| state | The desired state of the gem. `latest` ensures that the latest version is installed. Possible values are: present, absent, latest. Default is present. | Optional | 
| gem_source | The path to a local gem used as installation source. | Optional | 
| include_dependencies | Whether to include dependencies or not. Default is yes. | Optional | 
| repository | The repository from which the gem will be installed. | Optional | 
| user_install | Install gem in user's local gems cache or for all users. Default is yes. | Optional | 
| executable | Override the path to the gem executable. | Optional | 
| install_dir | Install the gems into a specific directory. These gems will be independent from the global installed ones. Specifying this requires user_install to be false. | Optional | 
| env_shebang | Rewrite the shebang line on installed scripts to use /usr/bin/env. Default is no. | Optional | 
| version | Version of the gem to be installed/removed. | Optional | 
| pre_release | Allow installation of pre-release versions of the gem. Default is no. | Optional | 
| include_doc | Install with or without docs. Default is no. | Optional | 
| build_flags | Allow adding build flags for gem compilation. | Optional | 
| force | Force gem to install, bypassing dependency checks. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-maven-artifact
***
Downloads an Artifact from a Maven Repository
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/maven_artifact_module.html


#### Base Command

`linux-maven-artifact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| group_id | The Maven groupId coordinate. | Required | 
| artifact_id | The maven artifactId coordinate. | Required | 
| version | The maven version coordinate. Default is latest. | Optional | 
| classifier | The maven classifier coordinate. | Optional | 
| extension | The maven type/extension coordinate. Default is jar. | Optional | 
| repository_url | The URL of the Maven Repository to download from.<br/>Use s3://... if the repository is hosted on Amazon S3, added in version 2.2.<br/>Use file://... if the repository is local, added in version 2.6. Default is https://repo1.maven.org/maven2. | Optional | 
| username | The username to authenticate as to the Maven Repository. Use AWS secret key of the repository is hosted on S3. | Optional | 
| password | The password to authenticate with to the Maven Repository. Use AWS secret access key of the repository is hosted on S3. | Optional | 
| headers | Add custom HTTP headers to a request in hash/dict format. | Optional | 
| dest | The path where the artifact should be written to<br/>If file mode or ownerships are specified and destination path already exists, they affect the downloaded file. | Required | 
| state | The desired state of the artifact. Possible values are: present, absent. Default is present. | Optional | 
| timeout | Specifies a timeout in seconds for the connection attempt. Default is 10. | Optional | 
| validate_certs | If `no`, SSL certificates will not be validated. This should only be set to `no` when no other option exists. Default is yes. | Optional | 
| keep_name | If `yes`, the downloaded artifact's name is preserved, i.e the version number remains part of it.<br/>This option only has effect when `dest` is a directory and `version` is set to `latest`. Default is no. | Optional | 
| verify_checksum | If `never`, the md5 checksum will never be downloaded and verified.<br/>If `download`, the md5 checksum will be downloaded and verified only after artifact download. This is the default.<br/>If `change`, the md5 checksum will be downloaded and verified if the destination already exist, to verify if they are identical. This was the behaviour before 2.6. Since it downloads the md5 before (maybe) downloading the artifact, and since some repository software, when acting as a proxy/cache, return a 404 error if the artifact has not been cached yet, it may fail unexpectedly. If you still need it, you should consider using `always` instead - if you deal with a checksum, it is better to use it to verify integrity after download.<br/>`always` combines `download` and `change`. Possible values are: never, download, change, always. Default is download. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-npm
***
Manage node.js packages with npm
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/npm_module.html


#### Base Command

`linux-npm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of a node.js library to install. | Optional | 
| path | The base path where to install the node.js libraries. | Optional | 
| version | The version to be installed. | Optional | 
| global | Install the node.js library globally. Possible values are: Yes, No. Default is No. | Optional | 
| executable | The executable location for npm.<br/>This is useful if you are using a version manager, such as nvm. | Optional | 
| ignore_scripts | Use the `--ignore-scripts` flag when installing. Possible values are: Yes, No. Default is No. | Optional | 
| unsafe_perm | Use the `--unsafe-perm` flag when installing. Possible values are: Yes, No. Default is No. | Optional | 
| ci | Install packages based on package-lock file, same as running npm ci. Possible values are: Yes, No. Default is No. | Optional | 
| production | Install dependencies in production mode, excluding devDependencies. Possible values are: Yes, No. Default is No. | Optional | 
| registry | The registry to install modules from. | Optional | 
| state | The state of the node.js library. Possible values are: present, absent, latest. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-pear
***
Manage pear/pecl packages
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/pear_module.html


#### Base Command

`linux-pear`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the package to install, upgrade, or remove. | Required | 
| state | Desired state of the package. Possible values are: present, absent, latest. Default is present. | Optional | 
| executable | Path to the pear executable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-pip
***
Manages Python library dependencies
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/pip_module.html


#### Base Command

`linux-pip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of a Python library to install or the url(bzr+,hg+,git+,svn+) of the remote package.<br/>This can be a list (since 2.2) and contain version specifiers (since 2.7). | Optional | 
| version | The version number to install of the Python library specified in the `name` parameter. | Optional | 
| requirements | The path to a pip requirements file, which should be local to the remote system. File can be specified as a relative path if using the chdir option. | Optional | 
| virtualenv | An optional path to a `virtualenv` directory to install into. It cannot be specified together with the 'executable' parameter (added in 2.1). If the virtualenv does not exist, it will be created before installing packages. The optional virtualenv_site_packages, virtualenv_command, and virtualenv_python options affect the creation of the virtualenv. | Optional | 
| virtualenv_site_packages | Whether the virtual environment will inherit packages from the global site-packages directory.  Note that if this setting is changed on an already existing virtual environment it will not have any effect, the environment must be deleted and newly created. Default is no. | Optional | 
| virtualenv_command | The command or a pathname to the command to create the virtual environment with. For example `pyvenv`, `virtualenv`, `virtualenv2`, `~/bin/virtualenv`, `/usr/local/bin/virtualenv`. Default is virtualenv. | Optional | 
| virtualenv_python | The Python executable used for creating the virtual environment. For example `python3.5`, `python2.7`. When not specified, the Python version used to run the ansible module is used. This parameter should not be used when `virtualenv_command` is using `pyvenv` or the `-m venv` module. | Optional | 
| state | The state of module<br/>The 'forcereinstall' option is only available in Ansible 2.1 and above. Possible values are: absent, forcereinstall, latest, present. Default is present. | Optional | 
| extra_args | Extra arguments passed to pip. | Optional | 
| editable | Pass the editable flag. Default is no. | Optional | 
| chdir | cd into this directory before running the command. | Optional | 
| executable | The explicit executable or pathname for the pip executable, if different from the Ansible Python interpreter. For example `pip3.3`, if there are both Python 2.7 and 3.3 installations in the system and you want to run pip for the Python 3.3 installation.<br/>Mutually exclusive with `virtualenv` (added in 2.1).<br/>Does not affect the Ansible Python interpreter.<br/>The setuptools package must be installed for both the Ansible Python interpreter and for the version of Python specified by this option. | Optional | 
| umask | The system umask to apply before installing the pip package. This is useful, for example, when installing on systems that have a very restrictive umask by default (e.g., "0077") and you want to pip install packages which are to be used by all users. Note that this requires you to specify desired umask mode as an octal string, (e.g., "0022"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Pip.cmd | string | pip command used by the module | 
| Linux.Pip.name | unknown | list of python modules targetted by pip | 
| Linux.Pip.requirements | string | Path to the requirements file | 
| Linux.Pip.version | string | Version of the package specified in 'name' | 
| Linux.Pip.virtualenv | string | Path to the virtualenv | 


#### Command Example
```!linux-pip host="123.123.123.123" name="bottle" ```

#### Context Example
```json
{
    "Linux": {
        "Pip": {
            "changed": false,
            "cmd": [
                "/usr/bin/pip3",
                "install",
                "bottle"
            ],
            "host": "123.123.123.123",
            "name": [
                "bottle"
            ],
            "requirements": null,
            "state": "present",
            "status": "SUCCESS",
            "stderr": "WARNING: Running pip install with root privileges is generally not a good idea. Try `pip3 install --user` instead.\n",
            "stderr_lines": [
                "WARNING: Running pip install with root privileges is generally not a good idea. Try `pip3 install --user` instead."
            ],
            "stdout": "Requirement already satisfied: bottle in /usr/local/lib/python3.6/site-packages\n",
            "stdout_lines": [
                "Requirement already satisfied: bottle in /usr/local/lib/python3.6/site-packages"
            ],
            "version": null,
            "virtualenv": null
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * requirements: None
>  * state: present
>  * stderr: WARNING: Running pip install with root privileges is generally not a good idea. Try `pip3 install --user` instead.
>
>  * stdout: Requirement already satisfied: bottle in /usr/local/lib/python3.6/site-packages
>
>  * version: None
>  * virtualenv: None
>  * ## Cmd
>    * 0: /usr/bin/pip3
>    * 1: install
>    * 2: bottle
>  * ## Name
>    * 0: bottle
>  * ## Stderr_Lines
>    * 0: WARNING: Running pip install with root privileges is generally not a good idea. Try `pip3 install --user` instead.
>  * ## Stdout_Lines
>    * 0: Requirement already satisfied: bottle in /usr/local/lib/python3.6/site-packages


### linux-pip-package-info
***
pip package information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/pip_package_info_module.html


#### Base Command

`linux-pip-package-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| clients | A list of the pip executables that will be used to get the packages. They can be supplied with the full path or just the executable name, i.e `pip3.7`. Default is ['pip']. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.PipPackageInfo.packages | unknown | a dictionary of installed package data | 



### linux-yarn
***
Manage node.js packages with Yarn
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/yarn_module.html


#### Base Command

`linux-yarn`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of a node.js library to install<br/>If omitted all packages in package.json are installed. | Optional | 
| path | The base path where Node.js libraries will be installed.<br/>This is where the node_modules folder lives. | Optional | 
| version | The version of the library to be installed.<br/>Must be in semver format. If "latest" is desired, use "state" arg instead. | Optional | 
| global | Install the node.js library globally. Possible values are: Yes, No. Default is No. | Optional | 
| executable | The executable location for yarn. | Optional | 
| ignore_scripts | Use the --ignore-scripts flag when installing. Possible values are: Yes, No. Default is No. | Optional | 
| production | Install dependencies in production mode.<br/>Yarn will ignore any dependencies under devDependencies in package.json. Possible values are: Yes, No. Default is No. | Optional | 
| registry | The registry to install modules from. | Optional | 
| state | Installation state of the named node.js library<br/>If absent is selected, a name option must be provided. Possible values are: present, absent, latest. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Yarn.changed | boolean | Whether Yarn changed any package data | 
| Linux.Yarn.msg | string | Provides an error message if Yarn syntax was incorrect | 
| Linux.Yarn.invocation | unknown | Parameters and values used during execution | 
| Linux.Yarn.out | string | Output generated from Yarn with emojis removed. | 



### linux-apk
***
Manages apk packages
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/apk_module.html


#### Base Command

`linux-apk`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| available | During upgrade, reset versioned world dependencies and change logic to prefer replacing or downgrading packages (instead of holding them) if the currently installed package is no longer available from any repository. Default is no. | Optional | 
| name | A package name, like `foo`, or multiple packages, like `foo, bar`. | Optional | 
| repository | A package repository or multiple repositories. Unlike with the underlying apk command, this list will override the system repositories rather than supplement them. | Optional | 
| state | Indicates the desired package(s) state.<br/>`present` ensures the package(s) is/are present.<br/>`absent` ensures the package(s) is/are absent.<br/>`latest` ensures the package(s) is/are present and the latest version(s). Possible values are: present, absent, latest. Default is present. | Optional | 
| update_cache | Update repository indexes. Can be run with other steps or on it's own. Default is no. | Optional | 
| upgrade | Upgrade all installed packages to their latest version. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Apk.packages | unknown | a list of packages that have been changed | 



### linux-apt
***
Manages apt-packages
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/apt_module.html


#### Base Command

`linux-apt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | A list of package names, like `foo`, or package specifier with version, like `foo=1.0`. Name wildcards (fnmatch) like `apt*` and version wildcards like `foo=1.0*` are also supported. | Optional | 
| state | Indicates the desired package state. `latest` ensures that the latest version is installed. `build-dep` ensures the package build dependencies are installed. `fixed` attempt to correct a system with broken dependencies in place. Possible values are: absent, build-dep, latest, present, fixed. Default is present. | Optional | 
| update_cache | Run the equivalent of `apt-get update` before the operation. Can be run as part of the package installation or as a separate step. Default is no. | Optional | 
| cache_valid_time | Update the apt cache if its older than the `cache_valid_time`. This option is set in seconds.<br/>As of Ansible 2.4, if explicitly set, this sets `update_cache=yes`. Default is 0. | Optional | 
| purge | Will force purging of configuration files if the module state is set to `absent`. Default is no. | Optional | 
| default_release | Corresponds to the `-t` option for `apt` and sets pin priorities. | Optional | 
| install_recommends | Corresponds to the `--no-install-recommends` option for `apt`. `yes` installs recommended packages.  `no` does not install recommended packages. By default, Ansible will use the same defaults as the operating system. Suggested packages are never installed. | Optional | 
| force | Corresponds to the `--force-yes` to `apt-get` and implies `allow_unauthenticated: yes`<br/>This option will disable checking both the packages' signatures and the certificates of the web servers they are downloaded from.<br/>This option *is not* the equivalent of passing the `-f` flag to `apt-get` on the command line<br/>**This is a destructive operation with the potential to destroy your system, and it should almost never be used.** Please also see `man apt-get` for more information. Default is no. | Optional | 
| allow_unauthenticated | Ignore if packages cannot be authenticated. This is useful for bootstrapping environments that manage their own apt-key setup.<br/>`allow_unauthenticated` is only supported with state: `install`/`present`. Default is no. | Optional | 
| upgrade | If yes or safe, performs an aptitude safe-upgrade.<br/>If full, performs an aptitude full-upgrade.<br/>If dist, performs an apt-get dist-upgrade.<br/>Note: This does not upgrade a specific package, use state=latest for that.<br/>Note: Since 2.4, apt-get is used as a fall-back if aptitude is not present. Possible values are: dist, full, no, safe, yes. Default is no. | Optional | 
| dpkg_options | Add dpkg options to apt command. Defaults to '-o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"'<br/>Options should be supplied as comma separated list. Default is force-confdef,force-confold. | Optional | 
| deb | Path to a .deb package on the remote machine.<br/>If :// in the path, ansible will attempt to download deb before installing. (Version added 2.1)<br/>Requires the `xz-utils` package to extract the control file of the deb package to install. | Optional | 
| autoremove | If `yes`, remove unused dependency packages for all module states except `build-dep`. It can also be used as the only option.<br/>Previous to version 2.4, autoclean was also an alias for autoremove, now it is its own separate command. See documentation for further information. Default is no. | Optional | 
| autoclean | If `yes`, cleans the local repository of retrieved package files that can no longer be downloaded. Default is no. | Optional | 
| policy_rc_d | Force the exit code of /usr/sbin/policy-rc.d.<br/>For example, if `policy_rc_d=101` the installed package will not trigger a service start.<br/>If /usr/sbin/policy-rc.d already exist, it is backed up and restored after the package installation.<br/>If `null`, the /usr/sbin/policy-rc.d isn't created/changed. | Optional | 
| only_upgrade | Only upgrade a package if it is already installed. Default is no. | Optional | 
| force_apt_get | Force usage of apt-get instead of aptitude. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Apt.cache_updated | boolean | if the cache was updated or not | 
| Linux.Apt.cache_update_time | number | time of the last cache update \(0 if unknown\) | 
| Linux.Apt.stdout | string | output from apt | 
| Linux.Apt.stderr | string | error output from apt | 



### linux-apt-key
***
Add or remove an apt key
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/apt_key_module.html


#### Base Command

`linux-apt-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| id | The identifier of the key.<br/>Including this allows check mode to correctly report the changed state.<br/>If specifying a subkey's id be aware that apt-key does not understand how to remove keys via a subkey id.  Specify the primary key's id instead.<br/>This parameter is required when `state` is set to `absent`. | Optional | 
| data | The keyfile contents to add to the keyring. | Optional | 
| file | The path to a keyfile on the remote server to add to the keyring. | Optional | 
| keyring | The full path to specific keyring file in /etc/apt/trusted.gpg.d/. | Optional | 
| url | The URL to retrieve key from. | Optional | 
| keyserver | The keyserver to retrieve key from. | Optional | 
| state | Ensures that the key is present (added) or absent (revoked). Possible values are: absent, present. Default is present. | Optional | 
| validate_certs | If `no`, SSL certificates for the target url will not be validated. This should only be used on personally controlled sites using self-signed certificates. Default is yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-apt-repo
***
Manage APT repositories via apt-repo
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/apt_repo_module.html


#### Base Command

`linux-apt-repo`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| repo | Name of the repository to add or remove. | Required | 
| state | Indicates the desired repository state. Possible values are: absent, present. Default is present. | Optional | 
| remove_others | Remove other then added repositories<br/>Used if `state=present`. Default is no. | Optional | 
| update | Update the package database after changing repositories. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-apt-repository
***
Add and remove APT repositories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/apt_repository_module.html


#### Base Command

`linux-apt-repository`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| repo | A source string for the repository. | Required | 
| state | A source string state. Possible values are: absent, present. Default is present. | Optional | 
| mode | The octal mode for newly created files in sources.list.d. Default is 0644. | Optional | 
| update_cache | Run the equivalent of `apt-get update` when a change occurs.  Cache updates are run after making changes. Default is yes. | Optional | 
| validate_certs | If `no`, SSL certificates for the target repo will not be validated. This should only be used on personally controlled sites using self-signed certificates. Default is yes. | Optional | 
| filename | Sets the name of the source list file in sources.list.d. Defaults to a file name based on the repository source url. The .list extension will be automatically added. | Optional | 
| codename | Override the distribution codename to use for PPA repositories. Should usually only be set when working with a PPA on a non-Ubuntu target (e.g. Debian or Mint). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-apt-rpm
***
apt_rpm package manager
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/apt_rpm_module.html


#### Base Command

`linux-apt-rpm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| pkg | name of package to install, upgrade or remove. | Required | 
| state | Indicates the desired package state. Possible values are: absent, present. Default is present. | Optional | 
| update_cache | update the package database first `apt-get update`. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-dpkg-selections
***
Dpkg package selection selections
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/dpkg_selections_module.html


#### Base Command

`linux-dpkg-selections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the package. | Required | 
| selection | The selection state to set the package to. Possible values are: install, hold, deinstall, purge. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


### linux-flatpak
***
Manage flatpaks
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/flatpak_module.html


#### Base Command

`linux-flatpak`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| executable | The path to the `flatpak` executable to use.<br/>By default, this module looks for the `flatpak` executable on the path. Default is flatpak. | Optional | 
| method | The installation method to use.<br/>Defines if the `flatpak` is supposed to be installed globally for the whole `system` or only for the current `user`. Possible values are: system, user. Default is system. | Optional | 
| name | The name of the flatpak to manage.<br/>When used with `state=present`, `name` can be specified as an `http(s`) URL to a `flatpakref` file or the unique reverse DNS name that identifies a flatpak.<br/>When supplying a reverse DNS name, you can use the `remote` option to specify on what remote to look for the flatpak. An example for a reverse DNS name is `org.gnome.gedit`.<br/>When used with `state=absent`, it is recommended to specify the name in the reverse DNS format.<br/>When supplying an `http(s`) URL with `state=absent`, the module will try to match the installed flatpak based on the name of the flatpakref to remove it. However, there is no guarantee that the names of the flatpakref file and the reverse DNS name of the installed flatpak do match. | Required | 
| remote | The flatpak remote (repository) to install the flatpak from.<br/>By default, `flathub` is assumed, but you do need to add the flathub flatpak_remote before you can use this.<br/>See the `flatpak_remote` module for managing flatpak remotes. Default is flathub. | Optional | 
| state | Indicates the desired package state. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Flatpak.command | string | The exact flatpak command that was executed | 
| Linux.Flatpak.msg | string | Module error message | 
| Linux.Flatpak.rc | number | Return code from flatpak binary | 
| Linux.Flatpak.stderr | string | Error output from flatpak binary | 
| Linux.Flatpak.stdout | string | Output from flatpak binary | 



### linux-flatpak-remote
***
Manage flatpak repository remotes
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/flatpak_remote_module.html


#### Base Command

`linux-flatpak-remote`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| executable | The path to the `flatpak` executable to use.<br/>By default, this module looks for the `flatpak` executable on the path. Default is flatpak. | Optional | 
| flatpakrepo_url | The URL to the `flatpakrepo` file representing the repository remote to add.<br/>When used with `state=present`, the flatpak remote specified under the `flatpakrepo_url` is added using the specified installation `method`.<br/>When used with `state=absent`, this is not required.<br/>Required when `state=present`. | Optional | 
| method | The installation method to use.<br/>Defines if the `flatpak` is supposed to be installed globally for the whole `system` or only for the current `user`. Possible values are: system, user. Default is system. | Optional | 
| name | The desired name for the flatpak remote to be registered under on the managed host.<br/>When used with `state=present`, the remote will be added to the managed host under the specified `name`.<br/>When used with `state=absent` the remote with that name will be removed. | Required | 
| state | Indicates the desired package state. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.FlatpakRemote.command | string | The exact flatpak command that was executed | 
| Linux.FlatpakRemote.msg | string | Module error message | 
| Linux.FlatpakRemote.rc | number | Return code from flatpak binary | 
| Linux.FlatpakRemote.stderr | string | Error output from flatpak binary | 
| Linux.FlatpakRemote.stdout | string | Output from flatpak binary | 



### linux-homebrew
***
Package manager for Homebrew
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/homebrew_module.html


#### Base Command

`linux-homebrew`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | list of names of packages to install/remove. | Optional | 
| path | A ':' separated list of paths to search for 'brew' executable. Since a package (`formula` in homebrew parlance) location is prefixed relative to the actual path of `brew` command, providing an alternative `brew` path enables managing different set of packages in an alternative location in the system. Default is /usr/local/bin. | Optional | 
| state | state of the package. Possible values are: head, latest, present, absent, linked, unlinked. Default is present. | Optional | 
| update_homebrew | update homebrew itself first. Default is no. | Optional | 
| upgrade_all | upgrade all homebrew packages. Default is no. | Optional | 
| install_options | options flags to install a package. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-homebrew-cask
***
Install/uninstall homebrew casks.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/homebrew_cask_module.html


#### Base Command

`linux-homebrew-cask`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | name of cask to install/remove. | Required | 
| path | ':' separated list of paths to search for 'brew' executable. Default is /usr/local/bin. | Optional | 
| state | state of the cask. Possible values are: present, absent, upgraded. Default is present. | Optional | 
| sudo_password | The sudo password to be passed to SUDO_ASKPASS. | Optional | 
| update_homebrew | update homebrew itself first. Note that `brew cask update` is a synonym for `brew update`. Default is no. | Optional | 
| install_options | options flags to install a package. | Optional | 
| accept_external_apps | allow external apps. Default is no. | Optional | 
| upgrade_all | upgrade all casks (mutually exclusive with `upgrade`). Default is no. | Optional | 
| upgrade | upgrade all casks (mutually exclusive with `upgrade_all`). Default is no. | Optional | 
| greedy | upgrade casks that auto update; passes --greedy to brew cask outdated when checking if an installed cask has a newer version available. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-homebrew-tap
***
Tap a Homebrew repository.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/homebrew_tap_module.html


#### Base Command

`linux-homebrew-tap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The GitHub user/organization repository to tap. | Required | 
| url | The optional git URL of the repository to tap. The URL is not assumed to be on GitHub, and the protocol doesn't have to be HTTP. Any location and protocol that git can handle is fine.<br/>`name` option may not be a list of multiple taps (but a single tap instead) when this option is provided. | Optional | 
| state | state of the repository. Possible values are: present, absent. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-layman
***
Manage Gentoo overlays
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/layman_module.html


#### Base Command

`linux-layman`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The overlay id to install, synchronize, or uninstall. Use 'ALL' to sync all of the installed overlays (can be used only when `state=updated`). | Required | 
| list_url | An URL of the alternative overlays list that defines the overlay to install. This list will be fetched and saved under `${overlay_defs}`/${name}.xml), where `overlay_defs` is readed from the Layman's configuration. | Optional | 
| state | Whether to install (`present`), sync (`updated`), or uninstall (`absent`) the overlay. Possible values are: present, absent, updated. Default is present. | Optional | 
| validate_certs | If `no`, SSL certificates will not be validated. This should only be set to `no` when no other option exists.  Prior to 1.9.3 the code defaulted to `no`. Default is yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-package
***
Generic OS package manager
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/package_module.html


#### Base Command

`linux-package`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Package name, or package specifier with version.<br/>Syntax varies with package manager. For example `name-1.0` or `name=1.0`.<br/>Package names also vary with package manager; this module will not "translate" them per distro. For example `libyaml-dev`, `libyaml-devel`. | Required | 
| state | Whether to install (`present`), or remove (`absent`) a package.<br/>You can use other states like `latest` ONLY if they are supported by the underlying package module(s) executed. | Required | 
| use | The required package manager module to use (yum, apt, etc). The default 'auto' will use existing facts or try to autodetect it.<br/>You should only use this field if the automatic selection is not working for some reason. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-package-facts
***
package information as facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/package_facts_module.html


#### Base Command

`linux-package-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| manager | The package manager used by the system so we can query the package information.<br/>Since 2.8 this is a list and can support multiple package managers per system.<br/>The 'portage' and 'pkg' options were added in version 2.8. Possible values are: auto, rpm, apt, portage, pkg. Default is ['auto']. | Optional | 
| strategy | This option controls how the module queries the package managers on the system. `first` means it will return only information for the first supported package manager available. `all` will return information for all supported and available package managers on the system. Possible values are: first, all. Default is first. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.PackageFacts.facts | unknown | facts to add to facts | 


#### Command Example
```!linux-package-facts host="123.123.123.123" manager="auto" ```

#### Context Example
```json
{
    "Linux": {
        "PackageFacts": {
            "discovered_interpreter_python": "/usr/libexec/platform-python",
            "host": "123.123.123.123",
            "packages": {
                "GConf2": [
                    {
                        "arch": "x86_64",
                        "epoch": null,
                        "name": "GConf2",
                        "release": "22.el8",
                        "source": "rpm",
                        "version": "3.2.6"
                    }
                ],
                "NetworkManager": [
                    {
                        "arch": "x86_64",
                        "epoch": 1,
                        "name": "NetworkManager",
                        "release": "5.el8_2",
                        "source": "rpm",
                        "version": "1.22.8"
                    }
                ],
                "NetworkManager-libnm": [
                    {
                        "arch": "x86_64",
                        "epoch": 1,
                        "name": "NetworkManager-libnm",
                        "release": "5.el8_2",
                        "source": "rpm",
                        "version": "1.22.8"
                    }
                ]
            },
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * discovered_interpreter_python: /usr/libexec/platform-python
>  * ## Packages
>    * ### Gconf2
>    * ### Gconf2
>      * arch: x86_64
>      * epoch: None
>      * name: GConf2
>      * release: 22.el8
>      * source: rpm
>      * version: 3.2.6
>    * ### Networkmanager
>    * ### Networkmanager
>      * arch: x86_64
>      * epoch: 1
>      * name: NetworkManager
>      * release: 5.el8_2
>      * source: rpm
>      * version: 1.22.8
>    * ### Networkmanager-Libnm
>    * ### Networkmanager-Libnm
>      * arch: x86_64
>      * epoch: 1
>      * name: NetworkManager-libnm
>      * release: 5.el8_2
>      * source: rpm
>      * version: 1.22.8



### linux-yum
***
Manages packages with the I(yum) package manager
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/yum_module.html


#### Base Command

`linux-yum`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| use_backend | This module supports `yum` (as it always has), this is known as `yum3`/`YUM3`/`yum-deprecated` by upstream yum developers. As of Ansible 2.7+, this module also supports `YUM4`, which is the "new yum" and it has an `dnf` backend.<br/>By default, this module will select the backend based on the `pkg_mgr` fact. Possible values are: auto, yum, yum4, dnf. Default is auto. | Optional | 
| name | A package name or package specifier with version, like `name-1.0`.<br/>If a previous version is specified, the task also needs to turn `allow_downgrade` on. See the `allow_downgrade` documentation for caveats with downgrading packages.<br/>When using state=latest, this can be `'*'` which means run `yum -y update`.<br/>You can also pass a url or a local path to a rpm file (using state=present). To operate on several packages this can accept a comma separated string of packages or (as of 2.0) a list of packages. | Optional | 
| exclude | Package name(s) to exclude when state=present, or latest. | Optional | 
| list | Package name to run the equivalent of yum list --show-duplicates &lt;package&gt; against. In addition to listing packages, use can also list the following: `installed`, `updates`, `available` and `repos`.<br/>This parameter is mutually exclusive with `name`. | Optional | 
| state | Whether to install (`present` or `installed`, `latest`), or remove (`absent` or `removed`) a package.<br/>`present` and `installed` will simply ensure that a desired package is installed.<br/>`latest` will update the specified package if it's not of the latest available version.<br/>`absent` and `removed` will remove the specified package.<br/>Default is `None`, however in effect the default action is `present` unless the `autoremove` option is enabled for this module, then `absent` is inferred. Possible values are: absent, installed, latest, present, removed. | Optional | 
| enablerepo | `Repoid` of repositories to enable for the install/update operation. These repos will not persist beyond the transaction. When specifying multiple repos, separate them with a `","`.<br/>As of Ansible 2.7, this can alternatively be a list instead of `","` separated string. | Optional | 
| disablerepo | `Repoid` of repositories to disable for the install/update operation. These repos will not persist beyond the transaction. When specifying multiple repos, separate them with a `","`.<br/>As of Ansible 2.7, this can alternatively be a list instead of `","` separated string. | Optional | 
| conf_file | The remote yum configuration file to use for the transaction. | Optional | 
| disable_gpg_check | Whether to disable the GPG checking of signatures of packages being installed. Has an effect only if state is `present` or `latest`. Default is no. | Optional | 
| skip_broken | Skip packages with broken dependencies(devsolve) and are causing problems. Default is no. | Optional | 
| update_cache | Force yum to check if cache is out of date and redownload if needed. Has an effect only if state is `present` or `latest`. Default is no. | Optional | 
| validate_certs | This only applies if using a https url as the source of the rpm. e.g. for localinstall. If set to `no`, the SSL certificates will not be validated.<br/>This should only set to `no` used on personally controlled sites using self-signed certificates as it avoids verifying the source site.<br/>Prior to 2.1 the code worked as if this was set to `yes`. Default is yes. | Optional | 
| update_only | When using latest, only update installed packages. Do not install packages.<br/>Has an effect only if state is `latest`. Default is no. | Optional | 
| installroot | Specifies an alternative installroot, relative to which all packages will be installed. Default is /. | Optional | 
| security | If set to `yes`, and `state=latest` then only installs updates that have been marked security related. Default is no. | Optional | 
| bugfix | If set to `yes`, and `state=latest` then only installs updates that have been marked bugfix related. Default is no. | Optional | 
| allow_downgrade | Specify if the named package and version is allowed to downgrade a maybe already installed higher version of that package. Note that setting allow_downgrade=True can make this module behave in a non-idempotent way. The task could end up with a set of packages that does not match the complete list of specified packages to install (because dependencies between the downgraded package and others can cause changes to the packages which were in the earlier transaction). Default is no. | Optional | 
| enable_plugin | `Plugin` name to enable for the install/update operation. The enabled plugin will not persist beyond the transaction. | Optional | 
| disable_plugin | `Plugin` name to disable for the install/update operation. The disabled plugins will not persist beyond the transaction. | Optional | 
| releasever | Specifies an alternative release from which all packages will be installed. | Optional | 
| autoremove | If `yes`, removes all "leaf" packages from the system that were originally installed as dependencies of user-installed packages but which are no longer required by any such package. Should be used alone or when state is `absent`<br/>NOTE: This feature requires yum &gt;= 3.4.3 (RHEL/CentOS 7+). Default is no. | Optional | 
| disable_excludes | Disable the excludes defined in YUM config files.<br/>If set to `all`, disables all excludes.<br/>If set to `main`, disable excludes defined in [main] in yum.conf.<br/>If set to `repoid`, disable excludes defined for given repo id. | Optional | 
| download_only | Only download the packages, do not install them. Default is no. | Optional | 
| lock_timeout | Amount of time to wait for the yum lockfile to be freed. Default is 30. | Optional | 
| install_weak_deps | Will also install all packages linked by a weak dependency relation.<br/>NOTE: This feature requires yum &gt;= 4 (RHEL/CentOS 8+). Default is yes. | Optional | 
| download_dir | Specifies an alternate directory to store packages.<br/>Has an effect only if `download_only` is specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-yum-repository
***
Add or remove YUM repositories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/yum_repository_module.html


#### Base Command

`linux-yum-repository`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| async | If set to `yes` Yum will download packages and metadata from this repo in parallel, if possible. Default is yes. | Optional | 
| bandwidth | Maximum available network bandwidth in bytes/second. Used with the `throttle` option.<br/>If `throttle` is a percentage and bandwidth is `0` then bandwidth throttling will be disabled. If `throttle` is expressed as a data rate (bytes/sec) then this option is ignored. Default is `0` (no bandwidth throttling). Default is 0. | Optional | 
| baseurl | URL to the directory where the yum repository's 'repodata' directory lives.<br/>It can also be a list of multiple URLs.<br/>This, the `metalink` or `mirrorlist` parameters are required if `state` is set to `present`. | Optional | 
| cost | Relative cost of accessing this repository. Useful for weighing one repo's packages as greater/less than any other. Default is 1000. | Optional | 
| deltarpm_metadata_percentage | When the relative size of deltarpm metadata vs pkgs is larger than this, deltarpm metadata is not downloaded from the repo. Note that you can give values over `100`, so `200` means that the metadata is required to be half the size of the packages. Use `0` to turn off this check, and always download metadata. Default is 100. | Optional | 
| deltarpm_percentage | When the relative size of delta vs pkg is larger than this, delta is not used. Use `0` to turn off delta rpm processing. Local repositories (with file:// `baseurl`) have delta rpms turned off by default. Default is 75. | Optional | 
| description | A human readable string describing the repository. This option corresponds to the "name" property in the repo file.<br/>This parameter is only required if `state` is set to `present`. | Optional | 
| enabled | This tells yum whether or not use this repository. Default is yes. | Optional | 
| enablegroups | Determines whether yum will allow the use of package groups for this repository. Default is yes. | Optional | 
| exclude | List of packages to exclude from updates or installs. This should be a space separated list. Shell globs using wildcards (eg. `*` and `?`) are allowed.<br/>The list can also be a regular YAML array. | Optional | 
| failovermethod | `roundrobin` randomly selects a URL out of the list of URLs to start with and proceeds through each of them as it encounters a failure contacting the host.<br/>`priority` starts from the first `baseurl` listed and reads through them sequentially. Possible values are: roundrobin, priority. Default is roundrobin. | Optional | 
| file | File name without the `.repo` extension to save the repo in. Defaults to the value of `name`. | Optional | 
| gpgcakey | A URL pointing to the ASCII-armored CA key file for the repository. | Optional | 
| gpgcheck | Tells yum whether or not it should perform a GPG signature check on packages.<br/>No default setting. If the value is not set, the system setting from `/etc/yum.conf` or system default of `no` will be used. | Optional | 
| gpgkey | A URL pointing to the ASCII-armored GPG key file for the repository.<br/>It can also be a list of multiple URLs. | Optional | 
| http_caching | Determines how upstream HTTP caches are instructed to handle any HTTP downloads that Yum does.<br/>`all` means that all HTTP downloads should be cached.<br/>`packages` means that only RPM package downloads should be cached (but not repository metadata downloads).<br/>`none` means that no HTTP downloads should be cached. Possible values are: all, packages, none. Default is all. | Optional | 
| include | Include external configuration file. Both, local path and URL is supported. Configuration file will be inserted at the position of the `include=` line. Included files may contain further include lines. Yum will abort with an error if an inclusion loop is detected. | Optional | 
| includepkgs | List of packages you want to only use from a repository. This should be a space separated list. Shell globs using wildcards (eg. `*` and `?`) are allowed. Substitution variables (e.g. `$releasever`) are honored here.<br/>The list can also be a regular YAML array. | Optional | 
| ip_resolve | Determines how yum resolves host names.<br/>`4` or `IPv4` - resolve to IPv4 addresses only.<br/>`6` or `IPv6` - resolve to IPv6 addresses only. Possible values are: 4, 6, IPv4, IPv6, whatever. Default is whatever. | Optional | 
| keepalive | This tells yum whether or not HTTP/1.1 keepalive should be used with this repository. This can improve transfer speeds by using one connection when downloading multiple files from a repository. Default is no. | Optional | 
| keepcache | Either `1` or `0`. Determines whether or not yum keeps the cache of headers and packages after successful installation. Possible values are: 0, 1. Default is 1. | Optional | 
| metadata_expire | Time (in seconds) after which the metadata will expire.<br/>Default value is 6 hours. Default is 21600. | Optional | 
| metadata_expire_filter | Filter the `metadata_expire` time, allowing a trade of speed for accuracy if a command doesn't require it. Each yum command can specify that it requires a certain level of timeliness quality from the remote repos. from "I'm about to install/upgrade, so this better be current" to "Anything that's available is good enough".<br/>`never` - Nothing is filtered, always obey `metadata_expire`.<br/>`read-only:past` - Commands that only care about past information are filtered from metadata expiring. Eg. `yum history` info (if history needs to lookup anything about a previous transaction, then by definition the remote package was available in the past).<br/>`read-only:present` - Commands that are balanced between past and future. Eg. `yum list yum`.<br/>`read-only:future` - Commands that are likely to result in running other commands which will require the latest metadata. Eg. `yum check-update`.<br/>Note that this option does not override "yum clean expire-cache". Possible values are: never, read-only:past, read-only:present, read-only:future. Default is read-only:present. | Optional | 
| metalink | Specifies a URL to a metalink file for the repomd.xml, a list of mirrors for the entire repository are generated by converting the mirrors for the repomd.xml file to a `baseurl`.<br/>This, the `baseurl` or `mirrorlist` parameters are required if `state` is set to `present`. | Optional | 
| mirrorlist | Specifies a URL to a file containing a list of baseurls.<br/>This, the `baseurl` or `metalink` parameters are required if `state` is set to `present`. | Optional | 
| mirrorlist_expire | Time (in seconds) after which the mirrorlist locally cached will expire.<br/>Default value is 6 hours. Default is 21600. | Optional | 
| name | Unique repository ID. This option builds the section name of the repository in the repo file.<br/>This parameter is only required if `state` is set to `present` or `absent`. | Required | 
| password | Password to use with the username for basic authentication. | Optional | 
| priority | Enforce ordered protection of repositories. The value is an integer from 1 to 99.<br/>This option only works if the YUM Priorities plugin is installed. Default is 99. | Optional | 
| protect | Protect packages from updates from other repositories. Default is no. | Optional | 
| proxy | URL to the proxy server that yum should use. Set to `_none_` to disable the global proxy setting. | Optional | 
| proxy_password | Password for this proxy. | Optional | 
| proxy_username | Username to use for proxy. | Optional | 
| repo_gpgcheck | This tells yum whether or not it should perform a GPG signature check on the repodata from this repository. Default is no. | Optional | 
| reposdir | Directory where the `.repo` files will be stored. Default is /etc/yum.repos.d. | Optional | 
| retries | Set the number of times any attempt to retrieve a file should retry before returning an error. Setting this to `0` makes yum try forever. Default is 10. | Optional | 
| s3_enabled | Enables support for S3 repositories.<br/>This option only works if the YUM S3 plugin is installed. Default is no. | Optional | 
| skip_if_unavailable | If set to `yes` yum will continue running if this repository cannot be contacted for any reason. This should be set carefully as all repos are consulted for any given command. Default is no. | Optional | 
| ssl_check_cert_permissions | Whether yum should check the permissions on the paths for the certificates on the repository (both remote and local).<br/>If we can't read any of the files then yum will force `skip_if_unavailable` to be `yes`. This is most useful for non-root processes which use yum on repos that have client cert files which are readable only by root. Default is no. | Optional | 
| sslcacert | Path to the directory containing the databases of the certificate authorities yum should use to verify SSL certificates. | Optional | 
| sslclientcert | Path to the SSL client certificate yum should use to connect to repos/remote sites. | Optional | 
| sslclientkey | Path to the SSL client key yum should use to connect to repos/remote sites. | Optional | 
| sslverify | Defines whether yum should verify SSL certificates/hosts at all. Default is yes. | Optional | 
| state | State of the repo file. Possible values are: absent, present. Default is present. | Optional | 
| throttle | Enable bandwidth throttling for downloads.<br/>This option can be expressed as a absolute data rate in bytes/sec. An SI prefix (k, M or G) may be appended to the bandwidth value. | Optional | 
| timeout | Number of seconds to wait for a connection before timing out. Default is 30. | Optional | 
| ui_repoid_vars | When a repository id is displayed, append these yum variables to the string if they are used in the `baseurl`/etc. Variables are appended in the order listed (and found). Default is releasever basearch. | Optional | 
| username | Username to use for basic authentication to a repo or really any url. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.YumRepository.repo | string | repository name | 
| Linux.YumRepository.state | string | state of the target, after execution | 


#### Command Example
```!linux-yum-repository host="123.123.123.123" name="epel" description="EPEL YUM repo" baseurl="https://download.fedoraproject.org/pub/epel/$releasever/$basearch/" ```

#### Context Example
```json
{
    "Linux": {
        "YumRepository": {
            "changed": false,
            "host": "123.123.123.123",
            "repo": "epel",
            "state": "present",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * repo: epel
>  * state: present


### linux-zypper
***
Manage packages on SUSE and openSUSE
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/zypper_module.html


#### Base Command

`linux-zypper`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Package name `name` or package specifier or a list of either.<br/>Can include a version like `name=1.0`, `name&gt;3.4` or `name&lt;=2.7`. If a version is given, `oldpackage` is implied and zypper is allowed to update the package within the version range given.<br/>You can also pass a url or a local path to a rpm file.<br/>When using state=latest, this can be '*', which updates all installed packages. | Required | 
| state | `present` will make sure the package is installed. `latest`  will make sure the latest version of the package is installed. `absent`  will make sure the specified package is not installed. `dist-upgrade` will make sure the latest version of all installed packages from all enabled repositories is installed.<br/>When using `dist-upgrade`, `name` should be `'*'`. Possible values are: present, latest, absent, dist-upgrade. Default is present. | Optional | 
| type | The type of package to be operated on. Possible values are: package, patch, pattern, product, srcpackage, application. Default is package. | Optional | 
| extra_args_precommand | Add additional global target options to `zypper`.<br/>Options should be supplied in a single line as if given in the command line. | Optional | 
| disable_gpg_check | Whether to disable to GPG signature checking of the package signature being installed. Has an effect only if state is `present` or `latest`. Default is no. | Optional | 
| disable_recommends | Corresponds to the `--no-recommends` option for `zypper`. Default behavior (`yes`) modifies zypper's default behavior; `no` does install recommended packages. Default is yes. | Optional | 
| force | Adds `--force` option to `zypper`. Allows to downgrade packages and change vendor or architecture. Default is no. | Optional | 
| update_cache | Run the equivalent of `zypper refresh` before the operation. Disabled in check mode. Default is no. | Optional | 
| oldpackage | Adds `--oldpackage` option to `zypper`. Allows to downgrade packages with less side-effects than force. This is implied as soon as a version is specified as part of the package name. Default is no. | Optional | 
| extra_args | Add additional options to `zypper` command.<br/>Options should be supplied in a single line as if given in the command line. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-zypper-repository
***
Add and remove Zypper repositories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/zypper_repository_module.html


#### Base Command

`linux-zypper-repository`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | A name for the repository. Not required when adding repofiles. | Optional | 
| repo | URI of the repository or .repo file. Required when state=present. | Optional | 
| state | A source string state. Possible values are: absent, present. Default is present. | Optional | 
| description | A description of the repository. | Optional | 
| disable_gpg_check | Whether to disable GPG signature checking of all packages. Has an effect only if state is `present`.<br/>Needs zypper version &gt;= 1.6.2. Default is no. | Optional | 
| autorefresh | Enable autorefresh of the repository. Default is yes. | Optional | 
| priority | Set priority of repository. Packages will always be installed from the repository with the smallest priority number.<br/>Needs zypper version &gt;= 1.12.25. | Optional | 
| overwrite_multiple | Overwrite multiple repository entries, if repositories with both name and URL already exist. Default is no. | Optional | 
| auto_import_keys | Automatically import the gpg signing key of the new or changed repository.<br/>Has an effect only if state is `present`. Has no effect on existing (unchanged) repositories or in combination with `absent`.<br/>Implies runrefresh.<br/>Only works with `.repo` files if `name` is given explicitly. Default is no. | Optional | 
| runrefresh | Refresh the package list of the given repository.<br/>Can be used with repo=* to refresh all repositories. Default is no. | Optional | 
| enabled | Set repository to enabled (or disabled). Default is yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-snap
***
Manages snaps
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/snap_module.html


#### Base Command

`linux-snap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the snap to install or remove. Can be a list of snaps. | Required | 
| state | Desired state of the package. Possible values are: absent, present. Default is present. | Optional | 
| classic | Confinement policy. The classic confinement allows a snap to have the same level of access to the system as "classic" packages, like those managed by APT. This option corresponds to the --classic argument. This option can only be specified if there is a single snap in the task. Possible values are: Yes, No. Default is No. | Optional | 
| channel | Define which release of a snap is installed and tracked for updates. This option can only be specified if there is a single snap in the task. Default is stable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.Snap.classic | boolean | Whether or not the snaps were installed with the classic confinement | 
| Linux.Snap.channel | string | The channel the snaps were installed from | 
| Linux.Snap.cmd | string | The command that was executed on the host | 
| Linux.Snap.snaps_installed | unknown | The list of actually installed snaps | 
| Linux.Snap.snaps_removed | unknown | The list of actually removed snaps | 



### linux-redhat-subscription
***
Manage registration and subscriptions to RHSM using the C(subscription-manager) command
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/redhat_subscription_module.html


#### Base Command

`linux-redhat-subscription`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | whether to register and subscribe (`present`), or unregister (`absent`) a system. Possible values are: present, absent. Default is present. | Optional | 
| username | access.Redhat.com or Sat6  username. | Optional | 
| password | access.Redhat.com or Sat6 password. | Optional | 
| server_hostname | Specify an alternative Red Hat Subscription Management or Sat6 server. | Optional | 
| server_insecure | Enable or disable https server certificate verification when connecting to `server_hostname`. | Optional | 
| rhsm_baseurl | Specify CDN baseurl. | Optional | 
| rhsm_repo_ca_cert | Specify an alternative location for a CA certificate for CDN. | Optional | 
| server_proxy_hostname | Specify a HTTP proxy hostname. | Optional | 
| server_proxy_port | Specify a HTTP proxy port. | Optional | 
| server_proxy_user | Specify a user for HTTP proxy with basic authentication. | Optional | 
| server_proxy_password | Specify a password for HTTP proxy with basic authentication. | Optional | 
| auto_attach | Upon successful registration, auto-consume available subscriptions<br/>Added in favor of deprecated autosubscribe in 2.5. Default is no. | Optional | 
| activationkey | supply an activation key for use with registration. | Optional | 
| org_id | Organization ID to use in conjunction with activationkey. | Optional | 
| environment | Register with a specific environment in the destination org. Used with Red Hat Satellite 6.x or Katello. | Optional | 
| pool | Specify a subscription pool name to consume.  Regular expressions accepted. Use `pool_ids` instead if<br/>possible, as it is much faster. Mutually exclusive with `pool_ids`. Default is ^$. | Optional | 
| pool_ids | Specify subscription pool IDs to consume. Prefer over `pool` when possible as it is much faster.<br/>A pool ID may be specified as a `string` - just the pool ID (ex. `0123456789abcdef0123456789abcdef`),<br/>or as a `dict` with the pool ID as the key, and a quantity as the value (ex.<br/>`0123456789abcdef0123456789abcdef: 2`. If the quantity is provided, it is used to consume multiple<br/>entitlements from a pool (the pool must support this). Mutually exclusive with `pool`. | Optional | 
| consumer_type | The type of unit to register, defaults to system. | Optional | 
| consumer_name | Name of the system to register, defaults to the hostname. | Optional | 
| consumer_id | References an existing consumer ID to resume using a previous registration<br/>for this system. If the  system's identity certificate is lost or corrupted,<br/>this option allows it to resume using its previous identity and subscriptions.<br/>The default is to not specify a consumer ID so a new ID is created. | Optional | 
| force_register | Register the system even if it is already registered. Default is no. | Optional | 
| release | Set a release version. | Optional | 
| syspurpose | Set syspurpose attributes in file `/etc/rhsm/syspurpose/syspurpose.json` and synchronize these attributes with RHSM server. Syspurpose attributes help attach the most appropriate subscriptions to the system automatically. When `syspurpose.json` file already contains some attributes, then new attributes overwrite existing attributes. When some attribute is not listed in the new list of attributes, the existing attribute will be removed from `syspurpose.json` file. Unknown attributes are ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.RedhatSubscription.subscribed_pool_ids | unknown | List of pool IDs to which system is now subscribed | 



### linux-rhn-channel
***
Adds or removes Red Hat software channels
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/rhn_channel_module.html


#### Base Command

`linux-rhn-channel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the software channel. | Required | 
| sysname | Name of the system as it is known in RHN/Satellite. | Required | 
| state | Whether the channel should be present or not, taking action if the state is different from what is stated. Default is present. | Optional | 
| url | The full URL to the RHN/Satellite API. | Required | 
| user | RHN/Satellite login. | Required | 
| password | RHN/Satellite password. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-rhn-register
***
Manage Red Hat Network registration using the C(rhnreg_ks) command
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/rhn_register_module.html


#### Base Command

`linux-rhn-register`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether to register (`present`), or unregister (`absent`) a system. Possible values are: absent, present. Default is present. | Optional | 
| username | Red Hat Network username. | Optional | 
| password | Red Hat Network password. | Optional | 
| server_url | Specify an alternative Red Hat Network server URL.<br/>The default is the current value of `serverURL` from `/etc/sysconfig/rhn/up2date`. | Optional | 
| activationkey | Supply an activation key for use with registration. | Optional | 
| profilename | Supply an profilename for use with registration. | Optional | 
| ca_cert | Supply a custom ssl CA certificate file for use with registration. | Optional | 
| systemorgid | Supply an organizational id for use with registration. | Optional | 
| channels | Optionally specify a list of channels to subscribe to upon successful registration. | Optional | 
| enable_eus | If `no`, extended update support will be requested. Possible values are: Yes, No. Default is No. | Optional | 
| nopackages | If `yes`, the registered node will not upload its installed packages information to Satellite server. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!linux-rhn-register host="123.123.123.123" state="absent" username="joe_user" password="somepass" ```

#### Context Example
```json
{
    "Linux": {
        "RhnRegister": {
            "changed": false,
            "host": "123.123.123.123",
            "msg": "System already unregistered.",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * msg: System already unregistered.


### linux-rhsm-release
***
Set or Unset RHSM Release version
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/rhsm_release_module.html


#### Base Command

`linux-rhsm-release`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| release | RHSM release version to use (use null to unset). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.RhsmRelease.current_release | string | The current RHSM release version value | 



### linux-rhsm-repository
***
Manage RHSM repositories using the subscription-manager command
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/rhsm_repository_module.html


#### Base Command

`linux-rhsm-repository`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | If state is equal to present or disabled, indicates the desired repository state. Possible values are: present, enabled, absent, disabled. Default is present. | Required | 
| name | The ID of repositories to enable.<br/>To operate on several repositories this can accept a comma separated list or a YAML list. | Required | 
| purge | Disable all currently enabled repositories that are not not specified in `name`. Only set this to `True` if passing in a list of repositories to the `name` field. Using this with `loop` will most likely not have the desired result. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.RhsmRepository.repositories | unknown | The list of RHSM repositories with their states.
When this module is used to change the repository states, this list contains the updated states after the changes. | 



### linux-rpm-key
***
Adds or removes a gpg key from the rpm db
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/rpm_key_module.html


#### Base Command

`linux-rpm-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| key | Key that will be modified. Can be a url, a file on the managed node, or a keyid if the key already exists in the database. | Required | 
| state | If the key will be imported or removed from the rpm db. Possible values are: absent, present. Default is present. | Optional | 
| validate_certs | If `no` and the `key` is a url starting with https, SSL certificates will not be validated.<br/>This should only be used on personally controlled sites using self-signed certificates. Default is yes. | Optional | 
| fingerprint | The long-form fingerprint of the key being imported.<br/>This will be used to verify the specified key. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |



### linux-get-url
***
Downloads files from HTTP, HTTPS, or FTP to node
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/get_url_module.html


#### Base Command

`linux-get-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| url | HTTP, HTTPS, or FTP URL in the form (http\|https\|ftp)://[user[:pass]]@host.domain[:port]/path. | Required | 
| dest | Absolute path of where to download the file to.<br/>If `dest` is a directory, either the server provided filename or, if none provided, the base name of the URL on the remote server will be used. If a directory, `force` has no effect.<br/>If `dest` is a directory, the file will always be downloaded (regardless of the `force` option), but replaced only if the contents changed.. | Required | 
| tmp_dest | Absolute path of where temporary file is downloaded to.<br/>When run on Ansible 2.5 or greater, path defaults to ansible's remote_tmp setting<br/>When run on Ansible prior to 2.5, it defaults to `TMPDIR`, `TEMP` or `TMP` env variables or a platform specific value.<br/>`https://docs.python.org/2/library/tempfile.html#tempfile.tempdir`. | Optional | 
| force | If `yes` and `dest` is not a directory, will download the file every time and replace the file if the contents change. If `no`, the file will only be downloaded if the destination does not exist. Generally should be `yes` only for small local files.<br/>Prior to 0.6, this module behaved as if `yes` was the default.<br/>Alias `thirsty` has been deprecated and will be removed in 2.13. Possible values are: Yes, No. Default is No. | Optional | 
| backup | Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| sha256sum | If a SHA-256 checksum is passed to this parameter, the digest of the destination file will be calculated after it is downloaded to ensure its integrity and verify that the transfer completed successfully. This option is deprecated. Use `checksum` instead. | Optional | 
| checksum | If a checksum is passed to this parameter, the digest of the destination file will be calculated after it is downloaded to ensure its integrity and verify that the transfer completed successfully. Format: &lt;algorithm&gt;:&lt;checksum\|url&gt;, e.g. checksum="sha256:D98291AC[...]B6DC7B97", checksum="sha256:http://example.com/path/sha256sum.txt"<br/>If you worry about portability, only the sha1 algorithm is available on all platforms and python versions.<br/>The third party hashlib library can be installed for access to additional algorithms.<br/>Additionally, if a checksum is passed to this parameter, and the file exist under the `dest` location, the `destination_checksum` would be calculated, and if checksum equals `destination_checksum`, the file download would be skipped (unless `force` is true). If the checksum does not equal `destination_checksum`, the destination file is deleted. | Optional | 
| use_proxy | if `no`, it will not use a proxy, even if one is defined in an environment variable on the target hosts. Possible values are: Yes, No. Default is Yes. | Optional | 
| validate_certs | If `no`, SSL certificates will not be validated.<br/>This should only be used on personally controlled sites using self-signed certificates. Possible values are: Yes, No. Default is Yes. | Optional | 
| timeout | Timeout in seconds for URL request. Default is 10. | Optional | 
| headers | Add custom HTTP headers to a request in hash/dict format.<br/>The hash/dict format was added in Ansible 2.6.<br/>Previous versions used a `"key:value,key:value"` string format.<br/>The `"key:value,key:value"` string format is deprecated and will be removed in version 2.10. | Optional | 
| url_username | The username for use in HTTP basic authentication.<br/>This parameter can be used without `url_password` for sites that allow empty passwords.<br/>Since version 2.8 you can also use the `username` alias for this option. | Optional | 
| url_password | The password for use in HTTP basic authentication.<br/>If the `url_username` parameter is not specified, the `url_password` parameter will not be used.<br/>Since version 2.8 you can also use the 'password' alias for this option. | Optional | 
| force_basic_auth | Force the sending of the Basic authentication header upon initial request.<br/>httplib2, the library used by the uri module only sends authentication information when a webservice responds to an initial request with a 401 status. Since some basic auth services do not properly send a 401, logins will fail. Possible values are: Yes, No. Default is No. | Optional | 
| client_cert | PEM formatted certificate chain file to be used for SSL client authentication.<br/>This file can also include the key as well, and if the key is included, `client_key` is not required. | Optional | 
| client_key | PEM formatted file that contains your private key to be used for SSL client authentication.<br/>If `client_cert` contains both the certificate and key, this option is not required. | Optional | 
| http_agent | Header to identify as, generally appears in web server logs. Default is ansible-httpget. | Optional | 
| mode | The permissions the resulting file or directory should have.<br/>For those used to `/usr/bin/chmod` remember that modes are actually octal numbers. You must either add a leading zero so that Ansible's YAML parser knows it is an octal number (like `0644` or `01777`) or quote it (like `'644'` or `'1777'`) so Ansible receives a string and can do its own conversion from string into number.<br/>Giving Ansible a number without following one of these rules will end up with a decimal number which will have unexpected results.<br/>As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, `u+rwx` or `u=rw,g=r,o=r`). | Optional | 
| owner | Name of the user that should own the file/directory, as would be fed to `chown`. | Optional | 
| group | Name of the group that should own the file/directory, as would be fed to `chown`. | Optional | 
| seuser | The user part of the SELinux file context.<br/>By default it uses the `system` policy, where applicable.<br/>When set to `_default`, it will use the `user` portion of the policy if available. | Optional | 
| serole | The role part of the SELinux file context.<br/>When set to `_default`, it will use the `role` portion of the policy if available. | Optional | 
| setype | The type part of the SELinux file context.<br/>When set to `_default`, it will use the `type` portion of the policy if available. | Optional | 
| selevel | The level part of the SELinux file context.<br/>This is the MLS/MCS attribute, sometimes known as the `range`.<br/>When set to `_default`, it will use the `level` portion of the policy if available. Default is s0. | Optional | 
| unsafe_writes | Influence when to use atomic operation to prevent data corruption or inconsistent reads from the target file.<br/>By default this module uses atomic operations to prevent data corruption or inconsistent reads from the target files, but sometimes systems are configured or just broken in ways that prevent this. One example is docker mounted files, which cannot be updated atomically from inside the container and can only be written in an unsafe manner.<br/>This option allows Ansible to fall back to unsafe methods of updating files when atomic operations fail (however, it doesn't force Ansible to perform unsafe writes).<br/>IMPORTANT! Unsafe writes are subject to race conditions and can lead to data corruption. Possible values are: Yes, No. Default is No. | Optional | 
| attributes | The attributes the resulting file or directory should have.<br/>To get supported flags look at the man page for `chattr` on the target system.<br/>This string should contain the attributes in the same order as the one displayed by `lsattr`.<br/>The `=` operator is assumed as default, otherwise `+` or `-` operators need to be included in the string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linux.GetUrl.backup_file | string | name of backup file created after download | 
| Linux.GetUrl.checksum_dest | string | sha1 checksum of the file after copy | 
| Linux.GetUrl.checksum_src | string | sha1 checksum of the file | 
| Linux.GetUrl.dest | string | destination file/path | 
| Linux.GetUrl.elapsed | number | The number of seconds that elapsed while performing the download | 
| Linux.GetUrl.gid | number | group id of the file | 
| Linux.GetUrl.group | string | group of the file | 
| Linux.GetUrl.md5sum | string | md5 checksum of the file after download | 
| Linux.GetUrl.mode | string | permissions of the target | 
| Linux.GetUrl.msg | string | the HTTP message from the request | 
| Linux.GetUrl.owner | string | owner of the file | 
| Linux.GetUrl.secontext | string | the SELinux security context of the file | 
| Linux.GetUrl.size | number | size of the target | 
| Linux.GetUrl.src | string | source file used after download | 
| Linux.GetUrl.state | string | state of the target | 
| Linux.GetUrl.status_code | number | the HTTP status code from the request | 
| Linux.GetUrl.uid | number | owner id of the file, after execution | 
| Linux.GetUrl.url | string | the actual URL used for the request | 


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
