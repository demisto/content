This integration enables the management of Microsoft Windows hosts directly from XSOAR using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the Windows hosts by utilising the Windows Remote Management (WinRM) API interface present in Windows 2008 and above combined with PowerShell.

To use this integration, configure an instance of this integration. This will associate a credential to be used to access hosts when commands are run. The commands from this integration will take the Windows host address(es) as an input, and use the saved credential associated to the instance to execute. Create separate instances if multiple credentials are required. 

This integration uses NTLM for authentication. This ensures that actual credentials are never sent over the network, instead relying on hashing methods. By default, the initial authentication phase is performed unencrypted over HTTP, after which all communication is encrypted using a symmetric 256-bit key. If it is desired to use HTTPS from the onset, [additional configuration on the Windows host is required](https://docs.microsoft.com/en-US/troubleshoot/windows-client/system-management-components/configure-winrm-for-https). After WinRM is configured for HTTPS, update the port setting on the integration. Any port other than the default 5985 will use HTTPS communication.

## Host Requirements
WinRM is enabled by default on all Windows Server operating systems since Windows Server 2012 and above, but disabled on all client operating systems like Windows 10, Windows 8 and Windows 7.

WinRM can be enabled on Windows client OSes [using Group Policy](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management#configuring-winrm-with-group-policy).

PowerShell 3.0 or newer and at least .NET 4.0 to be installed on the Windows host.

## Network Requirements
By default, TCP port 5985 will be used. If WinRM is configured for HTTPS, update the port setting on the integration.

Please also note that the default Windows Firewall Policy (Windows Remote Management (HTTP-In)) allows WinRM connections only from the private networks.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.
## Credentials
A Windows Domain Account is recommended; however local accounts are also supported.
The username syntax can be in Pre-Windows2000 style (domain.local/account) or in newer UPN format (account@domain.local)
## Permissions
While Administrative privileges are not strictly required, WinRM is configured by default to only allow connections from accounts in the local Administrators group.

Non-administrative accounts can be used with WinRM, however most typical server administration tasks require some level of administrative access, so the utility is usually limited.
## Concurrency
This integration supports execution of commands against multiple hosts concurrently. The `host` parameter accepts a list of addresses, and will run the command in parallel as per the **Concurrency Factor** value.

## Further information
This integration is powered by Ansible 2.9. Further information can be found on that the following locations:
* [Ansible Windows Guide](https://docs.ansible.com/ansible/2.9/user_guide/windows_setup.html)
* [Windows Module Index](https://docs.ansible.com/ansible/2.9/modules/list_of_windows_modules.html)


## Configure Ansible Microsoft Windows on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Ansible Microsoft Windows.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Username | The credentials to associate with the instance. | True |
    | Default WinRM Port | The default port to use if one is not specified in the commands \`host\` argument. If 5985 is specified the HTTP transport method will be used. Otherwise HTTPS will be used for all other ports | True |
    | Concurrency Factor | If multiple hosts are specified in a command, how many hosts should be interacted with concurrently. | True |

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!win-gather-facts`command providing an example `host` as the command argument. This command will connect to the specified host with the configured credentials in the integration, and if successful output general information about the host.

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### win-gather-facts
***
Gathers facts about remote hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/gather_facts_module.html


#### Base Command

`win-gather-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| parallel | A toggle that controls if the fact modules are executed in parallel or serially and in order. This can guarantee the merge order of module facts at the expense of performance.<br/>By default it will be true if more than one fact module is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


### win-acl
***
Set file/directory/registry permissions for a system user or group
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_acl_module.html


#### Base Command

`win-acl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The path to the file or directory. | Required | 
| user | User or Group to add specified rights to act on src file/folder or registry key. | Required | 
| state | Specify whether to add `present` or remove `absent` the specified access rule. Possible values are: absent, present. Default is present. | Optional | 
| type | Specify whether to allow or deny the rights specified. Possible values are: allow, deny. | Required | 
| rights | The rights/permissions that are to be allowed/denied for the specified user or group for the item at `path`.<br/>If `path` is a file or directory, rights can be any right under MSDN FileSystemRights `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx`.<br/>If `path` is a registry key, rights can be any right under MSDN RegistryRights `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx`. | Required | 
| inherit | Inherit flags on the ACL rules.<br/>Can be specified as a comma separated list, e.g. `ContainerInherit`, `ObjectInherit`.<br/>For more information on the choices see MSDN InheritanceFlags enumeration at `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags.aspx`.<br/>Defaults to `ContainerInherit, ObjectInherit` for Directories. Possible values are: ContainerInherit, ObjectInherit. | Optional | 
| propagation | Propagation flag on the ACL rules.<br/>For more information on the choices see MSDN PropagationFlags enumeration at `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags.aspx`. Possible values are: InheritOnly, None, NoPropagateInherit. Default is None. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-acl host="123.123.123.123" user="fed-phil" path="C:\\Important\\Executable.exe" type="deny" rights="ExecuteFile,Write" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinAcl": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-acl-inheritance
***
Change ACL inheritance
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_acl_inheritance_module.html


#### Base Command

`win-acl-inheritance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to be used for changing inheritance. | Required | 
| state | Specify whether to enable `present` or disable `absent` ACL inheritance. Possible values are: absent, present. Default is absent. | Optional | 
| reorganize | For P(state) = `absent`, indicates if the inherited ACE's should be copied from the parent directory. This is necessary (in combination with removal) for a simple ACL instead of using multiple ACE deny entries.<br/>For P(state) = `present`, indicates if the inherited ACE's should be deduplicated compared to the parent directory. This removes complexity of the ACL structure. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-acl-inheritance host="123.123.123.123" path="C://apache" state="absent"```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinAclInheritance": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-audit-policy-system
***
Used to make changes to the system wide Audit Policy
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_audit_policy_system_module.html


#### Base Command

`win-audit-policy-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| category | Single string value for the category you would like to adjust the policy on.<br/>Cannot be used with `subcategory`. You must define one or the other.<br/>Changing this setting causes all subcategories to be adjusted to the defined `audit_type`. | Optional | 
| subcategory | Single string value for the subcategory you would like to adjust the policy on.<br/>Cannot be used with `category`. You must define one or the other. | Optional | 
| audit_type | The type of event you would like to audit for.<br/>Accepts a list. See examples. Possible values are: failure, none, success. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinAuditPolicySystem.current_audit_policy | unknown | details on the policy being targetted | 


#### Command Example
```!win-audit-policy-system host="123.123.123.123" subcategory="File System" audit_type="failure" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinAuditPolicySystem": {
            "changed": false,
            "current_audit_policy": {
                "file system": "failure"
            },
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Current_Audit_Policy
>    * file system: failure


### win-audit-rule
***
Adds an audit rule to files, folders, or registry keys
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_audit_rule_module.html


#### Base Command

`win-audit-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the file, folder, or registry key.<br/>Registry paths should be in Powershell format, beginning with an abbreviation for the root such as, `HKLM:\Software`. | Required | 
| user | The user or group to adjust rules for. | Required | 
| rights | Comma separated list of the rights desired. Only required for adding a rule.<br/>If `path` is a file or directory, rights can be any right under MSDN FileSystemRights `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx`.<br/>If `path` is a registry key, rights can be any right under MSDN RegistryRights `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx`. | Required | 
| inheritance_flags | Defines what objects inside of a folder or registry key will inherit the settings.<br/>If you are setting a rule on a file, this value has to be changed to `none`.<br/>For more information on the choices see MSDN PropagationFlags enumeration at `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.inheritanceflags.aspx`. Possible values are: ContainerInherit, ObjectInherit. Default is ContainerInherit,ObjectInherit. | Optional | 
| propagation_flags | Propagation flag on the audit rules.<br/>This value is ignored when the path type is a file.<br/>For more information on the choices see MSDN PropagationFlags enumeration at `https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.propagationflags.aspx`. Possible values are: None, InherityOnly, NoPropagateInherit. Default is None. | Optional | 
| audit_flags | Defines whether to log on failure, success, or both.<br/>To log both define as comma separated list "Success, Failure". Possible values are: Failure, Success. | Required | 
| state | Whether the rule should be `present` or `absent`.<br/>For absent, only `path`, `user`, and `state` are required.<br/>Specifying `absent` will remove all rules matching the defined `user`. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinAuditRule.current_audit_rules | unknown | The current rules on the defined \`path\`
Will return "No audit rules defined on \`path\`" | 
| MicrosoftWindows.WinAuditRule.path_type | string | The type of \`path\` being targetted.
Will be one of file, directory, registry. | 


#### Command Example
```!win-audit-rule host="123.123.123.123" path="C:\\inetpub\\wwwroot\\website" user="BUILTIN\\Users" rights="write,delete,changepermissions" audit_flags="success,failure" inheritance_flags="ContainerInherit,ObjectInherit" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinAuditRule": {
            "changed": true,
            "current_audit_rules": {
                "audit_flags": "Success, Failure",
                "inheritance_flags": "ContainerInherit, ObjectInherit",
                "is_inherited": "False",
                "propagation_flags": "None",
                "rights": "Write, Delete, ChangePermissions",
                "user": "BUILTIN\\Users"
            },
            "host": "123.123.123.123",
            "path_type": "directory",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * path_type: directory
>  * ## Current_Audit_Rules
>    * audit_flags: Success, Failure
>    * inheritance_flags: ContainerInherit, ObjectInherit
>    * is_inherited: False
>    * propagation_flags: None
>    * rights: Write, Delete, ChangePermissions
>    * user: BUILTIN\Users


### win-certificate-store
***
Manages the certificate store
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_certificate_store_module.html


#### Base Command

`win-certificate-store`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | If `present`, will ensure that the certificate at `path` is imported into the certificate store specified.<br/>If `absent`, will ensure that the certificate specified by `thumbprint` or the thumbprint of the cert at `path` is removed from the store specified.<br/>If `exported`, will ensure the file at `path` is a certificate specified by `thumbprint`.<br/>When exporting a certificate, if `path` is a directory then the module will fail, otherwise the file will be replaced if needed. Possible values are: absent, exported, present. Default is present. | Optional | 
| path | The path to a certificate file.<br/>This is required when `state` is `present` or `exported`.<br/>When `state` is `absent` and `thumbprint` is not specified, the thumbprint is derived from the certificate at this path. | Optional | 
| thumbprint | The thumbprint as a hex string to either export or remove.<br/>See the examples for how to specify the thumbprint. | Optional | 
| store_name | The store name to use when importing a certificate or searching for a certificate.<br/>`AddressBook`: The X.509 certificate store for other users<br/>`AuthRoot`: The X.509 certificate store for third-party certificate authorities (CAs)<br/>`CertificateAuthority`: The X.509 certificate store for intermediate certificate authorities (CAs)<br/>`Disallowed`: The X.509 certificate store for revoked certificates<br/>`My`: The X.509 certificate store for personal certificates<br/>`Root`: The X.509 certificate store for trusted root certificate authorities (CAs)<br/>`TrustedPeople`: The X.509 certificate store for directly trusted people and resources<br/>`TrustedPublisher`: The X.509 certificate store for directly trusted publishers. Possible values are: AddressBook, AuthRoot, CertificateAuthority, Disallowed, My, Root, TrustedPeople, TrustedPublisher. Default is My. | Optional | 
| store_location | The store location to use when importing a certificate or searching for a certificate. Possible values are: CurrentUser, LocalMachine. Default is LocalMachine. | Optional | 
| password | The password of the pkcs12 certificate key.<br/>This is used when reading a pkcs12 certificate file or the password to set when `state=exported` and `file_type=pkcs12`.<br/>If the pkcs12 file has no password set or no password should be set on the exported file, do not set this option. | Optional | 
| key_exportable | Whether to allow the private key to be exported.<br/>If `no`, then this module and other process will only be able to export the certificate and the private key cannot be exported.<br/>Used when `state=present` only. Possible values are: Yes, No. Default is Yes. | Optional | 
| key_storage | Specifies where Windows will store the private key when it is imported.<br/>When set to `default`, the default option as set by Windows is used, typically `user`.<br/>When set to `machine`, the key is stored in a path accessible by various users.<br/>When set to `user`, the key is stored in a path only accessible by the current user.<br/>Used when `state=present` only and cannot be changed once imported.<br/>See `https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509keystorageflags.aspx` for more details. Possible values are: default, machine, user. Default is default. | Optional | 
| file_type | The file type to export the certificate as when `state=exported`.<br/>`der` is a binary ASN.1 encoded file.<br/>`pem` is a base64 encoded file of a der file in the OpenSSL form.<br/>`pkcs12` (also known as pfx) is a binary container that contains both the certificate and private key unlike the other options.<br/>When `pkcs12` is set and the private key is not exportable or accessible by the current user, it will throw an exception. Possible values are: der, pem, pkcs12. Default is der. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinCertificateStore.thumbprints | unknown | A list of certificate thumbprints that were touched by the module. | 


#### Command Example
```!win-certificate-store host="123.123.123.123" path="C:\\Temp\\cert.pem" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinCertificateStore": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED",
            "thumbprints": [
                "58288A1E834AD6E157688226A7206914CBD28519"
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Thumbprints
>    * 0: 58288A1E834AD6E157688226A7206914CBD28519


### win-chocolatey
***
Manage packages using chocolatey
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_chocolatey_module.html


#### Base Command

`win-chocolatey`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| allow_empty_checksums | Allow empty checksums to be used for downloaded resource from non-secure locations.<br/>Use `win_chocolatey_feature` with the name `allowEmptyChecksums` to control this option globally. Possible values are: Yes, No. Default is No. | Optional | 
| allow_multiple | Allow the installation of multiple packages when `version` is specified.<br/>Having multiple packages at different versions can cause issues if the package doesn't support this. Use at your own risk. Possible values are: Yes, No. Default is No. | Optional | 
| allow_prerelease | Allow the installation of pre-release packages.<br/>If `state` is `latest`, the latest pre-release package will be installed. Possible values are: Yes, No. Default is No. | Optional | 
| architecture | Force Chocolatey to install the package of a specific process architecture.<br/>When setting `x86`, will ensure Chocolatey installs the x86 package even when on an x64 bit OS. Possible values are: default, x86. Default is default. | Optional | 
| force | Forces the install of a package, even if it already is installed.<br/>Using `force` will cause Ansible to always report that a change was made. Possible values are: Yes, No. Default is No. | Optional | 
| install_args | Arguments to pass to the native installer.<br/>These are arguments that are passed directly to the installer the Chocolatey package runs, this is generally an advanced option. | Optional | 
| ignore_checksums | Ignore the checksums provided by the package.<br/>Use `win_chocolatey_feature` with the name `checksumFiles` to control this option globally. Possible values are: Yes, No. Default is No. | Optional | 
| ignore_dependencies | Ignore dependencies, only install/upgrade the package itself. Possible values are: Yes, No. Default is No. | Optional | 
| name | Name of the package(s) to be installed.<br/>Set to `all` to run the action on all the installed packages. | Required | 
| package_params | Parameters to pass to the package.<br/>These are parameters specific to the Chocolatey package and are generally documented by the package itself.<br/>Before Ansible 2.7, this option was just `params`. | Optional | 
| pinned | Whether to pin the Chocolatey package or not.<br/>If omitted then no checks on package pins are done.<br/>Will pin/unpin the specific version if `version` is set.<br/>Will pin the latest version of a package if `yes`, `version` is not set and and no pin already exists.<br/>Will unpin all versions of a package if `no` and `version` is not set.<br/>This is ignored when `state=absent`. | Optional | 
| proxy_url | Proxy URL used to install chocolatey and the package.<br/>Use `win_chocolatey_config` with the name `proxy` to control this option globally. | Optional | 
| proxy_username | Proxy username used to install Chocolatey and the package.<br/>Before Ansible 2.7, users with double quote characters `"` would need to be escaped with `\` beforehand. This is no longer necessary.<br/>Use `win_chocolatey_config` with the name `proxyUser` to control this option globally. | Optional | 
| proxy_password | Proxy password used to install Chocolatey and the package.<br/>This value is exposed as a command argument and any privileged account can see this value when the module is running Chocolatey, define the password on the global config level with `win_chocolatey_config` with name `proxyPassword` to avoid this. | Optional | 
| skip_scripts | Do not run `chocolateyInstall.ps1` or `chocolateyUninstall.ps1` scripts when installing a package. Possible values are: Yes, No. Default is No. | Optional | 
| source | Specify the source to retrieve the package from.<br/>Use `win_chocolatey_source` to manage global sources.<br/>This value can either be the URL to a Chocolatey feed, a path to a folder containing `.nupkg` packages or the name of a source defined by `win_chocolatey_source`.<br/>This value is also used when Chocolatey is not installed as the location of the install.ps1 script and only supports URLs for this case. | Optional | 
| source_username | A username to use with `source` when accessing a feed that requires authentication.<br/>It is recommended you define the credentials on a source with `win_chocolatey_source` instead of passing it per task. | Optional | 
| source_password | The password for `source_username`.<br/>This value is exposed as a command argument and any privileged account can see this value when the module is running Chocolatey, define the credentials with a source with `win_chocolatey_source` to avoid this. | Optional | 
| state | State of the package on the system.<br/>When `absent`, will ensure the package is not installed.<br/>When `present`, will ensure the package is installed.<br/>When `downgrade`, will allow Chocolatey to downgrade a package if `version` is older than the installed version.<br/>When `latest`, will ensure the package is installed to the latest available version.<br/>When `reinstalled`, will uninstall and reinstall the package. Possible values are: absent, downgrade, latest, present, reinstalled. Default is present. | Optional | 
| timeout | The time to allow chocolatey to finish before timing out. Default is 2700. | Optional | 
| validate_certs | Used when downloading the Chocolatey install script if Chocolatey is not already installed, this does not affect the Chocolatey package install process.<br/>When `no`, no SSL certificates will be validated.<br/>This should only be used on personally controlled sites using self-signed certificate. Possible values are: Yes, No. Default is Yes. | Optional | 
| version | Specific version of the package to be installed.<br/>When `state` is set to `absent`, will uninstall the specific version otherwise all versions of that package will be removed.<br/>If a different version of package is installed, `state` must be `latest` or `force` set to `yes` to install the desired version.<br/>Provide as a string (e.g. `'6.1'`), otherwise it is considered to be a floating-point number and depending on the locale could become `6,1`, which will cause a failure.<br/>If `name` is set to `chocolatey` and Chocolatey is not installed on the host, this will be the version of Chocolatey that is installed. You can also set the `chocolateyVersion` environment var. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinChocolatey.command | string | The full command used in the chocolatey task. | 
| MicrosoftWindows.WinChocolatey.rc | number | The return code from the chocolatey task. | 
| MicrosoftWindows.WinChocolatey.stdout | string | The stdout from the chocolatey task. The verbosity level of the messages are affected by Ansible verbosity setting, see notes for more details. | 


#### Command Example
```!win-chocolatey host="123.123.123.123" name="git" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinChocolatey": {
            "changed": true,
            "host": "123.123.123.123",
            "rc": 0,
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * rc: 0


### win-chocolatey-config
***
Manages Chocolatey config settings
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_chocolatey_config_module.html


#### Base Command

`win-chocolatey-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the config setting to manage.<br/>See `https://chocolatey.org/docs/chocolatey-configuration` for a list of valid configuration settings that can be changed.<br/>Any config values that contain encrypted values like a password are not idempotent as the plaintext value cannot be read. | Required | 
| state | When `absent`, it will ensure the setting is unset or blank.<br/>When `present`, it will ensure the setting is set to the value of `value`. Possible values are: absent, present. Default is present. | Optional | 
| value | Used when `state=present` that contains the value to set for the config setting.<br/>Cannot be null or an empty string, use `state=absent` to unset a config value instead. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-chocolatey-config host="123.123.123.123" name="cacheLocation" state="present" value="D:\\chocolatey_temp" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinChocolateyConfig": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-chocolatey-facts
***
Create a facts collection for Chocolatey
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_chocolatey_facts_module.html


#### Base Command

`win-chocolatey-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinChocolateyFacts.facts | unknown | Detailed information about the Chocolatey installation | 


#### Command Example
```!win-chocolatey-facts host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinChocolateyFacts": {
            "chocolatey": {
                "config": {
                    "cacheLocation": "D:\\chocolatey_temp",
                    "commandExecutionTimeoutSeconds": 2700,
                    "containsLegacyPackageInstalls": true,
                    "proxy": "",
                    "proxyBypassList": "",
                    "proxyBypassOnLocal": true,
                    "proxyPassword": "",
                    "proxyUser": "",
                    "upgradeAllExceptions": "",
                    "webRequestTimeoutSeconds": 30
                },
                "feature": {
                    "allowEmptyChecksums": false,
                    "allowEmptyChecksumsSecure": true,
                    "allowGlobalConfirmation": false,
                    "autoUninstaller": true,
                    "checksumFiles": true,
                    "exitOnRebootDetected": false,
                    "failOnAutoUninstaller": false,
                    "failOnInvalidOrMissingLicense": false,
                    "failOnStandardError": false,
                    "ignoreInvalidOptionsSwitches": true,
                    "ignoreUnfoundPackagesOnUpgradeOutdated": false,
                    "logEnvironmentValues": false,
                    "logValidationResultsOnWarnings": true,
                    "logWithoutColor": false,
                    "powershellHost": true,
                    "removePackageInformationOnUninstall": false,
                    "scriptsCheckLastExitCode": false,
                    "showDownloadProgress": true,
                    "showNonElevatedWarnings": true,
                    "skipPackageUpgradesWhenNotInstalled": false,
                    "stopOnFirstPackageFailure": false,
                    "useEnhancedExitCodes": false,
                    "useFipsCompliantChecksums": false,
                    "usePackageExitCodes": true,
                    "usePackageRepositoryOptimizations": true,
                    "useRememberedArgumentsForUpgrades": false,
                    "virusCheck": false
                },
                "packages": [
                    {
                        "package": "chocolatey",
                        "version": "0.10.15"
                    },
                    {
                        "package": "chocolatey-core.extension",
                        "version": "1.1.1.1"
                    },
                    {
                        "package": "git",
                        "version": "2.32.0"
                    },
                    {
                        "package": "git.install",
                        "version": "2.32.0"
                    },
                    {
                        "package": "nssm",
                        "version": "2.24.101.20180116"
                    }
                ],
                "sources": [
                    {
                        "admin_only": false,
                        "allow_self_service": false,
                        "bypass_proxy": false,
                        "certificate": null,
                        "disabled": false,
                        "name": "chocolatey",
                        "priority": 0,
                        "source": "https://chocolatey.org/api/v2/",
                        "source_username": null
                    }
                ]
            },
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * ## Chocolatey
>    * ### Config
>      * cacheLocation: D:\chocolatey_temp
>      * commandExecutionTimeoutSeconds: 2700
>      * containsLegacyPackageInstalls: True
>      * proxy: 
>      * proxyBypassList: 
>      * proxyBypassOnLocal: True
>      * proxyPassword: 
>      * proxyUser: 
>      * upgradeAllExceptions: 
>      * webRequestTimeoutSeconds: 30
>    * ### Feature
>      * allowEmptyChecksums: False
>      * allowEmptyChecksumsSecure: True
>      * allowGlobalConfirmation: False
>      * autoUninstaller: True
>      * checksumFiles: True
>      * exitOnRebootDetected: False
>      * failOnAutoUninstaller: False
>      * failOnInvalidOrMissingLicense: False
>      * failOnStandardError: False
>      * ignoreInvalidOptionsSwitches: True
>      * ignoreUnfoundPackagesOnUpgradeOutdated: False
>      * logEnvironmentValues: False
>      * logValidationResultsOnWarnings: True
>      * logWithoutColor: False
>      * powershellHost: True
>      * removePackageInformationOnUninstall: False
>      * scriptsCheckLastExitCode: False
>      * showDownloadProgress: True
>      * showNonElevatedWarnings: True
>      * skipPackageUpgradesWhenNotInstalled: False
>      * stopOnFirstPackageFailure: False
>      * useEnhancedExitCodes: False
>      * useFipsCompliantChecksums: False
>      * usePackageExitCodes: True
>      * usePackageRepositoryOptimizations: True
>      * useRememberedArgumentsForUpgrades: False
>      * virusCheck: False
>    * ### Packages
>    * ### List
>      * package: chocolatey
>      * version: 0.10.15
>    * ### List
>      * package: chocolatey-core.extension
>      * version: 1.1.1.1
>    * ### List
>      * package: git
>      * version: 2.32.0
>    * ### List
>      * package: git.install
>      * version: 2.32.0
>    * ### List
>      * package: nssm
>      * version: 2.24.101.20180116
>    * ### Sources
>    * ### Chocolatey
>      * admin_only: False
>      * allow_self_service: False
>      * bypass_proxy: False
>      * certificate: None
>      * disabled: False
>      * name: chocolatey
>      * priority: 0
>      * source: https://chocolatey.org/api/v2/
>      * source_username: None


### win-chocolatey-feature
***
Manages Chocolatey features
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_chocolatey_feature_module.html


#### Base Command

`win-chocolatey-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the feature to manage.<br/>Run `choco.exe feature list` to get a list of features that can be managed. | Required | 
| state | When `disabled` then the feature will be disabled.<br/>When `enabled` then the feature will be enabled. Possible values are: disabled, enabled. Default is enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-chocolatey-feature host="123.123.123.123" name="checksumFiles" state="disabled" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinChocolateyFeature": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-chocolatey-source
***
Manages Chocolatey sources
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_chocolatey_source_module.html


#### Base Command

`win-chocolatey-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| admin_only | Makes the source visible to Administrators only.<br/>Requires Chocolatey &gt;= 0.10.8.<br/>When creating a new source, this defaults to `no`. | Optional | 
| allow_self_service | Allow the source to be used with self-service<br/>Requires Chocolatey &gt;= 0.10.4.<br/>When creating a new source, this defaults to `no`. | Optional | 
| bypass_proxy | Bypass the proxy when using this source.<br/>Requires Chocolatey &gt;= 0.10.4.<br/>When creating a new source, this defaults to `no`. | Optional | 
| certificate | The path to a .pfx file to use for X509 authenticated feeds.<br/>Requires Chocolatey &gt;= 0.9.10. | Optional | 
| certificate_password | The password for `certificate` if required.<br/>Requires Chocolatey &gt;= 0.9.10. | Optional | 
| name | The name of the source to configure. | Required | 
| priority | The priority order of this source compared to other sources, lower is better.<br/>All priorities above `0` will be evaluated first, then zero-based values will be evaluated in config file order.<br/>Requires Chocolatey &gt;= 1.1.1.1.<br/>When creating a new source, this defaults to `0`. | Optional | 
| source | The file/folder/url of the source.<br/>Required when `state` is `present` or `disabled` and the source does not already exist. | Optional | 
| source_username | The username used to access `source`. | Optional | 
| source_password | The password for `source_username`.<br/>Required if `source_username` is set. | Optional | 
| state | When `absent`, will remove the source.<br/>When `disabled`, will ensure the source exists but is disabled.<br/>When `present`, will ensure the source exists and is enabled. Possible values are: absent, disabled, present. Default is present. | Optional | 
| update_password | When `always`, the module will always set the password and report a change if `certificate_password` or `source_password` is set.<br/>When `on_create`, the module will only set the password if the source is being created. Possible values are: always, on_create. Default is always. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-chocolatey-source host="123.123.123.123" name="chocolatey" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinChocolateySource": {
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


### win-copy
***
Copies files to remote locations on windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_copy_module.html


#### Base Command

`win-copy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| content | When used instead of `src`, sets the contents of a file directly to the specified value.<br/>This is for simple values, for anything complex or with formatting please switch to the `template` module. | Optional | 
| decrypt | This option controls the autodecryption of source files using vault. Possible values are: Yes, No. Default is Yes. | Optional | 
| dest | Remote absolute path where the file should be copied to.<br/>If `src` is a directory, this must be a directory too.<br/>Use \ for path separators or \\ when in "double quotes".<br/>If `dest` ends with \ then source or the contents of source will be copied to the directory without renaming.<br/>If `dest` is a nonexistent path, it will only be created if `dest` ends with "/" or "\", or `src` is a directory.<br/>If `src` and `dest` are files and if the parent directory of `dest` doesn't exist, then the task will fail. | Required | 
| backup | Determine whether a backup should be created.<br/>When set to `yes`, create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly.<br/>No backup is taken when `remote_"src"=False` and multiple files are being copied. Possible values are: Yes, No. Default is No. | Optional | 
| force | If set to `yes`, the file will only be transferred if the content is different than destination.<br/>If set to `no`, the file will only be transferred if the destination does not exist.<br/>If set to `no`, no checksuming of the content is performed which can help improve performance on larger files. Possible values are: Yes, No. Default is Yes. | Optional | 
| local_follow | This flag indicates that filesystem links in the source tree, if they exist, should be followed. Possible values are: Yes, No. Default is Yes. | Optional | 
| remote_src | If `no`, it will search for src at originating/master machine.<br/>If `yes`, it will go to the remote/target machine for the src. Possible values are: Yes, No. Default is No. | Optional | 
| src | Local path to a file to copy to the remote server; can be absolute or relative.<br/>If path is a directory, it is copied (including the source folder name) recursively to `dest`.<br/>If path is a directory and ends with "/", only the inside contents of that directory are copied to the destination. Otherwise, if it does not end with "/", the directory itself with all contents is copied.<br/>If path is a file and dest ends with "\", the file is copied to the folder with the same filename.<br/>Required unless using `content`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinCopy.backup_file | string | Name of the backup file that was created. | 
| MicrosoftWindows.WinCopy.dest | string | Destination file/path. | 
| MicrosoftWindows.WinCopy.src | string | Source file used for the copy on the target machine. | 
| MicrosoftWindows.WinCopy.checksum | string | SHA1 checksum of the file after running copy. | 
| MicrosoftWindows.WinCopy.size | number | Size of the target, after execution. | 
| MicrosoftWindows.WinCopy.operation | string | Whether a single file copy took place or a folder copy. | 
| MicrosoftWindows.WinCopy.original_basename | string | Basename of the copied file. | 


#### Command Example
```!win-copy host="123.123.123.123" "src"="C:\\Important\\Executable.exe" dest="C:\\Temp" remote_"src"=yes```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinCopy": {
            "changed": true,
            "checksum": "4a2446ee9651d90ac6c5613bddf416df197f6401",
            "dest": "C:\\Temp\\Executable.exe",
            "host": "123.123.123.123",
            "operation": "file_copy",
            "original_basename": "Executable.exe",
            "size": 32256,
            "src": "C:\\Important\\Executable.exe",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * checksum: 4a2446ee9651d90ac6c5613bddf416df197f6401
>  * dest: C:\Temp\Executable.exe
>  * operation: file_copy
>  * original_basename: Executable.exe
>  * size: 32256
>  * src: C:\Important\Executable.exe


### win-credential
***
Manages Windows Credentials in the Credential Manager
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_credential_module.html


#### Base Command

`win-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| alias | Adds an alias for the credential.<br/>Typically this is the NetBIOS name of a host if `name` is set to the DNS name. | Optional | 
| attributes | A list of dicts that set application specific attributes for a credential.<br/>When set, existing attributes will be compared to the list as a whole, any differences means all attributes will be replaced. | Optional | 
| comment | A user defined comment for the credential. | Optional | 
| name | The target that identifies the server or servers that the credential is to be used for.<br/>If the value can be a NetBIOS name, DNS server name, DNS host name suffix with a wildcard character (`*`), a NetBIOS of DNS domain name that contains a wildcard character sequence, or an asterisk.<br/>See `TargetName` in `https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentiala` for more details on what this value can be.<br/>This is used with `type` to produce a unique credential. | Required | 
| persistence | Defines the persistence of the credential.<br/>If `local`, the credential will persist for all logons of the same user on the same host.<br/>`enterprise` is the same as `local` but the credential is visible to the same domain user when running on other hosts and not just localhost. Possible values are: enterprise, local. Default is local. | Optional | 
| secret | The secret for the credential.<br/>When omitted, then no secret is used for the credential if a new credentials is created.<br/>When `type` is a password type, this is the password for `username`.<br/>When `type` is a certificate type, this is the pin for the certificate. | Optional | 
| secret_format | Controls the input type for `secret`.<br/>If `text`, `secret` is a text string that is UTF-16LE encoded to bytes.<br/>If `base64`, `secret` is a base64 string that is base64 decoded to bytes. Possible values are: base64, text. Default is text. | Optional | 
| state | When `absent`, the credential specified by `name` and `type` is removed.<br/>When `present`, the credential specified by `name` and `type` is removed. Possible values are: absent, present. Default is present. | Optional | 
| type | The type of credential to store.<br/>This is used with `name` to produce a unique credential.<br/>When the type is a `domain` type, the credential is used by Microsoft authentication packages like Negotiate.<br/>When the type is a `generic` type, the credential is not used by any particular authentication package.<br/>It is recommended to use a `domain` type as only authentication providers can access the secret. Possible values are: domain_certificate, domain_password, generic_certificate, generic_password. | Required | 
| update_secret | When `always`, the secret will always be updated if they differ.<br/>When `on_create`, the secret will only be checked/updated when it is first created.<br/>If the secret cannot be retrieved and this is set to `always`, the module will always result in a change. Possible values are: always, on_create. Default is always. | Optional | 
| username | When `type` is a password type, then this is the username to store for the credential.<br/>When `type` is a credential type, then this is the thumbprint as a hex string of the certificate to use.<br/>When `type=domain_password`, this should be in the form of a Netlogon (DOMAIN\Username) or a UPN (username@DOMAIN).<br/>If using a certificate thumbprint, the certificate must exist in the `CurrentUser\My` certificate store for the executing user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


### win-defrag
***
Consolidate fragmented files on local volumes
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_defrag_module.html


#### Base Command

`win-defrag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| include_volumes | A list of drive letters or mount point paths of the volumes to be defragmented.<br/>If this parameter is omitted, all volumes (not excluded) will be fragmented. | Optional | 
| exclude_volumes | A list of drive letters or mount point paths to exclude from defragmentation. | Optional | 
| freespace_consolidation | Perform free space consolidation on the specified volumes. Possible values are: Yes, No. Default is No. | Optional | 
| priority | Run the operation at low or normal priority. Possible values are: low, normal. Default is low. | Optional | 
| parallel | Run the operation on each volume in parallel in the background. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDefrag.cmd | string | The complete command line used by the module. | 
| MicrosoftWindows.WinDefrag.rc | number | The return code for the command. | 
| MicrosoftWindows.WinDefrag.stdout | string | The standard output from the command. | 
| MicrosoftWindows.WinDefrag.stderr | string | The error output from the command. | 
| MicrosoftWindows.WinDefrag.msg | string | Possible error message on failure. | 
| MicrosoftWindows.WinDefrag.changed | boolean | Whether or not any changes were made. | 


#### Command Example
```!win-defrag host="123.123.123.123" parallel="True" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinDefrag": {
            "changed": true,
            "cmd": "defrag.exe /C /M /V",
            "delta": "0:00:00.062484",
            "end": "2021-06-29 03:14:21.017314",
            "host": "123.123.123.123",
            "rc": 0,
            "start": "2021-06-29 03:14:20.954829",
            "status": "CHANGED",
            "stderr": "",
            "stderr_lines": [],
            "stdout": "Microsoft Drive Optimizer\r\nCopyright (c) 2013 Microsoft Corp.\r\n\r\nAn invalid command line option was specified. (0x89000008)\r\n\r\nDescription:\r\n\r\n\tOptimizes and defragments files on local volumes to\r\n\timprove system performance.\r\n\r\nSyntax:\r\n\r\n\tdefrag  | /C | /E  [<task(s)>] [/H] [/M [n] | [/U] [/V]] [/I n]\r\n\r\n\tWhere <task(s)> is omitted (traditional defrag), or as follows:\r\n\t\t/A | [/D] [/K] [/L] | /O | /X\r\n\r\n\tOr, to track an operation already in progress on a volume:\r\n\tdefrag  /T\r\n\r\nParameters:\r\n\r\n\tValue\tDescription\r\n\r\n\t/A\tPerform analysis on the specified volumes.\r\n\r\n\t/C\tPerform the operation on all volumes.\r\n\r\n\t/D\tPerform traditional defrag (this is the default).\r\n\r\n\t/E\tPerform the operation on all volumes except those specified.\r\n\r\n\t/G\tOptimize the storage tiers on the specified volumes.\r\n\r\n\t/H\tRun the operation at normal priority (default is low).\r\n\r\n\t/I n\tTier optimization would run for at most n seconds on each volume.\r\n\r\n\t/K\tPerform slab consolidation on the specified volumes.\r\n\r\n\t/L\tPerform retrim on the specified volumes.\r\n\r\n\t/M [n]\tRun the operation on each volume in parallel in the background.\r\n\t\tAt most n threads optimize the storage tiers in parallel.\r\n\r\n\t/O\tPerform the proper optimization for each media type.\r\n\r\n\t/T\tTrack an operation already in progress on the specified volume.\r\n\r\n\t/U\tPrint the progress of the operation on the screen.\r\n\r\n\t/V\tPrint verbose output containing the fragmentation statistics.\r\n\r\n\t/X\tPerform free space consolidation on the specified volumes.\r\n\r\nExamples:\r\n\r\n\tdefrag C: /U /V\r\n\tdefrag C: D: /M\r\n\tdefrag C:\\mountpoint /A /U\r\n\tdefrag /C /H /V\r\n",
            "stdout_lines": [
                "Microsoft Drive Optimizer",
                "Copyright (c) 2013 Microsoft Corp.",
                "",
                "An invalid command line option was specified. (0x89000008)",
                "",
                "Description:",
                "",
                "\tOptimizes and defragments files on local volumes to",
                "\timprove system performance.",
                "",
                "Syntax:",
                "",
                "\tdefrag | /C | /E  [<task(s)>] [/H] [/M [n] | [/U] [/V]] [/I n]",
                "",
                "\tWhere <task(s)> is omitted (traditional defrag), or as follows:",
                "\t\t/A | [/D] [/K] [/L] | /O | /X",
                "",
                "\tOr, to track an operation already in progress on a volume:",
                "\tdefrag  /T",
                "",
                "Parameters:",
                "",
                "\tValue\tDescription",
                "",
                "\t/A\tPerform analysis on the specified volumes.",
                "",
                "\t/C\tPerform the operation on all volumes.",
                "",
                "\t/D\tPerform traditional defrag (this is the default).",
                "",
                "\t/E\tPerform the operation on all volumes except those specified.",
                "",
                "\t/G\tOptimize the storage tiers on the specified volumes.",
                "",
                "\t/H\tRun the operation at normal priority (default is low).",
                "",
                "\t/I n\tTier optimization would run for at most n seconds on each volume.",
                "",
                "\t/K\tPerform slab consolidation on the specified volumes.",
                "",
                "\t/L\tPerform retrim on the specified volumes.",
                "",
                "\t/M [n]\tRun the operation on each volume in parallel in the background.",
                "\t\tAt most n threads optimize the storage tiers in parallel.",
                "",
                "\t/O\tPerform the proper optimization for each media type.",
                "",
                "\t/T\tTrack an operation already in progress on the specified volume.",
                "",
                "\t/U\tPrint the progress of the operation on the screen.",
                "",
                "\t/V\tPrint verbose output containing the fragmentation statistics.",
                "",
                "\t/X\tPerform free space consolidation on the specified volumes.",
                "",
                "Examples:",
                "",
                "\tdefrag C: /U /V",
                "\tdefrag C: D: /M",
                "\tdefrag C:\\mountpoint /A /U",
                "\tdefrag /C /H /V"
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * cmd: defrag.exe /C /M /V
>  * delta: 0:00:00.062484
>  * end: 2021-06-29 03:14:21.017314
>  * rc: 0
>  * start: 2021-06-29 03:14:20.954829
>  * stderr: 
>  * stdout: Microsoft Drive Optimizer
>Copyright (c) 2013 Microsoft Corp.
>
>An invalid command line option was specified. (0x89000008)
>
>Description:
>
>	Optimizes and defragments files on local volumes to
>	improve system performance.
>
>Syntax:
>
>	defrag  | /C | /E  [<task(s)>] [/H] [/M [n] | [/U] [/V]] [/I n]
>
>	Where <task(s)> is omitted (traditional defrag), or as follows:
>		/A | [/D] [/K] [/L] | /O | /X
>
>	Or, to track an operation already in progress on a volume:
>	defrag  /T
>
>Parameters:
>
>	Value	Description
>
>	/A	Perform analysis on the specified volumes.
>
>	/C	Perform the operation on all volumes.
>
>	/D	Perform traditional defrag (this is the default).
>
>	/E	Perform the operation on all volumes except those specified.
>
>	/G	Optimize the storage tiers on the specified volumes.
>
>	/H	Run the operation at normal priority (default is low).
>
>	/I n	Tier optimization would run for at most n seconds on each volume.
>
>	/K	Perform slab consolidation on the specified volumes.
>
>	/L	Perform retrim on the specified volumes.
>
>	/M [n]	Run the operation on each volume in parallel in the background.
>		At most n threads optimize the storage tiers in parallel.
>
>	/O	Perform the proper optimization for each media type.
>
>	/T	Track an operation already in progress on the specified volume.
>
>	/U	Print the progress of the operation on the screen.
>
>	/V	Print verbose output containing the fragmentation statistics.
>
>	/X	Perform free space consolidation on the specified volumes.
>
>Examples:
>
>	defrag C: /U /V
>	defrag C: D: /M
>	defrag C:\mountpoint /A /U
>	defrag /C /H /V
>
>  * ## Stderr_Lines
>  * ## Stdout_Lines
>    * 0: Microsoft Drive Optimizer
>    * 1: Copyright (c) 2013 Microsoft Corp.
>    * 2: 
>    * 3: An invalid command line option was specified. (0x89000008)
>    * 2: 
>    * 5: Description:
>    * 2: 
>    * 7: 	Optimizes and defragments files on local volumes to
>    * 8: 	improve system performance.
>    * 2: 
>    * 10: Syntax:
>    * 2: 
>    * 12: 	defrag  | /C | /E  [<task(s)>] [/H] [/M [n] | [/U] [/V]] [/I n]
>    * 2: 
>    * 14: 	Where <task(s)> is omitted (traditional defrag), or as follows:
>    * 15: 		/A | [/D] [/K] [/L] | /O | /X
>    * 2: 
>    * 17: 	Or, to track an operation already in progress on a volume:
>    * 18: 	defrag  /T
>    * 2: 
>    * 20: Parameters:
>    * 2: 
>    * 22: 	Value	Description
>    * 2: 
>    * 24: 	/A	Perform analysis on the specified volumes.
>    * 2: 
>    * 26: 	/C	Perform the operation on all volumes.
>    * 2: 
>    * 28: 	/D	Perform traditional defrag (this is the default).
>    * 2: 
>    * 30: 	/E	Perform the operation on all volumes except those specified.
>    * 2: 
>    * 32: 	/G	Optimize the storage tiers on the specified volumes.
>    * 2: 
>    * 34: 	/H	Run the operation at normal priority (default is low).
>    * 2: 
>    * 36: 	/I n	Tier optimization would run for at most n seconds on each volume.
>    * 2: 
>    * 38: 	/K	Perform slab consolidation on the specified volumes.
>    * 2: 
>    * 40: 	/L	Perform retrim on the specified volumes.
>    * 2: 
>    * 42: 	/M [n]	Run the operation on each volume in parallel in the background.
>    * 43: 		At most n threads optimize the storage tiers in parallel.
>    * 2: 
>    * 45: 	/O	Perform the proper optimization for each media type.
>    * 2: 
>    * 47: 	/T	Track an operation already in progress on the specified volume.
>    * 2: 
>    * 49: 	/U	Print the progress of the operation on the screen.
>    * 2: 
>    * 51: 	/V	Print verbose output containing the fragmentation statistics.
>    * 2: 
>    * 53: 	/X	Perform free space consolidation on the specified volumes.
>    * 2: 
>    * 55: Examples:
>    * 2: 
>    * 57: 	defrag C: /U /V
>    * 58: 	defrag C: D: /M
>    * 59: 	defrag C:\mountpoint /A /U
>    * 60: 	defrag /C /H /V


### win-disk-facts
***
Show the attached disks and disk information of the target host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_disk_facts_module.html


#### Base Command

`win-disk-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDiskFacts.facts | unknown | Dictionary containing all the detailed information about the disks of the target. | 


#### Command Example
```!win-disk-facts host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinDiskFacts": {
            "disks": [
                {
                    "bootable": true,
                    "bus_type": "SAS",
                    "clustered": false,
                    "firmware_version": "2.0 ",
                    "friendly_name": "VMware Virtual disk",
                    "guid": null,
                    "location": "SCSI0",
                    "manufacturer": "VMware  ",
                    "model": "Virtual disk    ",
                    "number": 0,
                    "operational_status": "Online",
                    "partition_count": 2,
                    "partition_style": "MBR",
                    "partitions": [
                        {
                            "access_paths": [
                                "\\\\?\\Volume{da4b1e8a-0000-0000-0000-100000000000}\\"
                            ],
                            "active": true,
                            "drive_letter": null,
                            "guid": null,
                            "hidden": false,
                            "mbr_type": 7,
                            "number": 1,
                            "offset": 1048576,
                            "shadow_copy": false,
                            "size": 524288000,
                            "transition_state": 1,
                            "type": "IFS",
                            "volumes": [
                                {
                                    "allocation_unit_size": 4096,
                                    "drive_type": "Fixed",
                                    "health_status": "Healthy",
                                    "label": "System Reserved",
                                    "object_id": "{1}\\\\WIN-U425UI0HPP7\\root/Microsoft/Windows/Storage/Providers_v2\\WSP_Volume.ObjectId=\"{65f97678-bd69-11eb-88d8-806e6f6e6963}:VO:\\\\?\\Volume{da4b1e8a-0000-0000-0000-100000000000}\\\"",
                                    "path": "\\\\?\\Volume{da4b1e8a-0000-0000-0000-100000000000}\\",
                                    "size": 524283904,
                                    "size_remaining": 179843072,
                                    "type": "NTFS"
                                }
                            ]
                        },
                        {
                            "access_paths": [
                                "C:\\",
                                "\\\\?\\Volume{da4b1e8a-0000-0000-0000-501f00000000}\\"
                            ],
                            "active": false,
                            "drive_letter": "C",
                            "guid": null,
                            "hidden": false,
                            "mbr_type": 7,
                            "number": 2,
                            "offset": 525336576,
                            "shadow_copy": false,
                            "size": 15579742208,
                            "transition_state": 1,
                            "type": "IFS",
                            "volumes": [
                                {
                                    "allocation_unit_size": 4096,
                                    "drive_type": "Fixed",
                                    "health_status": "Healthy",
                                    "label": "",
                                    "object_id": "{1}\\\\WIN-U425UI0HPP7\\root/Microsoft/Windows/Storage/Providers_v2\\WSP_Volume.ObjectId=\"{65f97678-bd69-11eb-88d8-806e6f6e6963}:VO:\\\\?\\Volume{da4b1e8a-0000-0000-0000-501f00000000}\\\"",
                                    "path": "\\\\?\\Volume{da4b1e8a-0000-0000-0000-501f00000000}\\",
                                    "size": 15579738112,
                                    "size_remaining": 1943584768,
                                    "type": "NTFS"
                                }
                            ]
                        }
                    ],
                    "path": "\\\\?\\scsi#disk&ven_vmware&prod_virtual_disk#5&1ec51bf7&0&000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
                    "physical_disk": {
                        "allocated_size": 16106127360,
                        "bus_type": "SAS",
                        "can_pool": false,
                        "cannot_pool_reason": "Insufficient Capacity",
                        "device_id": "0",
                        "firmware_version": "2.0",
                        "friendly_name": "VMware Virtual disk",
                        "health_status": "Healthy",
                        "indication_enabled": null,
                        "manufacturer": "VMware",
                        "media_type": "SSD",
                        "model": "Virtual disk",
                        "object_id": "{1}\\\\WIN-U425UI0HPP7\\root/Microsoft/Windows/Storage/Providers_v2\\SPACES_PhysicalDisk.ObjectId=\"{65f97678-bd69-11eb-88d8-806e6f6e6963}:PD:{2ab9f649-d867-11eb-88db-806e6f6e6963}\"",
                        "operational_status": "OK",
                        "partial": true,
                        "physical_location": "SCSI0",
                        "serial_number": null,
                        "size": 16106127360,
                        "spindle_speed": 0,
                        "supported_usages": {
                            "Count": 5,
                            "value": [
                                "Auto-Select",
                                "Manual-Select",
                                "Hot Spare",
                                "Retired",
                                "Journal"
                            ]
                        },
                        "unique_id": "{2ab9f649-d867-11eb-88db-806e6f6e6963}",
                        "usage_type": "Auto-Select"
                    },
                    "read_only": false,
                    "sector_size": 512,
                    "serial_number": null,
                    "size": 16106127360,
                    "system_disk": true,
                    "unique_id": "SCSI\\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\\5&1EC51BF7&0&000000:WIN-U425UI0HPP7",
                    "win32_disk_drive": {
                        "availability": null,
                        "bytes_per_sector": 512,
                        "capabilities": [
                            3,
                            4
                        ],
                        "capability_descriptions": [
                            "Random Access",
                            "Supports Writing"
                        ],
                        "caption": "VMware Virtual disk SCSI Disk Device",
                        "compression_method": null,
                        "config_manager_error_code": 0,
                        "config_manager_user_config": false,
                        "creation_class_name": "Win32_DiskDrive",
                        "default_block_size": null,
                        "description": "Disk drive",
                        "device_id": "\\\\.\\PHYSICALDRIVE0",
                        "error_cleared": null,
                        "error_description": null,
                        "error_methodology": null,
                        "firmware_revision": "2.0 ",
                        "index": 0,
                        "install_date": null,
                        "interface_type": "SCSI",
                        "last_error_code": null,
                        "manufacturer": "(Standard disk drives)",
                        "max_block_size": null,
                        "max_media_size": null,
                        "media_loaded": true,
                        "media_type": "Fixed hard disk media",
                        "min_block_size": null,
                        "model": "VMware Virtual disk SCSI Disk Device",
                        "name": "\\\\.\\PHYSICALDRIVE0",
                        "needs_cleaning": null,
                        "number_of_media_supported": null,
                        "partitions": 4,
                        "pnp_device_id": "SCSI\\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\\5&1EC51BF7&0&000000",
                        "power_management_capabilities": null,
                        "power_management_supported": null,
                        "scsi_bus": 0,
                        "scsi_logical_unit": 0,
                        "scsi_port": 0,
                        "scsi_target_id": 0,
                        "sectors_per_track": 63,
                        "serial_number": null,
                        "signature": 3662356106,
                        "size": 16105098240,
                        "status": "OK",
                        "status_info": null,
                        "system_creation_class_name": "Win32_ComputerSystem",
                        "system_name": "WIN-U425UI0HPP7",
                        "total_cylinders": 1958,
                        "total_heads": 255,
                        "total_sectors": 31455270,
                        "total_tracks": 499290,
                        "tracks_per_cylinder": 255
                    }
                },
                {
                    "bootable": false,
                    "bus_type": "SAS",
                    "clustered": false,
                    "firmware_version": "2.0 ",
                    "friendly_name": "VMware Virtual disk",
                    "guid": null,
                    "location": "SCSI0",
                    "manufacturer": "VMware  ",
                    "model": "Virtual disk    ",
                    "number": 1,
                    "operational_status": "Online",
                    "partition_count": 1,
                    "partition_style": "MBR",
                    "partitions": [
                        {
                            "access_paths": [
                                "F:\\",
                                "\\\\?\\Volume{75516713-0000-0000-0000-010000000000}\\"
                            ],
                            "active": false,
                            "drive_letter": "F",
                            "guid": null,
                            "hidden": false,
                            "mbr_type": 7,
                            "number": 1,
                            "offset": 65536,
                            "shadow_copy": false,
                            "size": 16777216,
                            "transition_state": 1,
                            "type": "IFS",
                            "volumes": [
                                {
                                    "allocation_unit_size": 4096,
                                    "drive_type": "Fixed",
                                    "health_status": "Healthy",
                                    "label": "New Volume",
                                    "object_id": "{1}\\\\WIN-U425UI0HPP7\\root/Microsoft/Windows/Storage/Providers_v2\\WSP_Volume.ObjectId=\"{65f97678-bd69-11eb-88d8-806e6f6e6963}:VO:\\\\?\\Volume{75516713-0000-0000-0000-010000000000}\\\"",
                                    "path": "\\\\?\\Volume{75516713-0000-0000-0000-010000000000}\\",
                                    "size": 16773120,
                                    "size_remaining": 6569984,
                                    "type": "NTFS"
                                }
                            ]
                        }
                    ],
                    "path": "\\\\?\\scsi#disk&ven_vmware&prod_virtual_disk#5&1ec51bf7&0&000100#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
                    "physical_disk": {
                        "allocated_size": 2097152,
                        "bus_type": "SAS",
                        "can_pool": false,
                        "cannot_pool_reason": "Insufficient Capacity",
                        "device_id": "1",
                        "firmware_version": "2.0",
                        "friendly_name": "VMware Virtual disk",
                        "health_status": "Healthy",
                        "indication_enabled": null,
                        "manufacturer": "VMware",
                        "media_type": "SSD",
                        "model": "Virtual disk",
                        "object_id": "{1}\\\\WIN-U425UI0HPP7\\root/Microsoft/Windows/Storage/Providers_v2\\SPACES_PhysicalDisk.ObjectId=\"{65f97678-bd69-11eb-88d8-806e6f6e6963}:PD:{2aba10d3-d867-11eb-88db-000c29740042}\"",
                        "operational_status": "OK",
                        "partial": false,
                        "physical_location": "SCSI0",
                        "serial_number": null,
                        "size": 19922944,
                        "spindle_speed": 0,
                        "supported_usages": {
                            "Count": 5,
                            "value": [
                                "Auto-Select",
                                "Manual-Select",
                                "Hot Spare",
                                "Retired",
                                "Journal"
                            ]
                        },
                        "unique_id": "{2aba10d3-d867-11eb-88db-000c29740042}",
                        "usage_type": "Auto-Select"
                    },
                    "read_only": false,
                    "sector_size": 512,
                    "serial_number": null,
                    "size": 19922944,
                    "system_disk": false,
                    "unique_id": "SCSI\\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\\5&1EC51BF7&0&000100:WIN-U425UI0HPP7",
                    "win32_disk_drive": {
                        "availability": null,
                        "bytes_per_sector": 512,
                        "capabilities": [
                            3,
                            4
                        ],
                        "capability_descriptions": [
                            "Random Access",
                            "Supports Writing"
                        ],
                        "caption": "VMware Virtual disk SCSI Disk Device",
                        "compression_method": null,
                        "config_manager_error_code": 0,
                        "config_manager_user_config": false,
                        "creation_class_name": "Win32_DiskDrive",
                        "default_block_size": null,
                        "description": "Disk drive",
                        "device_id": "\\\\.\\PHYSICALDRIVE1",
                        "error_cleared": null,
                        "error_description": null,
                        "error_methodology": null,
                        "firmware_revision": "2.0 ",
                        "index": 1,
                        "install_date": null,
                        "interface_type": "SCSI",
                        "last_error_code": null,
                        "manufacturer": "(Standard disk drives)",
                        "max_block_size": null,
                        "max_media_size": null,
                        "media_loaded": true,
                        "media_type": "Fixed hard disk media",
                        "min_block_size": null,
                        "model": "VMware Virtual disk SCSI Disk Device",
                        "name": "\\\\.\\PHYSICALDRIVE1",
                        "needs_cleaning": null,
                        "number_of_media_supported": null,
                        "partitions": 4,
                        "pnp_device_id": "SCSI\\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\\5&1EC51BF7&0&000100",
                        "power_management_capabilities": null,
                        "power_management_supported": null,
                        "scsi_bus": 0,
                        "scsi_logical_unit": 0,
                        "scsi_port": 0,
                        "scsi_target_id": 1,
                        "sectors_per_track": 63,
                        "serial_number": null,
                        "signature": 1968269075,
                        "size": 16450560,
                        "status": "OK",
                        "status_info": null,
                        "system_creation_class_name": "Win32_ComputerSystem",
                        "system_name": "WIN-U425UI0HPP7",
                        "total_cylinders": 2,
                        "total_heads": 255,
                        "total_sectors": 32130,
                        "total_tracks": 510,
                        "tracks_per_cylinder": 255
                    }
                }
            ],
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * ## Disks
>  * ## Vmware Virtual Disk
>    * bootable: True
>    * bus_type: SAS
>    * clustered: False
>    * firmware_version: 2.0 
>    * friendly_name: VMware Virtual disk
>    * guid: None
>    * location: SCSI0
>    * manufacturer: VMware  
>    * model: Virtual disk    
>    * number: 0
>    * operational_status: Online
>    * partition_count: 2
>    * partition_style: MBR
>    * path: \\?\scsi#disk&ven_vmware&prod_virtual_disk#5&1ec51bf7&0&000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
>    * read_only: False
>    * sector_size: 512
>    * serial_number: None
>    * size: 16106127360
>    * system_disk: True
>    * unique_id: SCSI\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\5&1EC51BF7&0&000000:WIN-U425UI0HPP7
>    * ### Partitions
>    * ### List
>      * active: True
>      * drive_letter: None
>      * guid: None
>      * hidden: False
>      * mbr_type: 7
>      * number: 1
>      * offset: 1048576
>      * shadow_copy: False
>      * size: 524288000
>      * transition_state: 1
>      * type: IFS
>      * #### Access_Paths
>        * 0: \\?\Volume{da4b1e8a-0000-0000-0000-100000000000}\
>      * #### Volumes
>      * #### {1}\\Win-U425Ui0Hpp7\Root/Microsoft/Windows/Storage/Providers_V2\Wsp_Volume.Objectid="{65F97678-Bd69-11Eb-88D8-806E6F6E6963}:Vo:\\?\Volume{Da4B1E8A-0000-0000-0000-100000000000}\"
>        * allocation_unit_size: 4096
>        * drive_type: Fixed
>        * health_status: Healthy
>        * label: System Reserved
>        * object_id: {1}\\WIN-U425UI0HPP7\root/Microsoft/Windows/Storage/Providers_v2\WSP_Volume.ObjectId="{65f97678-bd69-11eb-88d8-806e6f6e6963}:VO:\\?\Volume{da4b1e8a-0000-0000-0000-100000000000}\"
>        * path: \\?\Volume{da4b1e8a-0000-0000-0000-100000000000}\
>        * size: 524283904
>        * size_remaining: 179843072
>        * type: NTFS
>    * ### List
>      * active: False
>      * drive_letter: C
>      * guid: None
>      * hidden: False
>      * mbr_type: 7
>      * number: 2
>      * offset: 525336576
>      * shadow_copy: False
>      * size: 15579742208
>      * transition_state: 1
>      * type: IFS
>      * #### Access_Paths
>        * 0: C:\
>        * 1: \\?\Volume{da4b1e8a-0000-0000-0000-501f00000000}\
>      * #### Volumes
>      * #### {1}\\Win-U425Ui0Hpp7\Root/Microsoft/Windows/Storage/Providers_V2\Wsp_Volume.Objectid="{65F97678-Bd69-11Eb-88D8-806E6F6E6963}:Vo:\\?\Volume{Da4B1E8A-0000-0000-0000-501F00000000}\"
>        * allocation_unit_size: 4096
>        * drive_type: Fixed
>        * health_status: Healthy
>        * label: 
>        * object_id: {1}\\WIN-U425UI0HPP7\root/Microsoft/Windows/Storage/Providers_v2\WSP_Volume.ObjectId="{65f97678-bd69-11eb-88d8-806e6f6e6963}:VO:\\?\Volume{da4b1e8a-0000-0000-0000-501f00000000}\"
>        * path: \\?\Volume{da4b1e8a-0000-0000-0000-501f00000000}\
>        * size: 15579738112
>        * size_remaining: 1943584768
>        * type: NTFS
>    * ### Physical_Disk
>      * allocated_size: 16106127360
>      * bus_type: SAS
>      * can_pool: False
>      * cannot_pool_reason: Insufficient Capacity
>      * device_id: 0
>      * firmware_version: 2.0
>      * friendly_name: VMware Virtual disk
>      * health_status: Healthy
>      * indication_enabled: None
>      * manufacturer: VMware
>      * media_type: SSD
>      * model: Virtual disk
>      * object_id: {1}\\WIN-U425UI0HPP7\root/Microsoft/Windows/Storage/Providers_v2\SPACES_PhysicalDisk.ObjectId="{65f97678-bd69-11eb-88d8-806e6f6e6963}:PD:{2ab9f649-d867-11eb-88db-806e6f6e6963}"
>      * operational_status: OK
>      * partial: True
>      * physical_location: SCSI0
>      * serial_number: None
>      * size: 16106127360
>      * spindle_speed: 0
>      * unique_id: {2ab9f649-d867-11eb-88db-806e6f6e6963}
>      * usage_type: Auto-Select
>      * #### Supported_Usages
>        * Count: 5
>        * ##### Value
>          * 0: Auto-Select
>          * 1: Manual-Select
>          * 2: Hot Spare
>          * 3: Retired
>          * 4: Journal
>    * ### Win32_Disk_Drive
>      * availability: None
>      * bytes_per_sector: 512
>      * caption: VMware Virtual disk SCSI Disk Device
>      * compression_method: None
>      * config_manager_error_code: 0
>      * config_manager_user_config: False
>      * creation_class_name: Win32_DiskDrive
>      * default_block_size: None
>      * description: Disk drive
>      * device_id: \\.\PHYSICALDRIVE0
>      * error_cleared: None
>      * error_description: None
>      * error_methodology: None
>      * firmware_revision: 2.0 
>      * index: 0
>      * install_date: None
>      * interface_type: SCSI
>      * last_error_code: None
>      * manufacturer: (Standard disk drives)
>      * max_block_size: None
>      * max_media_size: None
>      * media_loaded: True
>      * media_type: Fixed hard disk media
>      * min_block_size: None
>      * model: VMware Virtual disk SCSI Disk Device
>      * name: \\.\PHYSICALDRIVE0
>      * needs_cleaning: None
>      * number_of_media_supported: None
>      * partitions: 4
>      * pnp_device_id: SCSI\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\5&1EC51BF7&0&000000
>      * power_management_capabilities: None
>      * power_management_supported: None
>      * scsi_bus: 0
>      * scsi_logical_unit: 0
>      * scsi_port: 0
>      * scsi_target_id: 0
>      * sectors_per_track: 63
>      * serial_number: None
>      * signature: 3662356106
>      * size: 16105098240
>      * status: OK
>      * status_info: None
>      * system_creation_class_name: Win32_ComputerSystem
>      * system_name: WIN-U425UI0HPP7
>      * total_cylinders: 1958
>      * total_heads: 255
>      * total_sectors: 31455270
>      * total_tracks: 499290
>      * tracks_per_cylinder: 255
>      * #### Capabilities
>        * 0: 3
>        * 1: 4
>      * #### Capability_Descriptions
>        * 0: Random Access
>        * 1: Supports Writing
>  * ## Vmware Virtual Disk
>    * bootable: False
>    * bus_type: SAS
>    * clustered: False
>    * firmware_version: 2.0 
>    * friendly_name: VMware Virtual disk
>    * guid: None
>    * location: SCSI0
>    * manufacturer: VMware  
>    * model: Virtual disk    
>    * number: 1
>    * operational_status: Online
>    * partition_count: 1
>    * partition_style: MBR
>    * path: \\?\scsi#disk&ven_vmware&prod_virtual_disk#5&1ec51bf7&0&000100#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
>    * read_only: False
>    * sector_size: 512
>    * serial_number: None
>    * size: 19922944
>    * system_disk: False
>    * unique_id: SCSI\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\5&1EC51BF7&0&000100:WIN-U425UI0HPP7
>    * ### Partitions
>    * ### List
>      * active: False
>      * drive_letter: F
>      * guid: None
>      * hidden: False
>      * mbr_type: 7
>      * number: 1
>      * offset: 65536
>      * shadow_copy: False
>      * size: 16777216
>      * transition_state: 1
>      * type: IFS
>      * #### Access_Paths
>        * 0: F:\
>        * 1: \\?\Volume{75516713-0000-0000-0000-010000000000}\
>      * #### Volumes
>      * #### {1}\\Win-U425Ui0Hpp7\Root/Microsoft/Windows/Storage/Providers_V2\Wsp_Volume.Objectid="{65F97678-Bd69-11Eb-88D8-806E6F6E6963}:Vo:\\?\Volume{75516713-0000-0000-0000-010000000000}\"
>        * allocation_unit_size: 4096
>        * drive_type: Fixed
>        * health_status: Healthy
>        * label: New Volume
>        * object_id: {1}\\WIN-U425UI0HPP7\root/Microsoft/Windows/Storage/Providers_v2\WSP_Volume.ObjectId="{65f97678-bd69-11eb-88d8-806e6f6e6963}:VO:\\?\Volume{75516713-0000-0000-0000-010000000000}\"
>        * path: \\?\Volume{75516713-0000-0000-0000-010000000000}\
>        * size: 16773120
>        * size_remaining: 6569984
>        * type: NTFS
>    * ### Physical_Disk
>      * allocated_size: 2097152
>      * bus_type: SAS
>      * can_pool: False
>      * cannot_pool_reason: Insufficient Capacity
>      * device_id: 1
>      * firmware_version: 2.0
>      * friendly_name: VMware Virtual disk
>      * health_status: Healthy
>      * indication_enabled: None
>      * manufacturer: VMware
>      * media_type: SSD
>      * model: Virtual disk
>      * object_id: {1}\\WIN-U425UI0HPP7\root/Microsoft/Windows/Storage/Providers_v2\SPACES_PhysicalDisk.ObjectId="{65f97678-bd69-11eb-88d8-806e6f6e6963}:PD:{2aba10d3-d867-11eb-88db-000c29740042}"
>      * operational_status: OK
>      * partial: False
>      * physical_location: SCSI0
>      * serial_number: None
>      * size: 19922944
>      * spindle_speed: 0
>      * unique_id: {2aba10d3-d867-11eb-88db-000c29740042}
>      * usage_type: Auto-Select
>      * #### Supported_Usages
>        * Count: 5
>        * ##### Value
>          * 0: Auto-Select
>          * 1: Manual-Select
>          * 2: Hot Spare
>          * 3: Retired
>          * 4: Journal
>    * ### Win32_Disk_Drive
>      * availability: None
>      * bytes_per_sector: 512
>      * caption: VMware Virtual disk SCSI Disk Device
>      * compression_method: None
>      * config_manager_error_code: 0
>      * config_manager_user_config: False
>      * creation_class_name: Win32_DiskDrive
>      * default_block_size: None
>      * description: Disk drive
>      * device_id: \\.\PHYSICALDRIVE1
>      * error_cleared: None
>      * error_description: None
>      * error_methodology: None
>      * firmware_revision: 2.0 
>      * index: 1
>      * install_date: None
>      * interface_type: SCSI
>      * last_error_code: None
>      * manufacturer: (Standard disk drives)
>      * max_block_size: None
>      * max_media_size: None
>      * media_loaded: True
>      * media_type: Fixed hard disk media
>      * min_block_size: None
>      * model: VMware Virtual disk SCSI Disk Device
>      * name: \\.\PHYSICALDRIVE1
>      * needs_cleaning: None
>      * number_of_media_supported: None
>      * partitions: 4
>      * pnp_device_id: SCSI\DISK&VEN_VMWARE&PROD_VIRTUAL_DISK\5&1EC51BF7&0&000100
>      * power_management_capabilities: None
>      * power_management_supported: None
>      * scsi_bus: 0
>      * scsi_logical_unit: 0
>      * scsi_port: 0
>      * scsi_target_id: 1
>      * sectors_per_track: 63
>      * serial_number: None
>      * signature: 1968269075
>      * size: 16450560
>      * status: OK
>      * status_info: None
>      * system_creation_class_name: Win32_ComputerSystem
>      * system_name: WIN-U425UI0HPP7
>      * total_cylinders: 2
>      * total_heads: 255
>      * total_sectors: 32130
>      * total_tracks: 510
>      * tracks_per_cylinder: 255
>      * #### Capabilities
>        * 0: 3
>        * 1: 4
>      * #### Capability_Descriptions
>        * 0: Random Access
>        * 1: Supports Writing


### win-disk-image
***
Manage ISO/VHD/VHDX mounts on Windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_disk_image_module.html


#### Base Command

`win-disk-image`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| image_path | Path to an ISO, VHD, or VHDX image on the target Windows host (the file cannot reside on a network share). | Required | 
| state | Whether the image should be present as a drive-letter mount or not. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDiskImage.mount_path | string | Filesystem path where the target image is mounted, this has been deprecated in favour of \`mount_paths\`. | 
| MicrosoftWindows.WinDiskImage.mount_paths | unknown | A list of filesystem paths mounted from the target image. | 


#### Command Example
```!win-disk-image host="123.123.123.123" image_path="C:/install.iso" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinDiskImage": {
            "changed": true,
            "host": "123.123.123.123",
            "mount_paths": [
                "D:\\"
            ],
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Mount_Paths
>    * 0: D:\


### win-dns-client
***
Configures DNS lookup on Windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_dns_client_module.html


#### Base Command

`win-dns-client`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| adapter_names | Adapter name or list of adapter names for which to manage DNS settings ('*' is supported as a wildcard value).<br/>The adapter name used is the connection caption in the Network Control Panel or via `Get-NetAdapter`, eg `Local Area Connection`. | Required | 
| ipv4_addresses | Single or ordered list of DNS server IPv4 addresses to configure for lookup. An empty list will configure the adapter to use the DHCP-assigned values on connections where DHCP is enabled, or disable DNS lookup on statically-configured connections. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-dns-record
***
Manage Windows Server DNS records
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_dns_record_module.html


#### Base Command

`win-dns-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the record. | Required | 
| state | Whether the record should exist or not. Possible values are: absent, present. Default is present. | Optional | 
| ttl | The "time to live" of the record, in seconds.<br/>Ignored when `state=absent`.<br/>Valid range is 1 - 31557600.<br/>Note that an Active Directory forest can specify a minimum TTL, and will dynamically "round up" other values to that minimum. Default is 3600. | Optional | 
| type | The type of DNS record to manage. Possible values are: A, AAAA, CNAME, PTR. | Required | 
| value | The value(s) to specify. Required when `state=present`.<br/>When c(type=PTR) only the partial part of the IP should be given. | Optional | 
| zone | The name of the zone to manage (eg `example.com`).<br/>The zone must already exist. | Required | 
| computer_name | Specifies a DNS server.<br/>You can specify an IP address or any value that resolves to an IP address, such as a fully qualified domain name (FQDN), host name, or NETBIOS name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-domain
***
Ensures the existence of a Windows domain
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_module.html


#### Base Command

`win-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dns_domain_name | The DNS name of the domain which should exist and be reachable or reside on the target Windows host. | Required | 
| domain_netbios_name | The NetBIOS name for the root domain in the new forest.<br/>For NetBIOS names to be valid for use with this parameter they must be single label names of 15 characters or less, if not it will fail.<br/>If this parameter is not set, then the default is automatically computed from the value of the `domain_name` parameter. | Optional | 
| safe_mode_password | Safe mode password for the domain controller. | Required | 
| database_path | The path to a directory on a fixed disk of the Windows host where the domain database will be created.<br/>If not set then the default path is `%SYSTEMROOT%\NTDS`. | Optional | 
| sysvol_path | The path to a directory on a fixed disk of the Windows host where the Sysvol file will be created.<br/>If not set then the default path is `%SYSTEMROOT%\SYSVOL`. | Optional | 
| create_dns_delegation | Whether to create a DNS delegation that references the new DNS server that you install along with the domain controller.<br/>Valid for Active Directory-integrated DNS only.<br/>The default is computed automatically based on the environment. | Optional | 
| domain_mode | Specifies the domain functional level of the first domain in the creation of a new forest.<br/>The domain functional level cannot be lower than the forest functional level, but it can be higher.<br/>The default is automatically computed and set. Possible values are: Win2003, Win2008, Win2008R2, Win2012, Win2012R2, WinThreshold. | Optional | 
| forest_mode | Specifies the forest functional level for the new forest.<br/>The default forest functional level in Windows Server is typically the same as the version you are running. Possible values are: Win2003, Win2008, Win2008R2, Win2012, Win2012R2, WinThreshold. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDomain.reboot_required | boolean | True if changes were made that require a reboot. | 


#### Command Example
```!win-domain host="123.123.123.123" dns_domain_name="ansible.vagrant" safe_mode_password="password123!" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinDomain": {
            "changed": true,
            "host": "123.123.123.123",
            "reboot_required": true,
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * reboot_required: True


### win-domain-computer
***
Manage computers in Active Directory
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_computer_module.html


#### Base Command

`win-domain-computer`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Specifies the name of the object.<br/>This parameter sets the Name property of the Active Directory object.<br/>The LDAP display name (ldapDisplayName) of this property is name. | Required | 
| sam_account_name | Specifies the Security Account Manager (SAM) account name of the computer.<br/>It maximum is 256 characters, 15 is advised for older operating systems compatibility.<br/>The LDAP display name (ldapDisplayName) for this property is sAMAccountName.<br/>If ommitted the value is the same as `name`.<br/>Note that all computer SAMAccountNames need to end with a $. | Optional | 
| enabled | Specifies if an account is enabled.<br/>An enabled account requires a password.<br/>This parameter sets the Enabled property for an account object.<br/>This parameter also sets the ADS_UF_ACCOUNTDISABLE flag of the Active Directory User Account Control (UAC) attribute. Possible values are: Yes, No. Default is Yes. | Optional | 
| ou | Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created. Required when `state=present`. | Optional | 
| description | Specifies a description of the object.<br/>This parameter sets the value of the Description property for the object.<br/>The LDAP display name (ldapDisplayName) for this property is description. | Optional | 
| dns_hostname | Specifies the fully qualified domain name (FQDN) of the computer.<br/>This parameter sets the DNSHostName property for a computer object.<br/>The LDAP display name for this property is dNSHostName.<br/>Required when `state=present`. | Optional | 
| domain_username | The username to use when interacting with AD.<br/>If this is not set then the user Ansible used to log in with will be used instead when using CredSSP or Kerberos with credential delegation. | Optional | 
| domain_password | The password for `username`. | Optional | 
| domain_server | Specifies the Active Directory Domain Services instance to connect to.<br/>Can be in the form of an FQDN or NetBIOS name.<br/>If not specified then the value is based on the domain of the computer running PowerShell. | Optional | 
| state | Specified whether the computer should be `present` or `absent` in Active Directory. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-domain-controller
***
Manage domain controller/member server state for a Windows host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_controller_module.html


#### Base Command

`win-domain-controller`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dns_domain_name | When `state` is `domain_controller`, the DNS name of the domain for which the targeted Windows host should be a DC. | Optional | 
| domain_admin_user | Username of a domain admin for the target domain (necessary to promote or demote a domain controller). | Required | 
| domain_admin_password | Password for the specified `domain_admin_user`. | Required | 
| safe_mode_password | Safe mode password for the domain controller (required when `state` is `domain_controller`). | Optional | 
| local_admin_password | Password to be assigned to the local `Administrator` user (required when `state` is `member_server`). | Optional | 
| read_only | Whether to install the domain controller as a read only replica for an existing domain. Possible values are: Yes, No. Default is No. | Optional | 
| site_name | Specifies the name of an existing site where you can place the new domain controller.<br/>This option is required when `read_only` is `yes`. | Optional | 
| state | Whether the target host should be a domain controller or a member server. Possible values are: domain_controller, member_server. | Optional | 
| database_path | The path to a directory on a fixed disk of the Windows host where the domain database will be created..<br/>If not set then the default path is `%SYSTEMROOT%\NTDS`. | Optional | 
| sysvol_path | The path to a directory on a fixed disk of the Windows host where the Sysvol folder will be created.<br/>If not set then the default path is `%SYSTEMROOT%\SYSVOL`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDomainController.reboot_required | boolean | True if changes were made that require a reboot. | 




### win-domain-group
***
Creates, modifies or removes domain groups
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_group_module.html


#### Base Command

`win-domain-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| attributes | A dict of custom LDAP attributes to set on the group.<br/>This can be used to set custom attributes that are not exposed as module parameters, e.g. `mail`.<br/>See the examples on how to format this parameter. | Optional | 
| category | The category of the group, this is the value to assign to the LDAP `groupType` attribute.<br/>If a new group is created then `security` will be used by default. Possible values are: distribution, security. | Optional | 
| description | The value to be assigned to the LDAP `description` attribute. | Optional | 
| display_name | The value to assign to the LDAP `displayName` attribute. | Optional | 
| domain_username | The username to use when interacting with AD.<br/>If this is not set then the user Ansible used to log in with will be used instead. | Optional | 
| domain_password | The password for `username`. | Optional | 
| domain_server | Specifies the Active Directory Domain Services instance to connect to.<br/>Can be in the form of an FQDN or NetBIOS name.<br/>If not specified then the value is based on the domain of the computer running PowerShell. | Optional | 
| ignore_protection | Will ignore the `ProtectedFromAccidentalDeletion` flag when deleting or moving a group.<br/>The module will fail if one of these actions need to occur and this value is set to `no`. Possible values are: Yes, No. Default is No. | Optional | 
| managed_by | The value to be assigned to the LDAP `managedBy` attribute.<br/>This value can be in the forms `Distinguished Name`, `objectGUID`, `objectSid` or `sAMAccountName`, see examples for more details. | Optional | 
| name | The name of the group to create, modify or remove.<br/>This value can be in the forms `Distinguished Name`, `objectGUID`, `objectSid` or `sAMAccountName`, see examples for more details. | Required | 
| organizational_unit | The full LDAP path to create or move the group to.<br/>This should be the path to the parent object to create or move the group to.<br/>See examples for details of how this path is formed. | Optional | 
| protect | Will set the `ProtectedFromAccidentalDeletion` flag based on this value.<br/>This flag stops a user from deleting or moving a group to a different path. | Optional | 
| scope | The scope of the group.<br/>If `state=present` and the group doesn't exist then this must be set. Possible values are: domainlocal, global, universal. | Optional | 
| state | If `state=present` this module will ensure the group is created and is configured accordingly.<br/>If `state=absent` this module will delete the group if it exists. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDomainGroup.attributes | unknown | Custom attributes that were set by the module. This does not show all the custom attributes rather just the ones that were set by the module. | 
| MicrosoftWindows.WinDomainGroup.canonical_name | string | The canonical name of the group. | 
| MicrosoftWindows.WinDomainGroup.category | string | The Group type value of the group, i.e. Security or Distribution. | 
| MicrosoftWindows.WinDomainGroup.description | string | The Description of the group. | 
| MicrosoftWindows.WinDomainGroup.display_name | string | The Display name of the group. | 
| MicrosoftWindows.WinDomainGroup.distinguished_name | string | The full Distinguished Name of the group. | 
| MicrosoftWindows.WinDomainGroup.group_scope | string | The Group scope value of the group. | 
| MicrosoftWindows.WinDomainGroup.guid | string | The guid of the group. | 
| MicrosoftWindows.WinDomainGroup.managed_by | string | The full Distinguished Name of the AD object that is set on the managedBy attribute. | 
| MicrosoftWindows.WinDomainGroup.name | string | The name of the group. | 
| MicrosoftWindows.WinDomainGroup.protected_from_accidental_deletion | boolean | Whether the group is protected from accidental deletion. | 
| MicrosoftWindows.WinDomainGroup.sid | string | The Security ID of the group. | 
| MicrosoftWindows.WinDomainGroup.created | boolean | Whether a group was created | 




### win-domain-group-membership
***
Manage Windows domain group membership
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_group_membership_module.html


#### Base Command

`win-domain-group-membership`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the domain group to manage membership on. | Required | 
| members | A list of members to ensure are present/absent from the group.<br/>The given names must be a SamAccountName of a user, group, service account, or computer.<br/>For computers, you must add "$" after the name; for example, to add "Mycomputer" to a group, use "Mycomputer$" as the member. | Required | 
| state | Desired state of the members in the group.<br/>When `state` is `pure`, only the members specified will exist, and all other existing members not specified are removed. Possible values are: absent, present, pure. Default is present. | Optional | 
| domain_username | The username to use when interacting with AD.<br/>If this is not set then the user Ansible used to log in with will be used instead when using CredSSP or Kerberos with credential delegation. | Optional | 
| domain_password | The password for `username`. | Optional | 
| domain_server | Specifies the Active Directory Domain Services instance to connect to.<br/>Can be in the form of an FQDN or NetBIOS name.<br/>If not specified then the value is based on the domain of the computer running PowerShell. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDomainGroupMembership.name | string | The name of the target domain group. | 
| MicrosoftWindows.WinDomainGroupMembership.added | unknown | A list of members added when \`state\` is \`present\` or \`pure\`; this is empty if no members are added. | 
| MicrosoftWindows.WinDomainGroupMembership.removed | unknown | A list of members removed when \`state\` is \`absent\` or \`pure\`; this is empty if no members are removed. | 
| MicrosoftWindows.WinDomainGroupMembership.members | unknown | A list of all domain group members at completion; this is empty if the group contains no members. | 




### win-domain-membership
***
Manage domain/workgroup membership for a Windows host
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_membership_module.html


#### Base Command

`win-domain-membership`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dns_domain_name | When `state` is `domain`, the DNS name of the domain to which the targeted Windows host should be joined. | Optional | 
| domain_admin_user | Username of a domain admin for the target domain (required to join or leave the domain). | Required | 
| domain_admin_password | Password for the specified `domain_admin_user`. | Optional | 
| hostname | The desired hostname for the Windows host. | Optional | 
| domain_ou_path | The desired OU path for adding the computer object.<br/>This is only used when adding the target host to a domain, if it is already a member then it is ignored. | Optional | 
| state | Whether the target host should be a member of a domain or workgroup. Possible values are: domain, workgroup. | Optional | 
| workgroup_name | When `state` is `workgroup`, the name of the workgroup that the Windows host should be in. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDomainMembership.reboot_required | boolean | True if changes were made that require a reboot. | 




### win-domain-user
***
Manages Windows Active Directory user accounts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_domain_user_module.html


#### Base Command

`win-domain-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the user to create, remove or modify. | Required | 
| state | When `present`, creates or updates the user account.<br/>When `absent`, removes the user account if it exists.<br/>When `query`, retrieves the user account details without making any changes. Possible values are: absent, present, query. Default is present. | Optional | 
| enabled | `yes` will enable the user account.<br/>`no` will disable the account. Possible values are: Yes, No. Default is Yes. | Optional | 
| account_locked | `no` will unlock the user account if locked.<br/>Note that there is not a way to lock an account as an administrator.<br/>Accounts are locked due to user actions; as an admin, you may only unlock a locked account.<br/>If you wish to administratively disable an account, set `enabled` to `no`. Possible values are: False. | Optional | 
| description | Description of the user. | Optional | 
| groups | Adds or removes the user from this list of groups, depending on the value of `groups_action`.<br/>To remove all but the Principal Group, set `groups=&lt;principal group name&gt;` and `groups_action=replace`.<br/>Note that users cannot be removed from their principal group (for example, "Domain Users"). | Optional | 
| groups_action | If `add`, the user is added to each group in `groups` where not already a member.<br/>If `remove`, the user is removed from each group in `groups`.<br/>If `replace`, the user is added as a member of each group in `groups` and removed from any other groups. Possible values are: add, remove, replace. Default is replace. | Optional | 
| password | Optionally set the user's password to this (plain text) value.<br/>To enable an account - `enabled` - a password must already be configured on the account, or you must provide a password here. | Optional | 
| update_password | `always` will always update passwords.<br/>`on_create` will only set the password for newly created users.<br/>`when_changed` will only set the password when changed (added in ansible 2.9). Possible values are: always, on_create, when_changed. Default is always. | Optional | 
| password_expired | `yes` will require the user to change their password at next login.<br/>`no` will clear the expired password flag.<br/>This is mutually exclusive with `password_never_expires`. | Optional | 
| password_never_expires | `yes` will set the password to never expire.<br/>`no` will allow the password to expire.<br/>This is mutually exclusive with `password_expired`. | Optional | 
| user_cannot_change_password | `yes` will prevent the user from changing their password.<br/>`no` will allow the user to change their password. | Optional | 
| firstname | Configures the user's first name (given name). | Optional | 
| surname | Configures the user's last name (surname). | Optional | 
| company | Configures the user's company name. | Optional | 
| upn | Configures the User Principal Name (UPN) for the account.<br/>This is not required, but is best practice to configure for modern versions of Active Directory.<br/>The format is `&lt;username&gt;@&lt;domain&gt;`. | Optional | 
| email | Configures the user's email address.<br/>This is a record in AD and does not do anything to configure any email servers or systems. | Optional | 
| street | Configures the user's street address. | Optional | 
| city | Configures the user's city. | Optional | 
| state_province | Configures the user's state or province. | Optional | 
| postal_code | Configures the user's postal code / zip code. | Optional | 
| country | Configures the user's country code.<br/>Note that this is a two-character ISO 3166 code. | Optional | 
| path | Container or OU for the new user; if you do not specify this, the user will be placed in the default container for users in the domain.<br/>Setting the path is only available when a new user is created; if you specify a path on an existing user, the user's path will not be updated - you must delete (e.g., `state=absent`) the user and then re-add the user with the appropriate path. | Optional | 
| attributes | A dict of custom LDAP attributes to set on the user.<br/>This can be used to set custom attributes that are not exposed as module parameters, e.g. `telephoneNumber`.<br/>See the examples on how to format this parameter. | Optional | 
| domain_username | The username to use when interacting with AD.<br/>If this is not set then the user Ansible used to log in with will be used instead when using CredSSP or Kerberos with credential delegation. | Optional | 
| domain_password | The password for `username`. | Optional | 
| domain_server | Specifies the Active Directory Domain Services instance to connect to.<br/>Can be in the form of an FQDN or NetBIOS name.<br/>If not specified then the value is based on the domain of the computer running PowerShell. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDomainUser.account_locked | boolean | true if the account is locked | 
| MicrosoftWindows.WinDomainUser.changed | boolean | true if the account changed during execution | 
| MicrosoftWindows.WinDomainUser.city | string | The user city | 
| MicrosoftWindows.WinDomainUser.company | string | The user company | 
| MicrosoftWindows.WinDomainUser.country | string | The user country | 
| MicrosoftWindows.WinDomainUser.description | string | A description of the account | 
| MicrosoftWindows.WinDomainUser.distinguished_name | string | DN of the user account | 
| MicrosoftWindows.WinDomainUser.email | string | The user email address | 
| MicrosoftWindows.WinDomainUser.enabled | string | true if the account is enabled and false if disabled | 
| MicrosoftWindows.WinDomainUser.firstname | string | The user first name | 
| MicrosoftWindows.WinDomainUser.groups | unknown | AD Groups to which the account belongs | 
| MicrosoftWindows.WinDomainUser.msg | string | Summary message of whether the user is present or absent | 
| MicrosoftWindows.WinDomainUser.name | string | The username on the account | 
| MicrosoftWindows.WinDomainUser.password_expired | boolean | true if the account password has expired | 
| MicrosoftWindows.WinDomainUser.password_updated | boolean | true if the password changed during this execution | 
| MicrosoftWindows.WinDomainUser.postal_code | string | The user postal code | 
| MicrosoftWindows.WinDomainUser.sid | string | The SID of the account | 
| MicrosoftWindows.WinDomainUser.state | string | The state of the user account | 
| MicrosoftWindows.WinDomainUser.state_province | string | The user state or province | 
| MicrosoftWindows.WinDomainUser.street | string | The user street address | 
| MicrosoftWindows.WinDomainUser.surname | string | The user last name | 
| MicrosoftWindows.WinDomainUser.upn | string | The User Principal Name of the account | 
| MicrosoftWindows.WinDomainUser.user_cannot_change_password | string | true if the user is not allowed to change password | 
| MicrosoftWindows.WinDomainUser.created | boolean | Whether a user was created | 




### win-dotnet-ngen
***
Runs ngen to recompile DLLs after .NET  updates
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_dotnet_ngen_module.html


#### Base Command

`win-dotnet-ngen`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen_update_exit_code | number | The exit code after running the 32-bit ngen.exe update /force command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen_update_output | string | The stdout after running the 32-bit ngen.exe update /force command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen_eqi_exit_code | number | The exit code after running the 32-bit ngen.exe executeQueuedItems command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen_eqi_output | string | The stdout after running the 32-bit ngen.exe executeQueuedItems command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen64_update_exit_code | number | The exit code after running the 64-bit ngen.exe update /force command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen64_update_output | string | The stdout after running the 64-bit ngen.exe update /force command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen64_eqi_exit_code | number | The exit code after running the 64-bit ngen.exe executeQueuedItems command. | 
| MicrosoftWindows.WinDotnetNgen.dotnet_ngen64_eqi_output | string | The stdout after running the 64-bit ngen.exe executeQueuedItems command. | 




### win-dsc
***
Invokes a PowerShell DSC configuration
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_dsc_module.html


#### Base Command

`win-dsc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| resource_name | The name of the DSC Resource to use.<br/>Must be accessible to PowerShell using any of the default paths. | Required | 
| module_version | Can be used to configure the exact version of the DSC resource to be invoked.<br/>Useful if the target node has multiple versions installed of the module containing the DSC resource.<br/>If not specified, the module will follow standard PowerShell convention and use the highest version available. Default is latest. | Optional | 
| free_form | The `win_dsc` module takes in multiple free form options based on the DSC resource being invoked by `resource_name`.<br/>There is no option actually named `free_form` so see the examples.<br/>This module will try and convert the option to the correct type required by the DSC resource and throw a warning if it fails.<br/>If the type of the DSC resource option is a `CimInstance` or `CimInstance[]`, this means the value should be a dictionary or list of dictionaries based on the values required by that option.<br/>If the type of the DSC resource option is a `PSCredential` then there needs to be 2 options set in the Ansible task definition suffixed with `_username` and `_password`.<br/>If the type of the DSC resource option is an array, then a list should be provided but a comma separated string also work. Use a list where possible as no escaping is required and it works with more complex types list `CimInstance[]`.<br/>If the type of the DSC resource option is a `DateTime`, you should use a string in the form of an ISO 8901 string to ensure the exact date is used.<br/>Since Ansible 2.8, Ansible will now validate the input fields against the DSC resource definition automatically. Older versions will silently ignore invalid fields. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinDsc.module_version | string | The version of the dsc resource/module used. | 
| MicrosoftWindows.WinDsc.reboot_required | boolean | Flag returned from the DSC engine indicating whether or not the machine requires a reboot for the invoked changes to take effect. | 
| MicrosoftWindows.WinDsc.verbose_test | unknown | The verbose output as a list from executing the DSC test method. | 
| MicrosoftWindows.WinDsc.verbose_set | unknown | The verbose output as a list from executing the DSC Set method. | 




### win-environment
***
Modify environment variables on windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_environment_module.html


#### Base Command

`win-environment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Set to `present` to ensure environment variable is set.<br/>Set to `absent` to ensure it is removed. Possible values are: absent, present. Default is present. | Optional | 
| name | The name of the environment variable. | Required | 
| value | The value to store in the environment variable.<br/>Must be set when `state=present` and cannot be an empty string.<br/>Can be omitted for `state=absent`. | Optional | 
| level | The level at which to set the environment variable.<br/>Use `machine` to set for all users.<br/>Use `user` to set for the current user that ansible is connected as.<br/>Use `process` to set for the current process.  Probably not that useful. Possible values are: machine, process, user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinEnvironment.before_value | string | the value of the environment key before a change, this is null if it didn't exist | 
| MicrosoftWindows.WinEnvironment.value | string | the value the environment key has been set to, this is null if removed | 


#### Command Example
```!win-environment host="123.123.123.123" state="present" name="TestVariable" value="Test value" level="machine" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinEnvironment": {
            "before_value": "Test value",
            "changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS",
            "value": "Test value",
            "values": {
                "TestVariable": {
                    "after": "Test value",
                    "before": "Test value",
                    "changed": false
                }
            }
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * before_value: Test value
>  * changed: False
>  * value: Test value
>  * ## Values
>    * ### Testvariable
>      * after: Test value
>      * before: Test value
>      * changed: False


### win-eventlog
***
Manage Windows event logs
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_eventlog_module.html


#### Base Command

`win-eventlog`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the event log to manage. | Required | 
| state | Desired state of the log and/or sources.<br/>When `sources` is populated, state is checked for sources.<br/>When `sources` is not populated, state is checked for the specified log itself.<br/>If `state` is `clear`, event log entries are cleared for the target log. Possible values are: absent, clear, present. Default is present. | Optional | 
| sources | A list of one or more sources to ensure are present/absent in the log.<br/>When `category_file`, `message_file` and/or `parameter_file` are specified, these values are applied across all sources. | Optional | 
| category_file | For one or more sources specified, the path to a custom category resource file. | Optional | 
| message_file | For one or more sources specified, the path to a custom event message resource file. | Optional | 
| parameter_file | For one or more sources specified, the path to a custom parameter resource file. | Optional | 
| maximum_size | The maximum size of the event log.<br/>Value must be between 64KB and 4GB, and divisible by 64KB.<br/>Size can be specified in KB, MB or GB (e.g. 128KB, 16MB, 2.5GB). | Optional | 
| overflow_action | The action for the log to take once it reaches its maximum size.<br/>For `DoNotOverwrite`, all existing entries are kept and new entries are not retained.<br/>For `OverwriteAsNeeded`, each new entry overwrites the oldest entry.<br/>For `OverwriteOlder`, new log entries overwrite those older than the `retention_days` value. Possible values are: DoNotOverwrite, OverwriteAsNeeded, OverwriteOlder. | Optional | 
| retention_days | The minimum number of days event entries must remain in the log.<br/>This option is only used when `overflow_action` is `OverwriteOlder`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinEventlog.name | string | The name of the event log. | 
| MicrosoftWindows.WinEventlog.exists | boolean | Whether the event log exists or not. | 
| MicrosoftWindows.WinEventlog.entries | number | The count of entries present in the event log. | 
| MicrosoftWindows.WinEventlog.maximum_size_kb | number | Maximum size of the log in KB. | 
| MicrosoftWindows.WinEventlog.overflow_action | string | The action the log takes once it reaches its maximum size. | 
| MicrosoftWindows.WinEventlog.retention_days | number | The minimum number of days entries are retained in the log. | 
| MicrosoftWindows.WinEventlog.sources | unknown | A list of the current sources for the log. | 
| MicrosoftWindows.WinEventlog.sources_changed | unknown | A list of sources changed \(e.g. re/created, removed\) for the log; this is empty if no sources are changed. | 


#### Command Example
```!win-eventlog host="123.123.123.123" name="MyNewLog" sources="['NewLogSource1', 'NewLogSource2']" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinEventlog": {
            "changed": false,
            "entries": 0,
            "exists": true,
            "host": "123.123.123.123",
            "maximum_size_kb": 512,
            "name": "MyNewLog",
            "overflow_action": "OverwriteOlder",
            "retention_days": 7,
            "sources": [
                "'NewLogSource2']",
                "MyNewLog",
                "['NewLogSource1'"
            ],
            "sources_changed": [],
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * entries: 0
>  * exists: True
>  * maximum_size_kb: 512
>  * name: MyNewLog
>  * overflow_action: OverwriteOlder
>  * retention_days: 7
>  * ## Sources
>    * 0: 'NewLogSource2']
>    * 1: MyNewLog
>    * 2: ['NewLogSource1'
>  * ## Sources_Changed


### win-eventlog-entry
***
Write entries to Windows event logs
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_eventlog_entry_module.html


#### Base Command

`win-eventlog-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| log | Name of the event log to write an entry to. | Required | 
| source | Name of the log source to indicate where the entry is from. | Required | 
| event_id | The numeric event identifier for the entry.<br/>Value must be between 0 and 65535. | Required | 
| message | The message for the given log entry. | Required | 
| entry_type | Indicates the entry being written to the log is of a specific type. Possible values are: Error, FailureAudit, Information, SuccessAudit, Warning. | Optional | 
| category | A numeric task category associated with the category message file for the log source. | Optional | 
| raw_data | Binary data associated with the log entry.<br/>Value must be a comma-separated array of 8-bit unsigned integers (0 to 255). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-eventlog-entry host="123.123.123.123" log="System" source="System" event_id="1234" message="This is a test log entry."```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinEventlogEntry": {
            "changed": true,
            "host": "123.123.123.123",
            "msg": "Entry added to log System from source System",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * msg: Entry added to log System from source System


### win-feature
***
Installs and uninstalls Windows Features on Windows Server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_feature_module.html


#### Base Command

`win-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Names of roles or features to install as a single feature or a comma-separated list of features.<br/>To list all available features use the PowerShell command `Get-WindowsFeature`. | Required | 
| state | State of the features or roles on the system. Possible values are: absent, present. Default is present. | Optional | 
| include_sub_features | Adds all subfeatures of the specified feature. Possible values are: Yes, No. Default is No. | Optional | 
| include_management_tools | Adds the corresponding management tools to the specified feature.<br/>Not supported in Windows 2008 R2 and will be ignored. Possible values are: Yes, No. Default is No. | Optional | 
| source | Specify a source to install the feature from.<br/>Not supported in Windows 2008 R2 and will be ignored.<br/>Can either be `{driveletter}:\sources\sxs` or `\\{IP}\share\sources\sxs`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinFeature.exitcode | string | The stringified exit code from the feature installation/removal command. | 
| MicrosoftWindows.WinFeature.feature_result | unknown | List of features that were installed or removed. | 
| MicrosoftWindows.WinFeature.reboot_required | boolean | True when the target server requires a reboot to complete updates \(no further updates can be installed until after a reboot\). | 


#### Command Example
```!win-feature host="123.123.123.123" name="Web-Server" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFeature": {
            "changed": false,
            "exitcode": "NoChangeNeeded",
            "feature_result": [],
            "host": "123.123.123.123",
            "reboot_required": false,
            "status": "SUCCESS",
            "success": true
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * exitcode: NoChangeNeeded
>  * reboot_required: False
>  * success: True
>  * ## Feature_Result


### win-file
***
Creates, touches or removes files or directories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_file_module.html


#### Base Command

`win-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to the file being managed. | Required | 
| state | If `directory`, all immediate subdirectories will be created if they do not exist.<br/>If `file`, the file will NOT be created if it does not exist, see the `copy` or `template` module if you want that behavior.  If `absent`, directories will be recursively deleted, and files will be removed.<br/>If `touch`, an empty file will be created if the `path` does not exist, while an existing file or directory will receive updated file access and modification times (similar to the way `touch` works from the command line). Possible values are: absent, directory, file, touch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-file host="123.123.123.123" path="C:/Temp/foo.conf" state="touch"```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFile": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-file-version
***
Get DLL or EXE file build version
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_file_version_module.html


#### Base Command

`win-file-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | File to get version.<br/>Always provide absolute path. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinFileVersion.path | string | file path | 
| MicrosoftWindows.WinFileVersion.file_version | string | File version number.. | 
| MicrosoftWindows.WinFileVersion.product_version | string | The version of the product this file is distributed with. | 
| MicrosoftWindows.WinFileVersion.file_major_part | string | the major part of the version number. | 
| MicrosoftWindows.WinFileVersion.file_minor_part | string | the minor part of the version number of the file. | 
| MicrosoftWindows.WinFileVersion.file_build_part | string | build number of the file. | 
| MicrosoftWindows.WinFileVersion.file_private_part | string | file private part number. | 


#### Command Example
```!win-file-version host="123.123.123.123" path="C:\\Windows\\System32\\cmd.exe" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFileVersion": {
            "file_build_part": "14393",
            "file_major_part": "10",
            "file_minor_part": "0",
            "file_private_part": "0",
            "file_version": "10.0.14393.0 (rs1_release.160715-1616)",
            "host": "123.123.123.123",
            "path": "C:\\Windows\\System32\\cmd.exe",
            "product_version": "10.0.14393.0",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * file_build_part: 14393
>  * file_major_part: 10
>  * file_minor_part: 0
>  * file_private_part: 0
>  * file_version: 10.0.14393.0 (rs1_release.160715-1616)
>  * path: C:\Windows\System32\cmd.exe
>  * product_version: 10.0.14393.0


### win-find
***
Return a list of files based on specific criteria
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_find_module.html


#### Base Command

`win-find`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| age | Select files or folders whose age is equal to or greater than the specified time.<br/>Use a negative age to find files equal to or less than the specified time.<br/>You can choose seconds, minutes, hours, days or weeks by specifying the first letter of an of those words (e.g., "2s", "10d", 1w"). | Optional | 
| age_stamp | Choose the file property against which we compare `age`.<br/>The default attribute we compare with is the last modification time. Possible values are: atime, ctime, mtime. Default is mtime. | Optional | 
| checksum_algorithm | Algorithm to determine the checksum of a file.<br/>Will throw an error if the host is unable to use specified algorithm. Possible values are: md5, sha1, sha256, sha384, sha512. Default is sha1. | Optional | 
| file_type | Type of file to search for. Possible values are: directory, file. Default is file. | Optional | 
| follow | Set this to `yes` to follow symlinks in the path.<br/>This needs to be used in conjunction with `recurse`. Possible values are: Yes, No. Default is No. | Optional | 
| get_checksum | Whether to return a checksum of the file in the return info (default sha1), use `checksum_algorithm` to change from the default. Possible values are: Yes, No. Default is Yes. | Optional | 
| hidden | Set this to include hidden files or folders. Possible values are: Yes, No. Default is No. | Optional | 
| paths | List of paths of directories to search for files or folders in.<br/>This can be supplied as a single path or a list of paths. | Required | 
| patterns | One or more (powershell or regex) patterns to compare filenames with.<br/>The type of pattern matching is controlled by `use_regex` option.<br/>The patterns restrict the list of files or folders to be returned based on the filenames.<br/>For a file to be matched it only has to match with one pattern in a list provided. | Optional | 
| recurse | Will recursively descend into the directory looking for files or folders. Possible values are: Yes, No. Default is No. | Optional | 
| size | Select files or folders whose size is equal to or greater than the specified size.<br/>Use a negative value to find files equal to or less than the specified size.<br/>You can specify the size with a suffix of the byte type i.e. kilo = k, mega = m...<br/>Size is not evaluated for symbolic links. | Optional | 
| use_regex | Will set patterns to run as a regex check if set to `yes`. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinFind.examined | number | The number of files/folders that was checked. | 
| MicrosoftWindows.WinFind.matched | number | The number of files/folders that match the criteria. | 
| MicrosoftWindows.WinFind.files | unknown | Information on the files/folders that match the criteria returned as a list of dictionary elements for each file matched. The entries are sorted by the path value alphabetically. | 


#### Command Example
```!win-find host="123.123.123.123" paths="c:\\Temp" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFind": {
            "changed": false,
            "examined": 2,
            "files": [
                {
                    "attributes": "Archive",
                    "checksum": "40c7d97574e7c791d649582912620f7d816829e4",
                    "creationtime": 1624943905.9269967,
                    "exists": true,
                    "extension": ".jpg",
                    "filename": "earthrise.jpg",
                    "hlnk_targets": [],
                    "isarchive": true,
                    "isdir": false,
                    "ishidden": false,
                    "isjunction": false,
                    "islnk": false,
                    "isreadonly": false,
                    "isreg": true,
                    "isshared": false,
                    "lastaccesstime": 1624943905.9269967,
                    "lastwritetime": 1624943905.8957422,
                    "lnk_source": null,
                    "lnk_target": null,
                    "nlink": 1,
                    "owner": "BUILTIN\\Administrators",
                    "path": "C:\\Temp\\earthrise.jpg",
                    "sharename": null,
                    "size": 45108
                }
            ],
            "host": "123.123.123.123",
            "matched": 1,
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * examined: 2
>  * matched: 1
>  * ## Files
>  * ## Earthrise.Jpg
>    * attributes: Archive
>    * checksum: 40c7d97574e7c791d649582912620f7d816829e4
>    * creationtime: 1624943905.9269967
>    * exists: True
>    * extension: .jpg
>    * filename: earthrise.jpg
>    * isarchive: True
>    * isdir: False
>    * ishidden: False
>    * isjunction: False
>    * islnk: False
>    * isreadonly: False
>    * isreg: True
>    * isshared: False
>    * lastaccesstime: 1624943905.9269967
>    * lastwritetime: 1624943905.8957422
>    * lnk_source: None
>    * lnk_target: None
>    * nlink: 1
>    * owner: BUILTIN\Administrators
>    * path: C:\Temp\earthrise.jpg
>    * sharename: None
>    * size: 45108
>    * ### Hlnk_Targets


### win-firewall
***
Enable or disable the Windows Firewall
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_firewall_module.html


#### Base Command

`win-firewall`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| profiles | Specify one or more profiles to change. Possible values are: Domain, Private, Public. Default is ['Domain', 'Private', 'Public']. | Optional | 
| state | Set state of firewall for given profile. Possible values are: disabled, enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinFirewall.enabled | boolean | Current firewall status for chosen profile \(after any potential change\). | 
| MicrosoftWindows.WinFirewall.profiles | string | Chosen profile. | 
| MicrosoftWindows.WinFirewall.state | unknown | Desired state of the given firewall profile\(s\). | 


#### Command Example
```!win-firewall host="123.123.123.123" state="enabled" profiles="['Domain', 'Private', 'Public']" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFirewall": {
            "Domain": {
                "considered": false,
                "currentstate": 1,
                "enabled": true
            },
            "Private": {
                "considered": false,
                "currentstate": 1,
                "enabled": true
            },
            "Public": {
                "considered": false,
                "currentstate": 1,
                "enabled": true
            },
            "changed": false,
            "host": "123.123.123.123",
            "profiles": [
                "['Domain'",
                "'Private'",
                "'Public']"
            ],
            "state": "enabled",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * state: enabled
>  * ## Domain
>    * considered: False
>    * currentstate: 1
>    * enabled: True
>  * ## Private
>    * considered: False
>    * currentstate: 1
>    * enabled: True
>  * ## Public
>    * considered: False
>    * currentstate: 1
>    * enabled: True
>  * ## Profiles
>    * 0: ['Domain'
>    * 1: 'Private'
>    * 2: 'Public']


### win-firewall-rule
***
Windows firewall automation
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_firewall_rule_module.html


#### Base Command

`win-firewall-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| enabled | Whether this firewall rule is enabled or disabled.<br/>Defaults to `true` when creating a new rule. | Optional | 
| state | Should this rule be added or removed. Possible values are: absent, present. Default is present. | Optional | 
| name | The rule's display name. | Required | 
| group | The group name for the rule. | Optional | 
| direction | Whether this rule is for inbound or outbound traffic.<br/>Defaults to `in` when creating a new rule. Possible values are: in, out. | Optional | 
| action | What to do with the items this rule is for.<br/>Defaults to `allow` when creating a new rule. Possible values are: allow, block. | Optional | 
| description | Description for the firewall rule. | Optional | 
| localip | The local ip address this rule applies to.<br/>Set to `any` to apply to all local ip addresses.<br/>Defaults to `any` when creating a new rule. | Optional | 
| remoteip | The remote ip address/range this rule applies to.<br/>Set to `any` to apply to all remote ip addresses.<br/>Defaults to `any` when creating a new rule. | Optional | 
| localport | The local port this rule applies to.<br/>Set to `any` to apply to all local ports.<br/>Defaults to `any` when creating a new rule.<br/>Must have `protocol` set. | Optional | 
| remoteport | The remote port this rule applies to.<br/>Set to `any` to apply to all remote ports.<br/>Defaults to `any` when creating a new rule.<br/>Must have `protocol` set. | Optional | 
| program | The program this rule applies to.<br/>Set to `any` to apply to all programs.<br/>Defaults to `any` when creating a new rule. | Optional | 
| service | The service this rule applies to.<br/>Set to `any` to apply to all services.<br/>Defaults to `any` when creating a new rule. | Optional | 
| protocol | The protocol this rule applies to.<br/>Set to `any` to apply to all services.<br/>Defaults to `any` when creating a new rule. | Optional | 
| profiles | The profile this rule applies to.<br/>Defaults to `domain,private,public` when creating a new rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-firewall-rule host="123.123.123.123" name="SMTP" localport="25" action="allow" direction="in" protocol="tcp" state="present" enabled="True" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFirewallRule": {
            "changed": false,
            "host": "123.123.123.123",
            "msg": "Firewall rule(s) changed '' - unchanged 'SMTP'",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * msg: Firewall rule(s) changed '' - unchanged 'SMTP'


### win-format
***
Formats an existing volume or a new volume on an existing partition on Windows
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_format_module.html


#### Base Command

`win-format`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| drive_letter | Used to specify the drive letter of the volume to be formatted. | Optional | 
| path | Used to specify the path to the volume to be formatted. | Optional | 
| label | Used to specify the label of the volume to be formatted. | Optional | 
| new_label | Used to specify the new file system label of the formatted volume. | Optional | 
| file_system | Used to specify the file system to be used when formatting the target volume. Possible values are: ntfs, refs, exfat, fat32, fat. | Optional | 
| allocation_unit_size | Specifies the cluster size to use when formatting the volume.<br/>If no cluster size is specified when you format a partition, defaults are selected based on the size of the partition. | Optional | 
| large_frs | Specifies that large File Record System (FRS) should be used. | Optional | 
| compress | Enable compression on the resulting NTFS volume.<br/>NTFS compression is not supported where `allocation_unit_size` is more than 4096. | Optional | 
| integrity_streams | Enable integrity streams on the resulting ReFS volume. | Optional | 
| full | A full format writes to every sector of the disk, takes much longer to perform than the default (quick) format, and is not recommended on storage that is thinly provisioned.<br/>Specify `true` for full format. | Optional | 
| force | Specify if formatting should be forced for volumes that are not created from new partitions or if the source and target file system are different. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-format host="123.123.123.123" drive_letter=f```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinFormat": {
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


### win-get-url
***
Downloads file from HTTP, HTTPS, or FTP to node
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_get_url_module.html


#### Base Command

`win-get-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| url | The full URL of a file to download. | Required | 
| dest | The location to save the file at the URL.<br/>Be sure to include a filename and extension as appropriate. | Required | 
| force | If `yes`, will download the file every time and replace the file if the contents change. If `no`, will only download the file if it does not exist or the remote file has been modified more recently than the local file.<br/>This works by sending an http HEAD request to retrieve last modified time of the requested resource, so for this to work, the remote web server must support HEAD requests. Possible values are: Yes, No. Default is Yes. | Optional | 
| checksum | If a `checksum` is passed to this parameter, the digest of the destination file will be calculated after it is downloaded to ensure its integrity and verify that the transfer completed successfully.<br/>This option cannot be set with `checksum_url`. | Optional | 
| checksum_algorithm | Specifies the hashing algorithm used when calculating the checksum of the remote and destination file. Possible values are: md5, sha1, sha256, sha384, sha512. Default is sha1. | Optional | 
| checksum_url | Specifies a URL that contains the checksum values for the resource at `url`.<br/>Like `checksum`, this is used to verify the integrity of the remote transfer.<br/>This option cannot be set with `checksum`. | Optional | 
| proxy_url | An explicit proxy to use for the request.<br/>By default, the request will use the IE defined proxy unless `use_proxy` is set to `no`. | Optional | 
| proxy_username | The username to use for proxy authentication. | Optional | 
| proxy_password | The password for `proxy_username`. | Optional | 
| headers | Extra headers to set on the request.<br/>This should be a dictionary where the key is the header name and the value is the value for that header. | Optional | 
| use_proxy | If `no`, it will not use the proxy defined in IE for the current user. Possible values are: Yes, No. Default is Yes. | Optional | 
| follow_redirects | Whether or the module should follow redirects.<br/>`all` will follow all redirect.<br/>`none` will not follow any redirect.<br/>`safe` will follow only "safe" redirects, where "safe" means that the client is only doing a `GET` or `HEAD` on the URI to which it is being redirected. Possible values are: all, none, safe. Default is safe. | Optional | 
| maximum_redirection | Specify how many times the module will redirect a connection to an alternative URI before the connection fails.<br/>If set to `0` or `follow_redirects` is set to `none`, or `safe` when not doing a `GET` or `HEAD` it prevents all redirection. Default is 50. | Optional | 
| client_cert | The path to the client certificate (.pfx) that is used for X509 authentication. This path can either be the path to the `pfx` on the filesystem or the PowerShell certificate path `Cert:\CurrentUser\My\&lt;thumbprint&gt;`.<br/>The WinRM connection must be authenticated with `CredSSP` or `become` is used on the task if the certificate file is not password protected.<br/>Other authentication types can set `client_cert_password` when the cert is password protected. | Optional | 
| client_cert_password | The password for `client_cert` if the cert is password protected. | Optional | 
| method | This option is not for use with `win_get_url` and should be ignored. | Optional | 
| http_agent | Header to identify as, generally appears in web server logs.<br/>This is set to the `User-Agent` header on a HTTP request. Default is ansible-httpget. | Optional | 
| timeout | Specifies how long the request can be pending before it times out (in seconds).<br/>Set to `0` to specify an infinite timeout. Default is 30. | Optional | 
| validate_certs | If `no`, SSL certificates will not be validated.<br/>This should only be used on personally controlled sites using self-signed certificates. Possible values are: Yes, No. Default is Yes. | Optional | 
| force_basic_auth | By default the authentication header is only sent when a webservice responses to an initial request with a 401 status. Since some basic auth services do not properly send a 401, logins will fail.<br/>This option forces the sending of the Basic authentication header upon the original request. Possible values are: Yes, No. Default is No. | Optional | 
| url_username | The username to use for authentication. | Optional | 
| url_password | The password for `url_username`. | Optional | 
| use_default_credential | Uses the current user's credentials when authenticating with a server protected with `NTLM`, `Kerberos`, or `Negotiate` authentication.<br/>Sites that use `Basic` auth will still require explicit credentials through the `url_username` and `url_password` options.<br/>The module will only have access to the user's credentials if using `become` with a password, you are connecting with SSH using a password, or connecting with WinRM using `CredSSP` or `Kerberos with delegation`.<br/>If not using `become` or a different auth method to the ones stated above, there will be no default credentials available and no authentication will occur. Possible values are: Yes, No. Default is No. | Optional | 
| proxy_use_default_credential | Uses the current user's credentials when authenticating with a proxy host protected with `NTLM`, `Kerberos`, or `Negotiate` authentication.<br/>Proxies that use `Basic` auth will still require explicit credentials through the `proxy_username` and `proxy_password` options.<br/>The module will only have access to the user's credentials if using `become` with a password, you are connecting with SSH using a password, or connecting with WinRM using `CredSSP` or `Kerberos with delegation`.<br/>If not using `become` or a different auth method to the ones stated above, there will be no default credentials available and no proxy authentication will occur. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinGetUrl.dest | string | destination file/path | 
| MicrosoftWindows.WinGetUrl.checksum_dest | string | &lt;algorithm&gt; checksum of the file after the download | 
| MicrosoftWindows.WinGetUrl.checksum_src | string | &lt;algorithm&gt; checksum of the remote resource | 
| MicrosoftWindows.WinGetUrl.elapsed | unknown | The elapsed seconds between the start of poll and the end of the module. | 
| MicrosoftWindows.WinGetUrl.size | number | size of the dest file | 
| MicrosoftWindows.WinGetUrl.url | string | requested url | 
| MicrosoftWindows.WinGetUrl.msg | string | Error message, or HTTP status message from web-server | 
| MicrosoftWindows.WinGetUrl.status_code | number | HTTP status code | 


#### Command Example
```!win-get-url host="123.123.123.123" url="https://www.nasa.gov/sites/default/files/styles/full_width_feature/public/images/297755main_GPN-2001-000009_full.jpg" dest="C:\\Temp\\earthrise.jpg" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinGetUrl": {
            "changed": true,
            "checksum_dest": "40c7d97574e7c791d649582912620f7d816829e4",
            "checksum_src": "40c7d97574e7c791d649582912620f7d816829e4",
            "dest": "C:\\Temp\\earthrise.jpg",
            "elapsed": 1.4999867,
            "host": "123.123.123.123",
            "msg": "OK",
            "size": 45108,
            "status": "CHANGED",
            "status_code": 200,
            "url": "https://www.nasa.gov/sites/default/files/styles/full_width_feature/public/images/297755main_GPN-2001-000009_full.jpg"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * checksum_dest: 40c7d97574e7c791d649582912620f7d816829e4
>  * checksum_src: 40c7d97574e7c791d649582912620f7d816829e4
>  * dest: C:\Temp\earthrise.jpg
>  * elapsed: 1.4999867
>  * msg: OK
>  * size: 45108
>  * status_code: 200
>  * url: https://www.nasa.gov/sites/default/files/styles/full_width_feature/public/images/297755main_GPN-2001-000009_full.jpg


### win-group
***
Add and remove local groups
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_group_module.html


#### Base Command

`win-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the group. | Required | 
| description | Description of the group. | Optional | 
| state | Create or remove the group. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-group host="123.123.123.123" name="deploy" description="Deploy Group" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinGroup": {
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


### win-group-membership
***
Manage Windows local group membership
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_group_membership_module.html


#### Base Command

`win-group-membership`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the local group to manage membership on. | Required | 
| members | A list of members to ensure are present/absent from the group.<br/>Accepts local users as .\username, and SERVERNAME\username.<br/>Accepts domain users and groups as DOMAIN\username and username@DOMAIN.<br/>Accepts service users as NT AUTHORITY\username.<br/>Accepts all local, domain and service user types as username, favoring domain lookups when in a domain. | Required | 
| state | Desired state of the members in the group.<br/>`pure` was added in Ansible 2.8.<br/>When `state` is `pure`, only the members specified will exist, and all other existing members not specified are removed. Possible values are: absent, present, pure. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinGroupMembership.name | string | The name of the target local group. | 
| MicrosoftWindows.WinGroupMembership.added | unknown | A list of members added when \`state\` is \`present\` or \`pure\`; this is empty if no members are added. | 
| MicrosoftWindows.WinGroupMembership.removed | unknown | A list of members removed when \`state\` is \`absent\` or \`pure\`; this is empty if no members are removed. | 
| MicrosoftWindows.WinGroupMembership.members | unknown | A list of all local group members at completion; this is empty if the group contains no members. | 


#### Command Example
```!win-group-membership host="123.123.123.123" name="Remote Desktop Users" members="fed-phil" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinGroupMembership": {
            "added": [
                "WIN-U425UI0HPP7\\fed-phil"
            ],
            "changed": true,
            "host": "123.123.123.123",
            "members": [
                "WIN-U425UI0HPP7\\fed-phil"
            ],
            "name": "Remote Desktop Users",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * name: Remote Desktop Users
>  * ## Added
>    * 0: WIN-U425UI0HPP7\fed-phil
>  * ## Members
>    * 0: WIN-U425UI0HPP7\fed-phil


### win-hostname
***
Manages local Windows computer name
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_hostname_module.html


#### Base Command

`win-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The hostname to set for the computer. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinHostname.old_name | string | The original hostname that was set before it was changed. | 
| MicrosoftWindows.WinHostname.reboot_required | boolean | Whether a reboot is required to complete the hostname change. | 


#### Command Example
```!win-hostname host="123.123.123.123" name="sample-hostname" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinHostname": {
            "changed": true,
            "host": "123.123.123.123",
            "old_name": "WIN-U425UI0HPP7",
            "reboot_required": true,
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * old_name: WIN-U425UI0HPP7
>  * reboot_required: True


### win-hosts
***
Manages hosts file entries on Windows.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_hosts_module.html


#### Base Command

`win-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether the entry should be present or absent.<br/>If only `canonical_name` is provided when `state=absent`, then all hosts entries with the canonical name of `canonical_name` will be removed.<br/>If only `ip_address` is provided when `state=absent`, then all hosts entries with the ip address of `ip_address` will be removed.<br/>If `ip_address` and `canonical_name` are both omitted when `state=absent`, then all hosts entries will be removed. Possible values are: absent, present. Default is present. | Optional | 
| canonical_name | A canonical name for the host entry.<br/>required for `state=present`. | Optional | 
| ip_address | The ip address for the host entry.<br/>Can be either IPv4 (A record) or IPv6 (AAAA record).<br/>Required for `state=present`. | Optional | 
| aliases | A list of additional names (cname records) for the host entry.<br/>Only applicable when `state=present`. | Optional | 
| action | Controls the behavior of `aliases`.<br/>Only applicable when `state=present`.<br/>If `add`, each alias in `aliases` will be added to the host entry.<br/>If `set`, each alias in `aliases` will be added to the host entry, and other aliases will be removed from the entry. Possible values are: add, remove, set. Default is set. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-hosts host="123.123.123.123" state="present" canonical_name="localhost" ip_address="127.0.0.1" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinHosts": {
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


### win-hotfix
***
Install and uninstalls Windows hotfixes
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_hotfix_module.html


#### Base Command

`win-hotfix`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| hotfix_identifier | The name of the hotfix as shown in DISM, see examples for details.<br/>This or `hotfix_kb` MUST be set when `state=absent`.<br/>If `state=present` then the hotfix at `source` will be validated against this value, if it does not match an error will occur.<br/>You can get the identifier by running 'Get-WindowsPackage -Online -PackagePath path-to-cab-in-msu' after expanding the msu file. | Optional | 
| hotfix_kb | The name of the KB the hotfix relates to, see examples for details.<br/>This or `hotfix_identifier` MUST be set when `state=absent`.<br/>If `state=present` then the hotfix at `source` will be validated against this value, if it does not match an error will occur.<br/>Because DISM uses the identifier as a key and doesn't refer to a KB in all cases it is recommended to use `hotfix_identifier` instead. | Optional | 
| state | Whether to install or uninstall the hotfix.<br/>When `present`, `source` MUST be set.<br/>When `absent`, `hotfix_identifier` or `hotfix_kb` MUST be set. Possible values are: absent, present. Default is present. | Optional | 
| source | The path to the downloaded hotfix .msu file.<br/>This MUST be set if `state=present` and MUST be a .msu hotfix file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinHotfix.identifier | string | The DISM identifier for the hotfix. | 
| MicrosoftWindows.WinHotfix.kb | string | The KB the hotfix relates to. | 
| MicrosoftWindows.WinHotfix.reboot_required | string | Whether a reboot is required for the install or uninstall to finalise. | 




### win-http-proxy
***
Manages proxy settings for WinHTTP
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_http_proxy_module.html


#### Base Command

`win-http-proxy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| bypass | A list of hosts that will bypass the set proxy when being accessed.<br/>Use `&lt;local&gt;` to match hostnames that are not fully qualified domain names. This is useful when needing to connect to intranet sites using just the hostname.<br/>Omit, set to null or an empty string/list to remove the bypass list.<br/>If this is set then `proxy` must also be set. | Optional | 
| proxy | A string or dict that specifies the proxy to be set.<br/>If setting a string, should be in the form `hostname`, `hostname:port`, or `protocol=hostname:port`.<br/>If the port is undefined, the default port for the protocol in use is used.<br/>If setting a dict, the keys should be the protocol and the values should be the hostname and/or port for that protocol.<br/>Valid protocols are `http`, `https`, `ftp`, and `socks`.<br/>Omit, set to null or an empty string to remove the proxy settings. | Optional | 
| source | Instead of manually specifying the `proxy` and/or `bypass`, set this to import the proxy from a set source like Internet Explorer.<br/>Using `ie` will import the Internet Explorer proxy settings for the current active network connection of the current user.<br/>Only IE's proxy URL and bypass list will be imported into WinHTTP.<br/>This is like running `netsh winhttp import proxy source=ie`.<br/>The value is imported when the module runs and will not automatically be updated if the IE configuration changes in the future. The module will have to be run again to sync the latest changes. Possible values are: ie. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-http-proxy host="123.123.123.123" proxy="hostname" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinHttpProxy": {
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


### win-iis-virtualdirectory
***
Configures a virtual directory in IIS
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_iis_virtualdirectory_module.html


#### Base Command

`win-iis-virtualdirectory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the virtual directory to create or remove. | Required | 
| state | Whether to add or remove the specified virtual directory.<br/>Removing will remove the virtual directory and all under it (Recursively). Possible values are: absent, present. Default is present. | Optional | 
| site | The site name under which the virtual directory is created or exists. | Required | 
| application | The application under which the virtual directory is created or exists. | Optional | 
| physical_path | The physical path to the folder in which the new virtual directory is created.<br/>The specified folder must already exist. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-iis-webapplication
***
Configures IIS web applications
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_iis_webapplication_module.html


#### Base Command

`win-iis-webapplication`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the web application. | Required | 
| site | Name of the site on which the application is created. | Required | 
| state | State of the web application. Possible values are: absent, present. Default is present. | Optional | 
| physical_path | The physical path on the remote host to use for the new application.<br/>The specified folder must already exist. | Optional | 
| application_pool | The application pool in which the new site executes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinIisWebapplication.application_pool | string | The used/implemented application_pool value. | 
| MicrosoftWindows.WinIisWebapplication.physical_path | string | The used/implemented physical_path value. | 




### win-iis-webapppool
***
Configure IIS Web Application Pools
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_iis_webapppool_module.html


#### Base Command

`win-iis-webapppool`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| attributes | This field is a free form dictionary value for the application pool attributes.<br/>These attributes are based on the naming standard at `https://www.iis.net/configreference/system.applicationhost/applicationpools/add#005`, see the examples section for more details on how to set this.<br/>You can also set the attributes of child elements like cpu and processModel, see the examples to see how it is done.<br/>While you can use the numeric values for enums it is recommended to use the enum name itself, e.g. use SpecificUser instead of 3 for processModel.identityType.<br/>managedPipelineMode may be either "Integrated" or "Classic".<br/>startMode may be either "OnDemand" or "AlwaysRunning".<br/>Use `state` module parameter to modify the state of the app pool.<br/>When trying to set 'processModel.password' and you receive a 'Value does fall within the expected range' error, you have a corrupted keystore. Please follow `http://structuredsight.com/2014/10/26/im-out-of-range-youre-out-of-range/` to help fix your host. | Optional | 
| name | Name of the application pool. | Required | 
| state | The state of the application pool.<br/>If `absent` will ensure the app pool is removed.<br/>If `present` will ensure the app pool is configured and exists.<br/>If `restarted` will ensure the app pool exists and will restart, this is never idempotent.<br/>If `started` will ensure the app pool exists and is started.<br/>If `stopped` will ensure the app pool exists and is stopped. Possible values are: absent, present, restarted, started, stopped. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinIisWebapppool.attributes | unknown | Application Pool attributes that were set and processed by this module invocation. | 
| MicrosoftWindows.WinIisWebapppool.info | unknown | Information on current state of the Application Pool. See https://www.iis.net/configreference/system.applicationhost/applicationpools/add\#005 for the full list of return attributes based on your IIS version. | 




### win-iis-webbinding
***
Configures a IIS Web site binding
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_iis_webbinding_module.html


#### Base Command

`win-iis-webbinding`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Names of web site. | Required | 
| state | State of the binding. Possible values are: absent, present. Default is present. | Optional | 
| port | The port to bind to / use for the new site. Default is 80. | Optional | 
| ip | The IP address to bind to / use for the new site. Default is *. | Optional | 
| host_header | The host header to bind to / use for the new site.<br/>If you are creating/removing a catch-all binding, omit this parameter rather than defining it as '*'. | Optional | 
| protocol | The protocol to be used for the Web binding (usually HTTP, HTTPS, or FTP). Default is http. | Optional | 
| certificate_hash | Certificate hash (thumbprint) for the SSL binding. The certificate hash is the unique identifier for the certificate. | Optional | 
| certificate_store_name | Name of the certificate store where the certificate for the binding is located. Default is my. | Optional | 
| ssl_flags | This parameter is only valid on Server 2012 and newer.<br/>Primarily used for enabling and disabling server name indication (SNI).<br/>Set to c(0) to disable SNI.<br/>Set to c(1) to enable SNI. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinIisWebbinding.website_state | string | The state of the website being targetted
Can be helpful in case you accidentally cause a binding collision which can result in the targetted site being stopped | 
| MicrosoftWindows.WinIisWebbinding.operation_type | string | The type of operation performed
Can be removed, updated, matched, or added | 
| MicrosoftWindows.WinIisWebbinding.binding_info | unknown | Information on the binding being manipulated | 




### win-iis-website
***
Configures a IIS Web site
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_iis_website_module.html


#### Base Command

`win-iis-website`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Names of web site. | Required | 
| site_id | Explicitly set the IIS numeric ID for a site.<br/>Note that this value cannot be changed after the website has been created. | Optional | 
| state | State of the web site. Possible values are: absent, started, stopped, restarted. | Optional | 
| physical_path | The physical path on the remote host to use for the new site.<br/>The specified folder must already exist. | Optional | 
| application_pool | The application pool in which the new site executes. | Optional | 
| port | The port to bind to / use for the new site. | Optional | 
| ip | The IP address to bind to / use for the new site. | Optional | 
| hostname | The host header to bind to / use for the new site. | Optional | 
| ssl | Enables HTTPS binding on the site.. | Optional | 
| parameters | Custom site Parameters from string where properties are separated by a pipe and property name/values by colon Ex. "foo:1\|bar:2". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-inet-proxy
***
Manages proxy settings for WinINet and Internet Explorer
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_inet_proxy_module.html


#### Base Command

`win-inet-proxy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| auto_detect | Whether to configure WinINet to automatically detect proxy settings through Web Proxy Auto-Detection `WPAD`.<br/>This corresponds to the checkbox `Automatically detect settings` in the connection settings window. Possible values are: Yes, No. Default is Yes. | Optional | 
| auto_config_url | The URL of a proxy configuration script.<br/>Proxy configuration scripts are typically JavaScript files with the `.pac` extension that implement the `FindProxyForURL(url, host` function.<br/>Omit, set to null or an empty string to remove the auto config URL.<br/>This corresponds to the checkbox `Use automatic configuration script` in the connection settings window. | Optional | 
| bypass | A list of hosts that will bypass the set proxy when being accessed.<br/>Use `&lt;local&gt;` to match hostnames that are not fully qualified domain names. This is useful when needing to connect to intranet sites using just the hostname. If defined, this should be the last entry in the bypass list.<br/>Use `&lt;-loopback&gt;` to stop automatically bypassing the proxy when connecting through any loopback address like `127.0.0.1`, `localhost`, or the local hostname.<br/>Omit, set to null or an empty string/list to remove the bypass list.<br/>If this is set then `proxy` must also be set. | Optional | 
| connection | The name of the IE connection to set the proxy settings for.<br/>These are the connections under the `Dial-up and Virtual Private Network` header in the IE settings.<br/>When omitted, the default LAN connection is used. | Optional | 
| proxy | A string or dict that specifies the proxy to be set.<br/>If setting a string, should be in the form `hostname`, `hostname:port`, or `protocol=hostname:port`.<br/>If the port is undefined, the default port for the protocol in use is used.<br/>If setting a dict, the keys should be the protocol and the values should be the hostname and/or port for that protocol.<br/>Valid protocols are `http`, `https`, `ftp`, and `socks`.<br/>Omit, set to null or an empty string to remove the proxy settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-inet-proxy host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinInetProxy": {
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


### win-lineinfile
***
Ensure a particular line is in a file, or replace an existing line using a back-referenced regular expression
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_lineinfile_module.html


#### Base Command

`win-lineinfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The path of the file to modify.<br/>Note that the Windows path delimiter `\` must be escaped as `\\` when the line is double quoted.<br/>Before Ansible 2.3 this option was only usable as `dest`, `destfile` and `name`. | Required | 
| backup | Determine whether a backup should be created.<br/>When set to `yes`, create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| regex | The regular expression to look for in every line of the file. For `state=present`, the pattern to replace if found; only the last line found will be replaced. For `state=absent`, the pattern of the line to remove. Uses .NET compatible regular expressions; see `https://msdn.microsoft.com/en-us/library/hs600312%28v=vs.110%29.aspx`. | Optional | 
| state | Whether the line should be there or not. Possible values are: absent, present. Default is present. | Optional | 
| line | Required for `state=present`. The line to insert/replace into the file. If `backrefs` is set, may contain backreferences that will get expanded with the `regexp` capture groups if the regexp matches.<br/>Be aware that the line is processed first on the controller and thus is dependent on yaml quoting rules. Any double quoted line will have control characters, such as '\r\n', expanded. To print such characters literally, use single or no quotes. | Optional | 
| backrefs | Used with `state=present`. If set, line can contain backreferences (both positional and named) that will get populated if the `regexp` matches. This flag changes the operation of the module slightly; `insertbefore` and `insertafter` will be ignored, and if the `regexp` doesn't match anywhere in the file, the file will be left unchanged.<br/>If the `regexp` does match, the last matching line will be replaced by the expanded line parameter. Possible values are: Yes, No. Default is No. | Optional | 
| insertafter | Used with `state=present`. If specified, the line will be inserted after the last match of specified regular expression. A special value is available; `EOF` for inserting the line at the end of the file.<br/>If specified regular expression has no matches, EOF will be used instead. May not be used with `backrefs`. Possible values are: EOF, *regex*. Default is EOF. | Optional | 
| insertbefore | Used with `state=present`. If specified, the line will be inserted before the last match of specified regular expression. A value is available; `BOF` for inserting the line at the beginning of the file.<br/>If specified regular expression has no matches, the line will be inserted at the end of the file. May not be used with `backrefs`. Possible values are: BOF, *regex*. | Optional | 
| create | Used with `state=present`. If specified, the file will be created if it does not already exist. By default it will fail if the file is missing. Possible values are: Yes, No. Default is No. | Optional | 
| validate | Validation to run before copying into place. Use %s in the command to indicate the current file to validate.<br/>The command is passed securely so shell features like expansion and pipes won't work. | Optional | 
| encoding | Specifies the encoding of the source text file to operate on (and thus what the output encoding will be). The default of `auto` will cause the module to auto-detect the encoding of the source file and ensure that the modified file is written with the same encoding.<br/>An explicit encoding can be passed as a string that is a valid value to pass to the .NET framework System.Text.Encoding.GetEncoding() method - see `https://msdn.microsoft.com/en-us/library/system.text.encoding%28v=vs.110%29.aspx`.<br/>This is mostly useful with `create=yes` if you want to create a new file with a specific encoding. If `create=yes` is specified without a specific encoding, the default encoding (UTF-8, no BOM) will be used. Default is auto. | Optional | 
| newline | Specifies the line separator style to use for the modified file. This defaults to the windows line separator (`\r\n`). Note that the indicated line separator will be used for file output regardless of the original line separator that appears in the input file. Possible values are: unix, windows. Default is windows. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinLineinfile.backup | string | Name of the backup file that was created.
This is now deprecated, use \`backup_file\` instead. | 
| MicrosoftWindows.WinLineinfile.backup_file | string | Name of the backup file that was created. | 


#### Command Example
```!win-lineinfile host="123.123.123.123" path="c:/temp/file.txt" line="c:/temp/new" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinLineinfile": {
            "backup": "",
            "changed": true,
            "encoding": "utf-8",
            "host": "123.123.123.123",
            "msg": "line added",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * backup: 
>  * changed: True
>  * encoding: utf-8
>  * msg: line added


### win-mapped-drive
***
Map network drives for users
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_mapped_drive_module.html


#### Base Command

`win-mapped-drive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| letter | The letter of the network path to map to.<br/>This letter must not already be in use with Windows. | Required | 
| password | The password for `username` that is used when testing the initial connection.<br/>This is never saved with a mapped drive, use the `win_credential` module to persist a username and password for a host. | Optional | 
| path | The UNC path to map the drive to.<br/>If pointing to a WebDAV location this must still be in a UNC path in the format `\\hostname\path` and not a URL, see examples for more details.<br/>To specify a `https` WebDAV path, add `@SSL` after the hostname. To specify a custom WebDAV port add `@&lt;port num&gt;` after the `@SSL` or hostname portion of the UNC path, e.g. `\\server@SSL@1234` or `\\server@1234`.<br/>This is required if `state=present`.<br/>If `state=absent` and `path` is not set, the module will delete the mapped drive regardless of the target.<br/>If `state=absent` and the `path` is set, the module will throw an error if path does not match the target of the mapped drive. | Optional | 
| state | If `present` will ensure the mapped drive exists.<br/>If `absent` will ensure the mapped drive does not exist. Possible values are: absent, present. Default is present. | Optional | 
| username | The username that is used when testing the initial connection.<br/>This is never saved with a mapped drive, the the `win_credential` module to persist a username and password for a host.<br/>This is required if the mapped drive requires authentication with custom credentials and become, or CredSSP cannot be used.<br/>If become or CredSSP is used, any credentials saved with `win_credential` will automatically be used instead. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-msg
***
Sends a message to logged in users on Windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_msg_module.html


#### Base Command

`win-msg`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| to | Who to send the message to. Can be a username, sessionname or sessionid. Default is *. | Optional | 
| display_seconds | How long to wait for receiver to acknowledge message, in seconds. Default is 10. | Optional | 
| wait | Whether to wait for users to respond.  Module will only wait for the number of seconds specified in display_seconds or 10 seconds if not specified. However, if `wait` is `yes`, the message is sent to each logged on user in turn, waiting for the user to either press 'ok' or for the timeout to elapse before moving on to the next user. Default is no. | Optional | 
| msg | The text of the message to be displayed.<br/>The message must be less than 256 characters. Default is Hello world!. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinMsg.msg | string | Test of the message that was sent. | 
| MicrosoftWindows.WinMsg.display_seconds | string | Value of display_seconds module parameter. | 
| MicrosoftWindows.WinMsg.rc | number | The return code of the API call. | 
| MicrosoftWindows.WinMsg.runtime_seconds | string | How long the module took to run on the remote windows host. | 
| MicrosoftWindows.WinMsg.sent_localtime | string | local time from windows host when the message was sent. | 
| MicrosoftWindows.WinMsg.wait | boolean | Value of wait module parameter. | 


#### Command Example
```!win-msg host="123.123.123.123" display_seconds="60" msg="Automated upgrade about to start.  Please save your work and log off before 6pm" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinMsg": {
            "changed": true,
            "display_seconds": 60,
            "host": "123.123.123.123",
            "msg": "Automated upgrade about to start.  Please save your work and log off before 6pm",
            "rc": 0,
            "runtime_seconds": 0.10118519999999999,
            "sent_localtime": "Tuesday, June 29, 2021 5:19:08 AM",
            "status": "CHANGED",
            "wait": false
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * display_seconds: 60
>  * msg: Automated upgrade about to start.  Please save your work and log off before 6pm
>  * rc: 0
>  * runtime_seconds: 0.10118519999999999
>  * sent_localtime: Tuesday, June 29, 2021 5:19:08 AM
>  * wait: False


### win-netbios
***
Manage NetBIOS over TCP/IP settings on Windows.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_netbios_module.html


#### Base Command

`win-netbios`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether NetBIOS should be enabled, disabled, or default (use setting from DHCP server or if static IP address is assigned enable NetBIOS). Possible values are: enabled, disabled, default. | Required | 
| adapter_names | List of adapter names for which to manage NetBIOS settings. If this option is omitted then configuration is applied to all adapters on the system.<br/>The adapter name used is the connection caption in the Network Control Panel or via `Get-NetAdapter`, eg `Ethernet 2`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinNetbios.reboot_required | boolean | Boolean value stating whether a system reboot is required. | 


#### Command Example
```!win-netbios host="123.123.123.123" state="disabled" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinNetbios": {
            "changed": false,
            "host": "123.123.123.123",
            "reboot_required": false,
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * reboot_required: False


### win-nssm
***
Install a service using NSSM
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_nssm_module.html


#### Base Command

`win-nssm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the service to operate on. | Required | 
| state | State of the service on the system.<br/>Values `started`, `stopped`, and `restarted` are deprecated since v2.8, please use the `win_service` module instead to start, stop or restart the service. Possible values are: absent, present, started, stopped, restarted. Default is present. | Optional | 
| application | The application binary to run as a service<br/>Required when `state` is `present`, `started`, `stopped`, or `restarted`. | Optional | 
| executable | The location of the NSSM utility (in case it is not located in your PATH). Default is nssm.exe. | Optional | 
| description | The description to set for the service. | Optional | 
| display_name | The display name to set for the service. | Optional | 
| working_directory | The working directory to run the service executable from (defaults to the directory containing the application binary). | Optional | 
| stdout_file | Path to receive output. | Optional | 
| stderr_file | Path to receive error output. | Optional | 
| app_parameters | A string representing a dictionary of parameters to be passed to the application when it starts.<br/>DEPRECATED since v2.8, please use `arguments` instead.<br/>This is mutually exclusive with `arguments`. | Optional | 
| arguments | Parameters to be passed to the application when it starts.<br/>This can be either a simple string or a list.<br/>This parameter was renamed from `app_parameters_free_form` in 2.8.<br/>This is mutually exclusive with `app_parameters`. | Optional | 
| dependencies | Service dependencies that has to be started to trigger startup, separated by comma.<br/>DEPRECATED since v2.8, please use the `win_service` module instead. | Optional | 
| user | User to be used for service startup.<br/>DEPRECATED since v2.8, please use the `win_service` module instead. | Optional | 
| password | Password to be used for service startup.<br/>DEPRECATED since v2.8, please use the `win_service` module instead. | Optional | 
| start_mode | If `auto` is selected, the service will start at bootup.<br/>`delayed` causes a delayed but automatic start after boot (added in version 2.5).<br/>`manual` means that the service will start only when another service needs it.<br/>`disabled` means that the service will stay off, regardless if it is needed or not.<br/>DEPRECATED since v2.8, please use the `win_service` module instead. Possible values are: auto, delayed, disabled, manual. Default is auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-nssm host="123.123.123.123" name="foo" application="C:/windows/system32/calc.exe" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinNssm": {
            "changed": true,
            "changed_by": "AppRotateBytes",
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * changed_by: AppRotateBytes


### win-optional-feature
***
Manage optional Windows features
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_optional_feature_module.html


#### Base Command

`win-optional-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name(s) of the feature to install.<br/>This relates to `FeatureName` in the Powershell cmdlet.<br/>To list all available features use the PowerShell command `Get-WindowsOptionalFeature`. | Required | 
| state | Whether to ensure the feature is absent or present on the system. Possible values are: absent, present. Default is present. | Optional | 
| include_parent | Whether to enable the parent feature and the parent's dependencies. Possible values are: Yes, No. Default is No. | Optional | 
| source | Specify a source to install the feature from.<br/>Can either be `{driveletter}:\sources\sxs` or `\\{IP}\share\sources\sxs`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinOptionalFeature.reboot_required | boolean | True when the target server requires a reboot to complete updates | 


#### Command Example
```!win-optional-feature host="123.123.123.123" name="TelnetClient" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinOptionalFeature": {
            "changed": false,
            "host": "123.123.123.123",
            "reboot_required": false,
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * reboot_required: False


### win-owner
***
Set owner
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_owner_module.html


#### Base Command

`win-owner`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to be used for changing owner. | Required | 
| user | Name to be used for changing owner. | Required | 
| recurse | Indicates if the owner should be changed recursively. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-owner host="123.123.123.123" path="C:/apache" user="fed-phil" recurse="True" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinOwner": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-package
***
Installs/uninstalls an installable package
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_package_module.html


#### Base Command

`win-package`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| arguments | Any arguments the installer needs to either install or uninstall the package.<br/>If the package is an MSI do not supply the `/qn`, `/log` or `/norestart` arguments.<br/>As of Ansible 2.5, this parameter can be a list of arguments and the module will escape the arguments as necessary, it is recommended to use a string when dealing with MSI packages due to the unique escaping issues with msiexec. | Optional | 
| chdir | Set the specified path as the current working directory before installing or uninstalling a package. | Optional | 
| creates_path | Will check the existence of the path specified and use the result to determine whether the package is already installed.<br/>You can use this in conjunction with `product_id` and other `creates_*`. | Optional | 
| creates_service | Will check the existing of the service specified and use the result to determine whether the package is already installed.<br/>You can use this in conjunction with `product_id` and other `creates_*`. | Optional | 
| creates_version | Will check the file version property of the file at `creates_path` and use the result to determine whether the package is already installed.<br/>`creates_path` MUST be set and is a file.<br/>You can use this in conjunction with `product_id` and other `creates_*`. | Optional | 
| expected_return_code | One or more return codes from the package installation that indicates success.<br/>Before Ansible 2.4 this was just 0 but since Ansible 2.4 this is both `0` and `3010`.<br/>A return code of `3010` usually means that a reboot is required, the `reboot_required` return value is set if the return code is `3010`. Default is [0, 3010]. | Optional | 
| password | The password for `user_name`, must be set when `user_name` is. | Optional | 
| path | Location of the package to be installed or uninstalled.<br/>This package can either be on the local file system, network share or a url.<br/>If the path is on a network share and the current WinRM transport doesn't support credential delegation, then `user_name` and `user_password` must be set to access the file.<br/>There are cases where this file will be copied locally to the server so it can access it, see the notes for more info.<br/>If `state=present` then this value MUST be set.<br/>If `state=absent` then this value does not need to be set if `product_id` is. | Optional | 
| product_id | The product id of the installed packaged.<br/>This is used for checking whether the product is already installed and getting the uninstall information if `state=absent`.<br/>You can find product ids for installed programs in the Windows registry editor either at `HKLM:Software\Microsoft\Windows\CurrentVersion\Uninstall` or for 32 bit programs at `HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`.<br/>This SHOULD be set when the package is not an MSI, or the path is a url or a network share and credential delegation is not being used. The `creates_*` options can be used instead but is not recommended. | Optional | 
| state | Whether to install or uninstall the package.<br/>The module uses `product_id` and whether it exists at the registry path to see whether it needs to install or uninstall the package. Possible values are: absent, present. Default is present. | Optional | 
| username | Username of an account with access to the package if it is located on a file share.<br/>This is only needed if the WinRM transport is over an auth method that does not support credential delegation like Basic or NTLM. | Optional | 
| validate_certs | If `no`, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.<br/>Before Ansible 2.4 this defaulted to `no`. Possible values are: Yes, No. Default is Yes. | Optional | 
| log_path | Specifies the path to a log file that is persisted after an MSI package is installed or uninstalled.<br/>When omitted, a temporary log file is used for MSI packages.<br/>This is only valid for MSI files, use `arguments` for other package types. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPackage.log | string | The contents of the MSI log. | 
| MicrosoftWindows.WinPackage.rc | number | The return code of the package process. | 
| MicrosoftWindows.WinPackage.reboot_required | boolean | Whether a reboot is required to finalise package. This is set to true if the executable return code is 3010. | 
| MicrosoftWindows.WinPackage.stdout | string | The stdout stream of the package process. | 
| MicrosoftWindows.WinPackage.stderr | string | The stderr stream of the package process. | 




### win-pagefile
***
Query or change pagefile configuration
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_pagefile_module.html


#### Base Command

`win-pagefile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| drive | The drive of the pagefile. | Optional | 
| initial_size | The initial size of the pagefile in megabytes. | Optional | 
| maximum_size | The maximum size of the pagefile in megabytes. | Optional | 
| override | Override the current pagefile on the drive. Possible values are: Yes, No. Default is Yes. | Optional | 
| system_managed | Configures current pagefile to be managed by the system. Possible values are: Yes, No. Default is No. | Optional | 
| automatic | Configures AutomaticManagedPagefile for the entire system. | Optional | 
| remove_all | Remove all pagefiles in the system, not including automatic managed. Possible values are: Yes, No. Default is No. | Optional | 
| test_path | Use Test-Path on the drive to make sure the drive is accessible before creating the pagefile. Possible values are: Yes, No. Default is Yes. | Optional | 
| state | State of the pagefile. Possible values are: absent, present, query. Default is query. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPagefile.automatic_managed_pagefiles | boolean | Whether the pagefiles is automatically managed. | 
| MicrosoftWindows.WinPagefile.pagefiles | unknown | Contains caption, description, initial_size, maximum_size and name for each pagefile in the system. | 


#### Command Example
```!win-pagefile host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPagefile": {
            "automatic_managed_pagefiles": true,
            "changed": false,
            "host": "123.123.123.123",
            "pagefiles": [],
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * automatic_managed_pagefiles: True
>  * changed: False
>  * ## Pagefiles


### win-partition
***
Creates, changes and removes partitions on Windows Server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_partition_module.html


#### Base Command

`win-partition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Used to specify the state of the partition. Use `absent` to specify if a partition should be removed and `present` to specify if the partition should be created or updated. Possible values are: absent, present. Default is present. | Optional | 
| drive_letter | Used for accessing partitions if `disk_number` and `partition_number` are not provided.<br/>Use `auto` for automatically assigning a drive letter, or a letter A-Z for manually assigning a drive letter to a new partition. If not specified, no drive letter is assigned when creating a new partition. | Optional | 
| disk_number | Disk number is mandatory for creating new partitions.<br/>A combination of `disk_number` and `partition_number` can be used to specify the partition instead of `drive_letter` if required. | Optional | 
| partition_number | Used in conjunction with `disk_number` to uniquely identify a partition. | Optional | 
| partition_size | Specify size of the partition in B, KB, KiB, MB, MiB, GB, GiB, TB or TiB. Use -1 to specify maximum supported size.<br/>Partition size is mandatory for creating a new partition but not for updating or deleting a partition.<br/>The decimal SI prefixes kilo, mega, giga, tera, etc., are powers of 10^3 = 1000. The binary prefixes kibi, mebi, gibi, tebi, etc. respectively refer to the corresponding power of 2^10 = 1024. Thus, a gigabyte (GB) is 1000000000 (1000^3) bytes while 1 gibibyte (GiB) is 1073741824 (1024^3) bytes. | Optional | 
| read_only | Make the partition read only, restricting changes from being made to the partition. | Optional | 
| active | Specifies if the partition is active and can be used to start the system. This property is only valid when the disk's partition style is MBR. | Optional | 
| hidden | Hides the target partition, making it undetectable by the mount manager. | Optional | 
| offline | Sets the partition offline.<br/>Adding a mount point (such as a drive letter) will cause the partition to go online again. | Optional | 
| mbr_type | Specify the partition's MBR type if the disk's partition style is MBR.<br/>This only applies to new partitions.<br/>This does not relate to the partitions file system formatting. Possible values are: fat12, fat16, extended, huge, ifs, fat32. | Optional | 
| gpt_type | Specify the partition's GPT type if the disk's partition style is GPT.<br/>This only applies to new partitions.<br/>This does not relate to the partitions file system formatting. Possible values are: system_partition, microsoft_reserved, basic_data, microsoft_recovery. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-partition host="123.123.123.123" drive_letter="F" partition_size="10 MB" disk_number="1"```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPartition": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True

### win-path
***
Manage Windows path environment variables
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_path_module.html


#### Base Command

`win-path`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Target path environment variable name. Default is PATH. | Optional | 
| elements | A single path element, or a list of path elements (ie, directories) to add or remove.<br/>When multiple elements are included in the list (and `state` is `present`), the elements are guaranteed to appear in the same relative order in the resultant path value.<br/>Variable expansions (eg, `%VARNAME%`) are allowed, and are stored unexpanded in the target path element.<br/>Any existing path elements not mentioned in `elements` are always preserved in their current order.<br/>New path elements are appended to the path, and existing path elements may be moved closer to the end to satisfy the requested ordering.<br/>Paths are compared in a case-insensitive fashion, and trailing backslashes are ignored for comparison purposes. However, note that trailing backslashes in YAML require quotes. | Required | 
| state | Whether the path elements specified in `elements` should be present or absent. Possible values are: absent, present. | Optional | 
| scope | The level at which the environment variable specified by `name` should be managed (either for the current user or global machine scope). Possible values are: machine, user. Default is machine. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-path host="123.123.123.123" elements="['%SystemRoot%\\\\system32', '%SystemRoot%\\\\system32\\\\WindowsPowerShell\\\\v1.0']" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPath": {
            "changed": false,
            "host": "123.123.123.123",
            "path_value": "%SystemRoot%\\system32;%SystemRoot%;%SystemRoot%\\System32\\Wbem;%SYSTEMROOT%\\System32\\WindowsPowerShell\\v1.0\\;C:\\ProgramData\\chocolatey\\bin;['%SystemRoot%\\system32', '%SystemRoot%\\system32\\WindowsPowerShell\\v1.0'];C:\\Program Files\\Git\\cmd",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * path_value: %SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\;C:\ProgramData\chocolatey\bin;['%SystemRoot%\system32', '%SystemRoot%\system32\WindowsPowerShell\v1.0'];C:\Program Files\Git\cmd


### win-pester
***
Run Pester tests on Windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_pester_module.html


#### Base Command

`win-pester`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Path to a pester test file or a folder where tests can be found.<br/>If the path is a folder, the module will consider all ps1 files as Pester tests. | Required | 
| tags | Runs only tests in Describe blocks with specified Tags values.<br/>Accepts multiple comma separated tags. | Optional | 
| test_parameters | Allows to specify parameters to the test script. | Optional | 
| version | Minimum version of the pester module that has to be available on the remote host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPester.pester_version | string | Version of the pester module found on the remote host. | 
| MicrosoftWindows.WinPester.output | unknown | Results of the Pester tests. | 




### win-ping
***
A windows version of the classic ping module
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_ping_module.html


#### Base Command

`win-ping`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| data | Alternate data to return instead of 'pong'.<br/>If this parameter is set to `crash`, the module will cause an exception. Default is pong. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPing.ping | string | Value provided with the data parameter. | 


#### Command Example
```!win-ping host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPing": {
            "changed": false,
            "host": "123.123.123.123",
            "ping": "pong",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ping: pong


### win-power-plan
***
Changes the power plan of a Windows system
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_power_plan_module.html


#### Base Command

`win-power-plan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | String value that indicates the desired power plan.<br/>The power plan must already be present on the system.<br/>Commonly there will be options for `balanced` and `high performance`. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPowerPlan.power_plan_name | string | Value of the intended power plan. | 
| MicrosoftWindows.WinPowerPlan.power_plan_enabled | boolean | State of the intended power plan. | 
| MicrosoftWindows.WinPowerPlan.all_available_plans | unknown | The name and enabled state of all power plans. | 


#### Command Example
```!win-power-plan host="123.123.123.123" name="high performance" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPowerPlan": {
            "all_available_plans": {
                "Balanced": false,
                "High performance": true,
                "Power saver": false
            },
            "changed": false,
            "host": "123.123.123.123",
            "power_plan_enabled": true,
            "power_plan_name": "high performance",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * power_plan_enabled: True
>  * power_plan_name: high performance
>  * ## All_Available_Plans
>    * Balanced: False
>    * High performance: True
>    * Power saver: False


### win-product-facts
***
Provides Windows product and license information
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_product_facts_module.html


#### Base Command

`win-product-facts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinProductFacts.facts | unknown | Dictionary containing all the detailed information about the Windows product and license. | 


#### Command Example
```!win-product-facts host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinProductFacts": {
            "host": "123.123.123.123",
            "os_license_channel": "Retail:TB:Eval",
            "os_license_edition": "Windows(R), ServerStandardEval edition",
            "os_license_status": "Licensed",
            "os_product_id": "00378-00000-00000-AA739",
            "os_product_key": "WD6GH-2TH8C-77QD4-8WVRH-9BVYG",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * os_license_channel: Retail:TB:Eval
>  * os_license_edition: Windows(R), ServerStandardEval edition
>  * os_license_status: Licensed
>  * os_product_id: 00378-00000-00000-AA739
>  * os_product_key: WD6GH-2TH8C-77QD4-8WVRH-9BVYG


### win-psexec
***
Runs commands (remotely) as another (privileged) user
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_psexec_module.html


#### Base Command

`win-psexec`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| command | The command line to run through PsExec (limited to 260 characters). | Required | 
| executable | The location of the PsExec utility (in case it is not located in your PATH). Default is psexec.exe. | Optional | 
| extra_opts | Specify additional options to add onto the PsExec invocation.<br/>This module was undocumented in older releases and will be removed in Ansible 2.10. | Optional | 
| hostnames | The hostnames to run the command.<br/>If not provided, the command is run locally. | Optional | 
| username | The (remote) user to run the command as.<br/>If not provided, the current user is used. | Optional | 
| password | The password for the (remote) user to run the command as.<br/>This is mandatory in order authenticate yourself. | Optional | 
| chdir | Run the command from this (remote) directory. | Optional | 
| nobanner | Do not display the startup banner and copyright message.<br/>This only works for specific versions of the PsExec binary. Possible values are: Yes, No. Default is No. | Optional | 
| noprofile | Run the command without loading the account's profile. Possible values are: Yes, No. Default is No. | Optional | 
| elevated | Run the command with elevated privileges. Possible values are: Yes, No. Default is No. | Optional | 
| interactive | Run the program so that it interacts with the desktop on the remote system. Possible values are: Yes, No. Default is No. | Optional | 
| session | Specifies the session ID to use.<br/>This parameter works in conjunction with `interactive`.<br/>It has no effect when `interactive` is set to `no`. | Optional | 
| limited | Run the command as limited user (strips the Administrators group and allows only privileges assigned to the Users group). Possible values are: Yes, No. Default is No. | Optional | 
| system | Run the remote command in the System account. Possible values are: Yes, No. Default is No. | Optional | 
| priority | Used to run the command at a different priority. Possible values are: abovenormal, background, belownormal, high, low, realtime. | Optional | 
| timeout | The connection timeout in seconds. | Optional | 
| wait | Wait for the application to terminate.<br/>Only use for non-interactive applications. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPsexec.cmd | string | The complete command line used by the module, including PsExec call and additional options. | 
| MicrosoftWindows.WinPsexec.pid | number | The PID of the async process created by PsExec. | 
| MicrosoftWindows.WinPsexec.rc | number | The return code for the command. | 
| MicrosoftWindows.WinPsexec.stdout | string | The standard output from the command. | 
| MicrosoftWindows.WinPsexec.stderr | string | The error output from the command. | 


#### Command Example
```!win-psexec host="123.123.123.123" command="whoami.exe" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPsexec": {
            "changed": true,
            "delta": "0:00:01.375000",
            "end": "2021-06-29 04:18:35.671487",
            "host": "123.123.123.123",
            "psexec_command": "psexec.exe -accepteula whoami.exe",
            "rc": 0,
            "start": "2021-06-29 04:18:34.296487",
            "status": "CHANGED",
            "stderr": "whoami.exe exited with error code 0.\r\n",
            "stderr_lines": [
                "whoami.exe exited with error code 0."
            ],
            "stdout": "\r\nPsExec v2.34 - Execute processes remotely\r\nCopyright (C) 2001-2021 Mark Russinovich\r\nSysinternals - www.sysinternals.com\r\n\r\n",
            "stdout_lines": [
                "",
                "PsExec v2.34 - Execute processes remotely",
                "Copyright (C) 2001-2021 Mark Russinovich",
                "Sysinternals - www.sysinternals.com",
                ""
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * delta: 0:00:01.375000
>  * end: 2021-06-29 04:18:35.671487
>  * psexec_command: psexec.exe -accepteula whoami.exe
>  * rc: 0
>  * start: 2021-06-29 04:18:34.296487
>  * stderr: whoami.exe exited with error code 0.
>
>  * stdout: 
>PsExec v2.34 - Execute processes remotely
>Copyright (C) 2001-2021 Mark Russinovich
>Sysinternals - www.sysinternals.com
>
>
>  * ## Stderr_Lines
>    * 0: whoami.exe exited with error code 0.
>  * ## Stdout_Lines
>    * 0: 
>    * 1: PsExec v2.34 - Execute processes remotely
>    * 2: Copyright (C) 2001-2021 Mark Russinovich
>    * 3: Sysinternals - www.sysinternals.com
>    * 0: 

### win-psmodule
***
Adds or removes a Windows PowerShell module
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_psmodule_module.html


#### Base Command

`win-psmodule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the Windows PowerShell module that has to be installed. | Required | 
| state | If `present` a new module is installed.<br/>If `absent` a module is removed.<br/>If `latest` a module is updated to the newest version. This option was added in version 2.8. Possible values are: absent, latest, present. Default is present. | Optional | 
| required_version | The exact version of the PowerShell module that has to be installed. | Optional | 
| minimum_version | The minimum version of the PowerShell module that has to be installed. | Optional | 
| maximum_version | The maximum version of the PowerShell module that has to be installed. | Optional | 
| allow_clobber | If `yes` allows install modules that contains commands those have the same names as commands that already exists. Possible values are: Yes, No. Default is No. | Optional | 
| skip_publisher_check | If `yes`, allows you to install a different version of a module that already exists on your computer in the case when a different one is not digitally signed by a trusted publisher and the newest existing module is digitally signed by a trusted publisher. Possible values are: Yes, No. Default is No. | Optional | 
| allow_prerelease | If `yes` installs modules marked as prereleases.<br/>It doesn't work with the parameters `minimum_version` and/or `maximum_version`.<br/>It doesn't work with the `state` set to absent. Possible values are: Yes, No. Default is No. | Optional | 
| repository | Name of the custom repository to use. | Optional | 
| url | URL of the custom repository to register.<br/>This option is deprecated and will be removed in Ansible 2.12. Use the `win_psrepository` module instead. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinPsmodule.output | string | A message describing the task result. | 
| MicrosoftWindows.WinPsmodule.nuget_changed | boolean | True when Nuget package provider is installed. | 
| MicrosoftWindows.WinPsmodule.repository_changed | boolean | True when a custom repository is installed or removed. | 


#### Command Example
```!win-psmodule host="123.123.123.123" name="PowerShellModule" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPsmodule": {
            "changed": false,
            "host": "123.123.123.123",
            "nuget_changed": false,
            "output": "Module PowerShellModule already present",
            "repository_changed": false,
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * nuget_changed: False
>  * output: Module PowerShellModule already present
>  * repository_changed: False


### win-psrepository
***
Adds, removes or updates a Windows PowerShell repository.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_psrepository_module.html


#### Base Command

`win-psrepository`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the repository to work with. | Required | 
| source | Specifies the URI for discovering and installing modules from this repository.<br/>A URI can be a NuGet server feed (most common situation), HTTP, HTTPS, FTP or file location. | Optional | 
| state | If `present` a new repository is added or updated.<br/>If `absent` a repository is removed. Possible values are: absent, present. Default is present. | Optional | 
| installation_policy | Sets the `InstallationPolicy` of a repository.<br/>Will default to `trusted` when creating a new repository. Possible values are: trusted, untrusted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-psrepository host="123.123.123.123" name="PSGallery" state="present"```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPsrepository": {
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


### win-rabbitmq-plugin
***
Manage RabbitMQ plugins
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_rabbitmq_plugin_module.html


#### Base Command

`win-rabbitmq-plugin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| names | Comma-separated list of plugin names. | Required | 
| new_only | Only enable missing plugins.<br/>Does not disable plugins that are not in the names list. Possible values are: Yes, No. Default is No. | Optional | 
| state | Specify if plugins are to be enabled or disabled. Possible values are: disabled, enabled. Default is enabled. | Optional | 
| prefix | Specify a custom install prefix to a Rabbit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRabbitmqPlugin.enabled | unknown | List of plugins enabled during task run. | 
| MicrosoftWindows.WinRabbitmqPlugin.disabled | unknown | List of plugins disabled during task run. | 




### win-rds-cap
***
Manage Connection Authorization Policies (CAP) on a Remote Desktop Gateway server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_rds_cap_module.html


#### Base Command

`win-rds-cap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the connection authorization policy. | Required | 
| state | The state of connection authorization policy.<br/>If `absent` will ensure the policy is removed.<br/>If `present` will ensure the policy is configured and exists.<br/>If `enabled` will ensure the policy is configured, exists and enabled.<br/>If `disabled` will ensure the policy is configured, exists, but disabled. Possible values are: absent, enabled, disabled, present. Default is present. | Optional | 
| auth_method | Specifies how the RD Gateway server authenticates users.<br/>When a new CAP is created, the default value is `password`. Possible values are: both, none, password, smartcard. | Optional | 
| order | Evaluation order of the policy.<br/>The CAP in which `order` is set to a value of '1' is evaluated first.<br/>By default, a newly created CAP will take the first position.<br/>If the given value exceed the total number of existing policies, the policy will take the last position but the evaluation order will be capped to this number. | Optional | 
| session_timeout | The maximum time, in minutes, that a session can be idle.<br/>A value of zero disables session timeout. | Optional | 
| session_timeout_action | The action the server takes when a session times out.<br/>`disconnect`: disconnect the session.<br/>`reauth`: silently reauthenticate and reauthorize the session. Possible values are: disconnect, reauth. Default is disconnect. | Optional | 
| idle_timeout | Specifies the time interval, in minutes, after which an idle session is disconnected.<br/>A value of zero disables idle timeout. | Optional | 
| allow_only_sdrts_servers | Specifies whether connections are allowed only to Remote Desktop Session Host servers that enforce Remote Desktop Gateway redirection policy. | Optional | 
| user_groups | A list of user groups that is allowed to connect to the Remote Gateway server.<br/>Required when a new CAP is created. | Optional | 
| computer_groups | A list of computer groups that is allowed to connect to the Remote Gateway server. | Optional | 
| redirect_clipboard | Allow clipboard redirection. | Optional | 
| redirect_drives | Allow disk drive redirection. | Optional | 
| redirect_printers | Allow printers redirection. | Optional | 
| redirect_serial | Allow serial port redirection. | Optional | 
| redirect_pnp | Allow Plug and Play devices redirection. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-rds-rap
***
Manage Resource Authorization Policies (RAP) on a Remote Desktop Gateway server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_rds_rap_module.html


#### Base Command

`win-rds-rap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the resource authorization policy. | Required | 
| state | The state of resource authorization policy.<br/>If `absent` will ensure the policy is removed.<br/>If `present` will ensure the policy is configured and exists.<br/>If `enabled` will ensure the policy is configured, exists and enabled.<br/>If `disabled` will ensure the policy is configured, exists, but disabled. Possible values are: absent, disabled, enabled, present. Default is present. | Optional | 
| description | Optional description of the resource authorization policy. | Optional | 
| user_groups | List of user groups that are associated with this resource authorization policy (RAP). A user must belong to one of these groups to access the RD Gateway server.<br/>Required when a new RAP is created. | Optional | 
| allowed_ports | List of port numbers through which connections are allowed for this policy.<br/>To allow connections through any port, specify 'any'. | Optional | 
| computer_group_type | The computer group type:<br/>`rdg_group`: RD Gateway-managed group<br/>`ad_network_resource_group`: Active Directory Domain Services network resource group<br/>`allow_any`: Allow users to connect to any network resource. Possible values are: rdg_group, ad_network_resource_group, allow_any. | Optional | 
| computer_group | The computer group name that is associated with this resource authorization policy (RAP).<br/>This is required when `computer_group_type` is `rdg_group` or `ad_network_resource_group`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-rds-settings
***
Manage main settings of a Remote Desktop Gateway server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_rds_settings_module.html


#### Base Command

`win-rds-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| certificate_hash | Certificate hash (thumbprint) for the Remote Desktop Gateway server. The certificate hash is the unique identifier for the certificate. | Optional | 
| max_connections | The maximum number of connections allowed.<br/>If set to `0`, no new connections are allowed.<br/>If set to `-1`, the number of connections is unlimited. | Optional | 
| ssl_bridging | Specifies whether to use SSL Bridging.<br/>`none`: no SSL bridging.<br/>`https_http`: HTTPS-HTTP bridging.<br/>`https_https`: HTTPS-HTTPS bridging. Possible values are: https_http, https_https, none. | Optional | 
| enable_only_messaging_capable_clients | If enabled, only clients that support logon messages and administrator messages can connect. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-reboot
***
Reboot a windows machine
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_reboot_module.html


#### Base Command

`win-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| pre_reboot_delay | Seconds to wait before reboot. Passed as a parameter to the reboot command. Default is 2. | Optional | 
| post_reboot_delay | Seconds to wait after the reboot command was successful before attempting to validate the system rebooted successfully.<br/>This is useful if you want wait for something to settle despite your connection already working. Default is 0. | Optional | 
| shutdown_timeout | Maximum seconds to wait for shutdown to occur.<br/>Increase this timeout for very slow hardware, large update applications, etc.<br/>This option has been removed since Ansible 2.5 as the win_reboot behavior has changed. Default is 600. | Optional | 
| reboot_timeout | Maximum seconds to wait for machine to re-appear on the network and respond to a test command.<br/>This timeout is evaluated separately for both reboot verification and test command success so maximum clock time is actually twice this value. Default is 600. | Optional | 
| connect_timeout | Maximum seconds to wait for a single successful TCP connection to the WinRM endpoint before trying again. Default is 5. | Optional | 
| test_command | Command to expect success for to determine the machine is ready for management. Default is whoami. | Optional | 
| msg | Message to display to users. Default is Reboot initiated by Ansible. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinReboot.rebooted | boolean | True if the machine was rebooted. | 
| MicrosoftWindows.WinReboot.elapsed | unknown | The number of seconds that elapsed waiting for the system to be rebooted. | 


#### Command Example
```!win-reboot host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinPsrepository": {
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

### win-reg-stat
***
Get information about Windows registry keys
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_reg_stat_module.html


#### Base Command

`win-reg-stat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The full registry key path including the hive to search for. | Required | 
| name | The registry property name to get information for, the return json will not include the sub_keys and properties entries for the `key` specified.<br/>Set to an empty string to target the registry key's `(Default`) property value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRegStat.changed | boolean | Whether anything was changed. | 
| MicrosoftWindows.WinRegStat.exists | boolean | States whether the registry key/property exists. | 
| MicrosoftWindows.WinRegStat.properties | unknown | A dictionary containing all the properties and their values in the registry key. | 
| MicrosoftWindows.WinRegStat.sub_keys | unknown | A list of all the sub keys of the key specified. | 
| MicrosoftWindows.WinRegStat.raw_value | string | Returns the raw value of the registry property, REG_EXPAND_SZ has no string expansion, REG_BINARY or REG_NONE is in hex 0x format. REG_NONE, this value is a hex string in the 0x format. | 
| MicrosoftWindows.WinRegStat.type | string | The property type. | 
| MicrosoftWindows.WinRegStat.value | string | The value of the property. | 


#### Command Example
```!win-reg-stat host="123.123.123.123" path="HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinRegStat": {
            "changed": false,
            "exists": true,
            "host": "123.123.123.123",
            "properties": {
                "CommonFilesDir": {
                    "raw_value": "C:\\Program Files\\Common Files",
                    "type": "REG_SZ",
                    "value": "C:\\Program Files\\Common Files"
                },
                "CommonFilesDir (x86)": {
                    "raw_value": "C:\\Program Files (x86)\\Common Files",
                    "type": "REG_SZ",
                    "value": "C:\\Program Files (x86)\\Common Files"
                },
                "CommonW6432Dir": {
                    "raw_value": "C:\\Program Files\\Common Files",
                    "type": "REG_SZ",
                    "value": "C:\\Program Files\\Common Files"
                },
                "DevicePath": {
                    "raw_value": "%SystemRoot%\\inf",
                    "type": "REG_EXPAND_SZ",
                    "value": "C:\\Windows\\inf"
                },
                "MediaPathUnexpanded": {
                    "raw_value": "%SystemRoot%\\Media",
                    "type": "REG_EXPAND_SZ",
                    "value": "C:\\Windows\\Media"
                },
                "ProgramFilesDir": {
                    "raw_value": "C:\\Program Files",
                    "type": "REG_SZ",
                    "value": "C:\\Program Files"
                },
                "ProgramFilesDir (x86)": {
                    "raw_value": "C:\\Program Files (x86)",
                    "type": "REG_SZ",
                    "value": "C:\\Program Files (x86)"
                },
                "ProgramFilesPath": {
                    "raw_value": "%ProgramFiles%",
                    "type": "REG_EXPAND_SZ",
                    "value": "C:\\Program Files"
                },
                "ProgramW6432Dir": {
                    "raw_value": "C:\\Program Files",
                    "type": "REG_SZ",
                    "value": "C:\\Program Files"
                },
                "SM_ConfigureProgramsName": {
                    "raw_value": "Set Program Access and Defaults",
                    "type": "REG_SZ",
                    "value": "Set Program Access and Defaults"
                },
                "SM_GamesName": {
                    "raw_value": "Games",
                    "type": "REG_SZ",
                    "value": "Games"
                }
            },
            "status": "SUCCESS",
            "sub_keys": [
                "AccountPicture",
                "ActionCenter"
            ]
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * exists: True
>  * ## Properties
>    * ### Commonfilesdir
>      * raw_value: C:\Program Files\Common Files
>      * type: REG_SZ
>      * value: C:\Program Files\Common Files
>    * ### Commonfilesdir (X86)
>      * raw_value: C:\Program Files (x86)\Common Files
>      * type: REG_SZ
>      * value: C:\Program Files (x86)\Common Files
>    * ### Commonw6432Dir
>      * raw_value: C:\Program Files\Common Files
>      * type: REG_SZ
>      * value: C:\Program Files\Common Files
>    * ### Devicepath
>      * raw_value: %SystemRoot%\inf
>      * type: REG_EXPAND_SZ
>      * value: C:\Windows\inf
>    * ### Mediapathunexpanded
>      * raw_value: %SystemRoot%\Media
>      * type: REG_EXPAND_SZ
>      * value: C:\Windows\Media
>    * ### Programfilesdir
>      * raw_value: C:\Program Files
>      * type: REG_SZ
>      * value: C:\Program Files
>    * ### Programfilesdir (X86)
>      * raw_value: C:\Program Files (x86)
>      * type: REG_SZ
>      * value: C:\Program Files (x86)
>    * ### Programfilespath
>      * raw_value: %ProgramFiles%
>      * type: REG_EXPAND_SZ
>      * value: C:\Program Files
>    * ### Programw6432Dir
>      * raw_value: C:\Program Files
>      * type: REG_SZ
>      * value: C:\Program Files
>    * ### Sm_Configureprogramsname
>      * raw_value: Set Program Access and Defaults
>      * type: REG_SZ
>      * value: Set Program Access and Defaults
>    * ### Sm_Gamesname
>      * raw_value: Games
>      * type: REG_SZ
>      * value: Games
>  * ## Sub_Keys
>    * 0: AccountPicture
>    * 1: ActionCenter


### win-regedit
***
Add, change, or remove registry keys and values
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_regedit_module.html


#### Base Command

`win-regedit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | Name of the registry path.<br/>Should be in one of the following registry hives: HKCC, HKCR, HKCU, HKLM, HKU. | Required | 
| name | Name of the registry entry in the above `path` parameters.<br/>If not provided, or empty then the '(Default)' property for the key will be used. | Optional | 
| data | Value of the registry entry `name` in `path`.<br/>If not specified then the value for the property will be null for the corresponding `type`.<br/>Binary and None data should be expressed in a yaml byte array or as comma separated hex values.<br/>An easy way to generate this is to run `regedit.exe` and use the `export` option to save the registry values to a file.<br/>In the exported file, binary value will look like `hex:be,ef,be,ef`, the `hex:` prefix is optional.<br/>DWORD and QWORD values should either be represented as a decimal number or a hex value.<br/>Multistring values should be passed in as a list.<br/>See the examples for more details on how to format this data. | Optional | 
| type | The registry value data type. Possible values are: binary, dword, expandstring, multistring, string, qword. Default is string. | Optional | 
| state | The state of the registry entry. Possible values are: absent, present. Default is present. | Optional | 
| delete_key | When `state` is 'absent' then this will delete the entire key.<br/>If `no` then it will only clear out the '(Default)' property for that key. Possible values are: Yes, No. Default is Yes. | Optional | 
| hive | A path to a hive key like C:\Users\Default\NTUSER.DAT to load in the registry.<br/>This hive is loaded under the HKLM:\ANSIBLE key which can then be used in `name` like any other path.<br/>This can be used to load the default user profile registry hive or any other hive saved as a file.<br/>Using this function requires the user to have the `SeRestorePrivilege` and `SeBackupPrivilege` privileges enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRegedit.data_changed | boolean | Whether this invocation changed the data in the registry value. | 
| MicrosoftWindows.WinRegedit.data_type_changed | boolean | Whether this invocation changed the datatype of the registry value. | 


#### Command Example
```!win-regedit host="123.123.123.123" path="HKCU:\\Software\\MyCompany" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinRegedit": {
            "changed": false,
            "data_changed": false,
            "data_type_changed": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * data_changed: False
>  * data_type_changed: False


### win-region
***
Set the region and format settings
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_region_module.html


#### Base Command

`win-region`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| location | The location to set for the current user, see `https://msdn.microsoft.com/en-us/library/dd374073.aspx` for a list of GeoIDs you can use and what location it relates to.<br/>This needs to be set if `format` or `unicode_language` is not set. | Optional | 
| format | The language format to set for the current user, see `https://msdn.microsoft.com/en-us/library/system.globalization.cultureinfo.aspx` for a list of culture names to use.<br/>This needs to be set if `location` or `unicode_language` is not set. | Optional | 
| unicode_language | The unicode language format to set for all users, see `https://msdn.microsoft.com/en-us/library/system.globalization.cultureinfo.aspx` for a list of culture names to use.<br/>This needs to be set if `location` or `format` is not set. After setting this value a reboot is required for it to take effect. | Optional | 
| copy_settings | This will copy the current format and location values to new user profiles and the welcome screen. This will only run if `location`, `format` or `unicode_language` has resulted in a change. If this process runs then it will always result in a change. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRegion.restart_required | boolean | Whether a reboot is required for the change to take effect. | 


#### Command Example
```!win-region host="123.123.123.123" format="en-US" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinRegion": {
            "changed": false,
            "host": "123.123.123.123",
            "restart_required": false,
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * restart_required: False


### win-regmerge
***
Merges the contents of a registry file into the Windows registry
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_regmerge_module.html


#### Base Command

`win-regmerge`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The full path including file name to the registry file on the remote machine to be merged. | Required | 
| compare_key | The parent key to use when comparing the contents of the registry to the contents of the file.  Needs to be in HKLM or HKCU part of registry. Use a PS-Drive style path for example HKLM:\SOFTWARE not HKEY_LOCAL_MACHINE\SOFTWARE If not supplied, or the registry key is not found, no comparison will be made, and the module will report changed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRegmerge.compare_to_key_found | boolean | whether the parent registry key has been found for comparison | 
| MicrosoftWindows.WinRegmerge.difference_count | number | number of differences between the registry and the file | 
| MicrosoftWindows.WinRegmerge.compared | boolean | whether a comparison has taken place between the registry and the file | 


#### Command Example
```!win-regmerge host="123.123.123.123" path="C:/temp/firefox.reg" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinRegmerge": {
            "changed": true,
            "compared": false,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * compared: False


### win-robocopy
***
Synchronizes the contents of two directories using Robocopy
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_robocopy_module.html


#### Base Command

`win-robocopy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| src | Source file/directory to sync. | Required | 
| dest | Destination file/directory to sync (Will receive contents of src). | Required | 
| recurse | Includes all subdirectories (Toggles the `/e` flag to RoboCopy).<br/>If `flags` is set, this will be ignored. Possible values are: Yes, No. Default is No. | Optional | 
| purge | Deletes any files/directories found in the destination that do not exist in the source.<br/>Toggles the `/purge` flag to RoboCopy.<br/>If `flags` is set, this will be ignored. Possible values are: Yes, No. Default is No. | Optional | 
| flags | Directly supply Robocopy flags.<br/>If set, `purge` and `recurse` will be ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRobocopy.cmd | string | The used command line. | 
| MicrosoftWindows.WinRobocopy.src | string | The Source file/directory of the sync. | 
| MicrosoftWindows.WinRobocopy.dest | string | The Destination file/directory of the sync. | 
| MicrosoftWindows.WinRobocopy.recurse | boolean | Whether or not the recurse flag was toggled. | 
| MicrosoftWindows.WinRobocopy.purge | boolean | Whether or not the purge flag was toggled. | 
| MicrosoftWindows.WinRobocopy.flags | string | Any flags passed in by the user. | 
| MicrosoftWindows.WinRobocopy.rc | number | The return code returned by robocopy. | 
| MicrosoftWindows.WinRobocopy.output | string | The output of running the robocopy command. | 
| MicrosoftWindows.WinRobocopy.msg | string | Output interpreted into a concise message. | 


#### Command Example
```!win-robocopy host="123.123.123.123" "src"="C:/temp" dest="C:/temp2" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinRobocopy": {
            "changed": true,
            "cmd": " C:/temp C:/temp2",
            "dest": "C:/temp2",
            "flags": null,
            "host": "123.123.123.123",
            "msg": "Files copied successfully!",
            "output": [
                "",
                "-------------------------------------------------------------------------------",
                "   ROBOCOPY     ::     Robust File Copy for Windows                              ",
                "-------------------------------------------------------------------------------",
                "",
                "  Started : Tuesday, June 29, 2021 5:22:01 AM",
                "   Source : C:\\temp\\",
                "     Dest : C:\\temp2\\",
                "",
                "    Files : *.*",
                "\t    ",
                "  Options : *.* /DCOPY:DA /COPY:DAT /R:1000000 /W:30 ",
                "",
                "------------------------------------------------------------------------------",
                "",
                "\t                   6\tC:\\temp\\",
                "\t    New File  \t\t    4708\tcert.pem",
                "  0%  ",
                "100%  ",
                "\t    New File  \t\t   45108\tearthrise.jpg",
                "  0%  ",
                "100%  ",
                "\t    New File  \t\t   32256\tExecutable.exe",
                "  0%  ",
                "100%  ",
                "\t    New File  \t\t      11\tfile.txt",
                "  0%  ",
                "100%  ",
                "\t    New File  \t\t     446\tfirefox.reg",
                "  0%  ",
                "100%  ",
                "\t    New File  \t\t       0\tfoo.conf",
                "100%  ",
                "",
                "------------------------------------------------------------------------------",
                "",
                "               Total    Copied   Skipped  Mismatch    FAILED    Extras",
                "    Dirs :         1         0         1         0         0         0",
                "   Files :         6         6         0         0         0         0",
                "   Bytes :    80.5 k    80.5 k         0         0         0         0",
                "   Times :   0:00:00   0:00:00                       0:00:00   0:00:00",
                "",
                "",
                "   Speed :             5894928 Bytes/sec.",
                "   Speed :             337.310 MegaBytes/min.",
                "   Ended : Tuesday, June 29, 2021 5:22:01 AM",
                ""
            ],
            "purge": false,
            "rc": 1,
            "recurse": false,
            "return_code": 1,
            "src": "C:/temp",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * cmd:  C:/temp C:/temp2
>  * dest: C:/temp2
>  * flags: None
>  * msg: Files copied successfully!
>  * purge: False
>  * rc: 1
>  * recurse: False
>  * return_code: 1
>  * src: C:/temp
>  * ## Output
>    * 0: 
>    * 1: -------------------------------------------------------------------------------
>    * 2:    ROBOCOPY     ::     Robust File Copy for Windows                              
>    * 1: -------------------------------------------------------------------------------
>    * 0: 
>    * 5:   Started : Tuesday, June 29, 2021 5:22:01 AM
>    * 6:    Source : C:\temp\
>    * 7:      Dest : C:\temp2\
>    * 0: 
>    * 9:     Files : *.*
>    * 10: 	    
>    * 11:   Options : *.* /DCOPY:DA /COPY:DAT /R:1000000 /W:30 
>    * 0: 
>    * 13: ------------------------------------------------------------------------------
>    * 0: 
>    * 15: 	                   6	C:\temp\
>    * 16: 	    New File  		    4708	cert.pem
>    * 17:   0%  
>    * 18: 100%  
>    * 19: 	    New File  		   45108	earthrise.jpg
>    * 17:   0%  
>    * 18: 100%  
>    * 22: 	    New File  		   32256	Executable.exe
>    * 17:   0%  
>    * 18: 100%  
>    * 25: 	    New File  		      11	file.txt
>    * 17:   0%  
>    * 18: 100%  
>    * 28: 	    New File  		     446	firefox.reg
>    * 17:   0%  
>    * 18: 100%  
>    * 31: 	    New File  		       0	foo.conf
>    * 18: 100%  
>    * 0: 
>    * 13: ------------------------------------------------------------------------------
>    * 0: 
>    * 36:                Total    Copied   Skipped  Mismatch    FAILED    Extras
>    * 37:     Dirs :         1         0         1         0         0         0
>    * 38:    Files :         6         6         0         0         0         0
>    * 39:    Bytes :    80.5 k    80.5 k         0         0         0         0
>    * 40:    Times :   0:00:00   0:00:00                       0:00:00   0:00:00
>    * 0: 
>    * 0: 
>    * 43:    Speed :             5894928 Bytes/sec.
>    * 44:    Speed :             337.310 MegaBytes/min.
>    * 45:    Ended : Tuesday, June 29, 2021 5:22:01 AM
>    * 0: 


### win-route
***
Add or remove a static route
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_route_module.html


#### Base Command

`win-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| destination | Destination IP address in CIDR format (ip address/prefix length). | Required | 
| gateway | The gateway used by the static route.<br/>If `gateway` is not provided it will be set to `0.0.0.0`. | Optional | 
| metric | Metric used by the static route. Default is 1. | Optional | 
| state | If `absent`, it removes a network static route.<br/>If `present`, it adds a network static route. Possible values are: absent, present. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinRoute.output | string | A message describing the task result. | 


#### Command Example
```!win-route host="123.123.123.123" destination="192.168.2.10/32" gateway="192.168.1.1" metric="1" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinRoute": {
            "changed": false,
            "host": "123.123.123.123",
            "output": "Static route already exists",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * output: Static route already exists


### win-say
***
Text to speech module for Windows to speak messages and optionally play sounds
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_say_module.html


#### Base Command

`win-say`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| msg | The text to be spoken.<br/>Use either `msg` or `msg_file`.<br/>Optional so that you can use this module just to play sounds. | Optional | 
| msg_file | Full path to a windows format text file containing the text to be spoken.<br/>Use either `msg` or `msg_file`.<br/>Optional so that you can use this module just to play sounds. | Optional | 
| voice | Which voice to use. See notes for how to discover installed voices.<br/>If the requested voice is not available the default voice will be used. Example voice names from Windows 10 are `Microsoft Zira Desktop` and `Microsoft Hazel Desktop`. | Optional | 
| speech_speed | How fast or slow to speak the text.<br/>Must be an integer value in the range -10 to 10.<br/>-10 is slowest, 10 is fastest. Default is 0. | Optional | 
| start_sound_path | Full path to a `.wav` file containing a sound to play before the text is spoken.<br/>Useful on conference calls to alert other speakers that ansible has something to say. | Optional | 
| end_sound_path | Full path to a `.wav` file containing a sound to play after the text has been spoken.<br/>Useful on conference calls to alert other speakers that ansible has finished speaking. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinSay.message_text | string | The text that the module attempted to speak. | 
| MicrosoftWindows.WinSay.voice | string | The voice used to speak the text. | 
| MicrosoftWindows.WinSay.voice_info | string | The voice used to speak the text. | 


#### Command Example
```!win-say host="123.123.123.123" msg="Warning, deployment commencing in 5 minutes, please log out." ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinSay": {
            "changed": false,
            "host": "123.123.123.123",
            "message_text": "Warning, deployment commencing in 5 minutes, please log out.",
            "status": "SUCCESS",
            "voice": "Microsoft Zira Desktop"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * message_text: Warning, deployment commencing in 5 minutes, please log out.
>  * voice: Microsoft Zira Desktop


### win-scheduled-task
***
Manage scheduled tasks
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_scheduled_task_module.html


#### Base Command

`win-scheduled-task`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the scheduled task without the path. | Required | 
| path | Task folder in which this task will be stored.<br/>Will create the folder when `state=present` and the folder does not already exist.<br/>Will remove the folder when `state=absent` and there are no tasks left in the folder. Default is \. | Optional | 
| state | When `state=present` will ensure the task exists.<br/>When `state=absent` will ensure the task does not exist. Possible values are: absent, present. Default is present. | Optional | 
| actions | A list of action to configure for the task.<br/>See suboptions for details on how to construct each list entry.<br/>When creating a task there MUST be at least one action but when deleting a task this can be a null or an empty list.<br/>The ordering of this list is important, the module will ensure the order is kept when modifying the task.<br/>This module only supports the `ExecAction` type but can still delete the older legacy types. | Optional | 
| triggers | A list of triggers to configure for the task.<br/>See suboptions for details on how to construct each list entry.<br/>The ordering of this list is important, the module will ensure the order is kept when modifying the task.<br/>There are multiple types of triggers, see `https://msdn.microsoft.com/en-us/library/windows/desktop/aa383868.aspx` for a list of trigger types and their options.<br/>The suboption options listed below are not required for all trigger types, read the description for more details. | Optional | 
| display_name | The name of the user/group that is displayed in the Task Scheduler UI. | Optional | 
| group | The group that will run the task.<br/>`group` and `username` are exclusive to each other and cannot be set at the same time.<br/>`logon_type` can either be not set or equal `group`. | Optional | 
| logon_type | The logon method that the task will run with.<br/>`password` means the password will be stored and the task has access to network resources.<br/>`s4u` means the existing token will be used to run the task and no password will be stored with the task. Means no network or encrypted files access.<br/>`interactive_token` means the user must already be logged on interactively and will run in an existing interactive session.<br/>`group` means that the task will run as a group.<br/>`service_account` means that a service account like System, Local Service or Network Service will run the task. Possible values are: none, password, s4u, interactive_token, group, service_account, token_or_password. | Optional | 
| run_level | The level of user rights used to run the task.<br/>If not specified the task will be created with limited rights. Possible values are: limited, highest. | Optional | 
| username | The user to run the scheduled task as.<br/>Will default to the current user under an interactive token if not specified during creation. | Optional | 
| password | The password for the user account to run the scheduled task as.<br/>This is required when running a task without the user being logged in, excluding the builtin service accounts and Group Managed Service Accounts (gMSA).<br/>If set, will always result in a change unless `update_password` is set to `no` and no other changes are required for the service. | Optional | 
| update_password | Whether to update the password even when not other changes have occurred.<br/>When `yes` will always result in a change when executing the module. Possible values are: Yes, No. Default is Yes. | Optional | 
| author | The author of the task. | Optional | 
| date | The date when the task was registered. | Optional | 
| description | The description of the task. | Optional | 
| source | The source of the task. | Optional | 
| version | The version number of the task. | Optional | 
| allow_demand_start | Whether the task can be started by using either the Run command or the Context menu. | Optional | 
| allow_hard_terminate | Whether the task can be terminated by using TerminateProcess. | Optional | 
| compatibility | The integer value with indicates which version of Task Scheduler a task is compatible with.<br/>`0` means the task is compatible with the AT command.<br/>`1` means the task is compatible with Task Scheduler 1.0.<br/>`2` means the task is compatible with Task Scheduler 2.0. Possible values are: 0, 1, 2. | Optional | 
| delete_expired_task_after | The amount of time that the Task Scheduler will wait before deleting the task after it expires.<br/>A task expires after the end_boundary has been exceeded for all triggers associated with the task.<br/>This is in the ISO 8601 Duration format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`. | Optional | 
| disallow_start_if_on_batteries | Whether the task will not be started if the computer is running on battery power. | Optional | 
| enabled | Whether the task is enabled, the task can only run when `yes`. | Optional | 
| execution_time_limit | The amount of time allowed to complete the task.<br/>When not set, the time limit is infinite.<br/>This is in the ISO 8601 Duration format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`. | Optional | 
| hidden | Whether the task will be hidden in the UI. | Optional | 
| multiple_instances | An integer that indicates the behaviour when starting a task that is already running.<br/>`0` will start a new instance in parallel with existing instances of that task.<br/>`1` will wait until other instances of that task to finish running before starting itself.<br/>`2` will not start a new instance if another is running.<br/>`3` will stop other instances of the task and start the new one. Possible values are: 0, 1, 2, 3. | Optional | 
| priority | The priority level (0-10) of the task.<br/>When creating a new task the default is `7`.<br/>See `https://msdn.microsoft.com/en-us/library/windows/desktop/aa383512.aspx` for details on the priority levels. | Optional | 
| restart_count | The number of times that the Task Scheduler will attempt to restart the task. | Optional | 
| restart_interval | How long the Task Scheduler will attempt to restart the task.<br/>If this is set then `restart_count` must also be set.<br/>The maximum allowed time is 31 days.<br/>The minimum allowed time is 1 minute.<br/>This is in the ISO 8601 Duration format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`. | Optional | 
| run_only_if_idle | Whether the task will run the task only if the computer is in an idle state. | Optional | 
| run_only_if_network_available | Whether the task will run only when a network is available. | Optional | 
| start_when_available | Whether the task can start at any time after its scheduled time has passed. | Optional | 
| stop_if_going_on_batteries | Whether the task will be stopped if the computer begins to run on battery power. | Optional | 
| wake_to_run | Whether the task will wake the computer when it is time to run the task. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-scheduled-task host="123.123.123.123" name="TaskName" description="open command prompt" actions="[{'path': 'cmd.exe', 'arguments': '/c hostname'}, {'path': 'cmd.exe', 'arguments': '/c whoami'}]" triggers="[{'type': 'daily', 'start_boundary': '2017-10-09T09:00:00'}]" username="SYSTEM" state="present" enabled="True" ```

#### Human Readable Output

>null

### win-scheduled-task-stat
***
Get information about Windows Scheduled Tasks
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_scheduled_task_stat_module.html


#### Base Command

`win-scheduled-task-stat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The folder path where the task lives. Default is \. | Optional | 
| name | The name of the scheduled task to get information for.<br/>If `name` is set and exists, will return information on the task itself. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinScheduledTaskStat.actions | unknown | A list of actions. | 
| MicrosoftWindows.WinScheduledTaskStat.folder_exists | boolean | Whether the folder set at path exists. | 
| MicrosoftWindows.WinScheduledTaskStat.folder_task_count | number | The number of tasks that exist in the folder. | 
| MicrosoftWindows.WinScheduledTaskStat.folder_task_names | unknown | A list of tasks that exist in the folder. | 
| MicrosoftWindows.WinScheduledTaskStat.principal | unknown | Details on the principal configured to run the task. | 
| MicrosoftWindows.WinScheduledTaskStat.registration_info | unknown | Details on the task registration info. | 
| MicrosoftWindows.WinScheduledTaskStat.settings | unknown | Details on the task settings. | 
| MicrosoftWindows.WinScheduledTaskStat.state | unknown | Details on the state of the task | 
| MicrosoftWindows.WinScheduledTaskStat.task_exists | boolean | Whether the task at the folder exists. | 
| MicrosoftWindows.WinScheduledTaskStat.triggers | unknown | A list of triggers. | 


#### Command Example
```!win-scheduled-task-stat host="123.123.123.123" path="\\folder name" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinScheduledTaskStat": {
            "changed": false,
            "folder_exists": false,
            "host": "123.123.123.123",
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * folder_exists: False


### win-security-policy
***
Change local security policy settings
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_security_policy_module.html


#### Base Command

`win-security-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| section | The ini section the key exists in.<br/>If the section does not exist then the module will return an error.<br/>Example sections to use are 'Account Policies', 'Local Policies', 'Event Log', 'Restricted Groups', 'System Services', 'Registry' and 'File System'<br/>If wanting to edit the `Privilege Rights` section, use the `win_user_right` module instead. | Required | 
| key | The ini key of the section or policy name to modify.<br/>The module will return an error if this key is invalid. | Required | 
| value | The value for the ini key or policy name.<br/>If the key takes in a boolean value then 0 = False and 1 = True. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinSecurityPolicy.rc | number | The return code after a failure when running SecEdit.exe. | 
| MicrosoftWindows.WinSecurityPolicy.stdout | string | The output of the STDOUT buffer after a failure when running SecEdit.exe. | 
| MicrosoftWindows.WinSecurityPolicy.stderr | string | The output of the STDERR buffer after a failure when running SecEdit.exe. | 
| MicrosoftWindows.WinSecurityPolicy.import_log | string | The log of the SecEdit.exe /configure job that configured the local policies. This is used for debugging purposes on failures. | 
| MicrosoftWindows.WinSecurityPolicy.key | string | The key in the section passed to the module to modify. | 
| MicrosoftWindows.WinSecurityPolicy.section | string | The section passed to the module to modify. | 
| MicrosoftWindows.WinSecurityPolicy.value | string | The value passed to the module to modify to. | 


#### Command Example
```!win-security-policy host="123.123.123.123" section="System Access" key="NewGuestName" value="Guest Account" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinSecurityPolicy": {
            "changed": false,
            "host": "123.123.123.123",
            "key": "NewGuestName",
            "section": "System Access",
            "status": "SUCCESS",
            "value": "Guest Account"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * key: NewGuestName
>  * section: System Access
>  * value: Guest Account


### win-service
***
Manage and query Windows services
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_service_module.html


#### Base Command

`win-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| dependencies | A list of service dependencies to set for this particular service.<br/>This should be a list of service names and not the display name of the service.<br/>This works by `dependency_action` to either add/remove or set the services in this list. | Optional | 
| dependency_action | Used in conjunction with `dependency` to either add the dependencies to the existing service dependencies.<br/>Remove the dependencies to the existing dependencies.<br/>Set the dependencies to only the values in the list replacing the existing dependencies. Possible values are: add, remove, set. Default is set. | Optional | 
| desktop_interact | Whether to allow the service user to interact with the desktop.<br/>This should only be set to `yes` when using the `LocalSystem` username. Possible values are: Yes, No. Default is No. | Optional | 
| description | The description to set for the service. | Optional | 
| display_name | The display name to set for the service. | Optional | 
| force_dependent_services | If `yes`, stopping or restarting a service with dependent services will force the dependent services to stop or restart also.<br/>If `no`, stopping or restarting a service with dependent services may fail. Possible values are: Yes, No. Default is No. | Optional | 
| name | Name of the service.<br/>If only the name parameter is specified, the module will report on whether the service exists or not without making any changes. | Required | 
| path | The path to the executable to set for the service. | Optional | 
| password | The password to set the service to start as.<br/>This and the `username` argument must be supplied together.<br/>If specifying `LocalSystem`, `NetworkService` or `LocalService` this field must be an empty string and not null. | Optional | 
| start_mode | Set the startup type for the service.<br/>A newly created service will default to `auto`.<br/>`delayed` added in Ansible 2.3. Possible values are: auto, delayed, disabled, manual. | Optional | 
| state | The desired state of the service.<br/>`started`/`stopped`/`absent`/`paused` are idempotent actions that will not run commands unless necessary.<br/>`restarted` will always bounce the service.<br/>`absent` was added in Ansible 2.3<br/>`paused` was added in Ansible 2.4<br/>Only services that support the paused state can be paused, you can check the return value `can_pause_and_continue`.<br/>You can only pause a service that is already started.<br/>A newly created service will default to `stopped`. Possible values are: absent, paused, started, stopped, restarted. | Optional | 
| username | The username to set the service to start as.<br/>This and the `password` argument must be supplied together when using a local or domain account.<br/>Set to `LocalSystem` to use the SYSTEM account.<br/>A newly created service will default to `LocalSystem`.<br/>If using a custom user account, it must have the `SeServiceLogonRight` granted to be able to start up. You can use the `win_user_right` module to grant this user right for you. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinService.exists | boolean | Whether the service exists or not. | 
| MicrosoftWindows.WinService.name | string | The service name or id of the service. | 
| MicrosoftWindows.WinService.display_name | string | The display name of the installed service. | 
| MicrosoftWindows.WinService.state | string | The current running status of the service. | 
| MicrosoftWindows.WinService.start_mode | string | The startup type of the service. | 
| MicrosoftWindows.WinService.path | string | The path to the service executable. | 
| MicrosoftWindows.WinService.can_pause_and_continue | boolean | Whether the service can be paused and unpaused. | 
| MicrosoftWindows.WinService.description | string | The description of the service. | 
| MicrosoftWindows.WinService.username | string | The username that runs the service. | 
| MicrosoftWindows.WinService.desktop_interact | boolean | Whether the current user is allowed to interact with the desktop. | 
| MicrosoftWindows.WinService.dependencies | unknown | A list of services that is depended by this service. | 
| MicrosoftWindows.WinService.depended_by | unknown | A list of services that depend on this service. | 


#### Command Example
```!win-service host="123.123.123.123" name="spooler" state="restarted" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinService": {
            "can_pause_and_continue": false,
            "changed": true,
            "depended_by": [],
            "dependencies": [
                "RPCSS",
                "http"
            ],
            "description": "This service spools print jobs and handles interaction with the printer.  If you turn off this service, you won\u2019t be able to print or see your printers.",
            "desktop_interact": false,
            "display_name": "Print Spooler",
            "exists": true,
            "host": "123.123.123.123",
            "name": "Spooler",
            "path": "C:\\Windows\\System32\\spoolsv.exe",
            "start_mode": "auto",
            "state": "running",
            "status": "CHANGED",
            "username": "LocalSystem"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * can_pause_and_continue: False
>  * changed: True
>  * description: This service spools print jobs and handles interaction with the printer.  If you turn off this service, you won’t be able to print or see your printers.
>  * desktop_interact: False
>  * display_name: Print Spooler
>  * exists: True
>  * name: Spooler
>  * path: C:\Windows\System32\spoolsv.exe
>  * start_mode: auto
>  * state: running
>  * username: LocalSystem
>  * ## Depended_By
>  * ## Dependencies
>    * 0: RPCSS
>    * 1: http


### win-share
***
Manage Windows shares
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_share_module.html


#### Base Command

`win-share`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Share name. | Required | 
| path | Share directory. | Required | 
| state | Specify whether to add `present` or remove `absent` the specified share. Possible values are: absent, present. Default is present. | Optional | 
| description | Share description. | Optional | 
| list | Specify whether to allow or deny file listing, in case user has no permission on share. Also known as Access-Based Enumeration. Possible values are: Yes, No. Default is No. | Optional | 
| read | Specify user list that should get read access on share, separated by comma. | Optional | 
| change | Specify user list that should get read and write access on share, separated by comma. | Optional | 
| full | Specify user list that should get full access on share, separated by comma. | Optional | 
| deny | Specify user list that should get no access, regardless of implied access on share, separated by comma. | Optional | 
| caching_mode | Set the CachingMode for this share. Possible values are: BranchCache, Documents, Manual, None, Programs, Unknown. Default is Manual. | Optional | 
| encrypt | Sets whether to encrypt the traffic to the share or not. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinShare.actions | unknown | A list of action cmdlets that were run by the module. | 


#### Command Example
```!win-share host="123.123.123.123" name="internal" description="top secret share" path="C:/temp" list="False" full="Administrators,fed-phil" read="fed-phil" deny="Guest" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinShare": {
            "actions": [
                "New-SmbShare -Name internal -Path C:\\temp",
                "Set-SmbShare -Force -Name internal -Description top secret share",
                "Set-SmbShare -Force -Name internal -FolderEnumerationMode AccessBased",
                "Revoke-SmbShareAccess -Force -Name internal -AccountName Everyone",
                "Grant-SmbShareAccess -Force -Name internal -AccountName BUILTIN\\Administrators -AccessRight Full",
                "Grant-SmbShareAccess -Force -Name internal -AccountName WIN-U425UI0HPP7\\fed-phil -AccessRight Full",
                "Block-SmbShareAccess -Force -Name internal -AccountName WIN-U425UI0HPP7\\Guest"
            ],
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Actions
>    * 0: New-SmbShare -Name internal -Path C:\temp
>    * 1: Set-SmbShare -Force -Name internal -Description top secret share
>    * 2: Set-SmbShare -Force -Name internal -FolderEnumerationMode AccessBased
>    * 3: Revoke-SmbShareAccess -Force -Name internal -AccountName Everyone
>    * 4: Grant-SmbShareAccess -Force -Name internal -AccountName BUILTIN\Administrators -AccessRight Full
>    * 5: Grant-SmbShareAccess -Force -Name internal -AccountName WIN-U425UI0HPP7\fed-phil -AccessRight Full
>    * 6: Block-SmbShareAccess -Force -Name internal -AccountName WIN-U425UI0HPP7\Guest


### win-shortcut
***
Manage shortcuts on Windows
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_shortcut_module.html


#### Base Command

`win-shortcut`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| src | Executable or URL the shortcut points to.<br/>The executable needs to be in your PATH, or has to be an absolute path to the executable. | Optional | 
| description | Description for the shortcut.<br/>This is usually shown when hoovering the icon. | Optional | 
| dest | Destination file for the shortcuting file.<br/>File name should have a `.lnk` or `.url` extension. | Required | 
| arguments | Additional arguments for the executable defined in `src`.<br/>Was originally just `args` but renamed in Ansible 2.8. | Optional | 
| directory | Working directory for executable defined in `src`. | Optional | 
| icon | Icon used for the shortcut.<br/>File name should have a `.ico` extension.<br/>The file name is followed by a comma and the number in the library file (.dll) or use 0 for an image file. | Optional | 
| hotkey | Key combination for the shortcut.<br/>This is a combination of one or more modifiers and a key.<br/>Possible modifiers are Alt, Ctrl, Shift, Ext.<br/>Possible keys are [A-Z] and [0-9]. | Optional | 
| windowstyle | Influences how the application is displayed when it is launched. Possible values are: maximized, minimized, normal. | Optional | 
| state | When `absent`, removes the shortcut if it exists.<br/>When `present`, creates or updates the shortcut. Possible values are: absent, present. Default is present. | Optional | 
| run_as_admin | When `src` is an executable, this can control whether the shortcut will be opened as an administrator or not. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-shortcut host="123.123.123.123" "src"="C:\\Program Files\\Mozilla Firefox\\Firefox.exe" dest="C:\\Users\\Public\\Desktop\\Mozilla Firefox.lnk" icon="C:\\Program Files\\Mozilla Firefox\\Firefox.exe,0" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinShortcut": {
            "args": "",
            "changed": false,
            "description": "",
            "dest": "C:\\Users\\Public\\Desktop\\Mozilla Firefox.lnk",
            "directory": "",
            "host": "123.123.123.123",
            "hotkey": "",
            "icon": "C:\\Program Files\\Mozilla Firefox\\Firefox.exe,0",
            "src": "C:\\Program Files\\Mozilla Firefox\\Firefox.exe",
            "state": "present",
            "status": "SUCCESS",
            "windowstyle": "normal"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * args: 
>  * changed: False
>  * description: 
>  * dest: C:\Users\Public\Desktop\Mozilla Firefox.lnk
>  * directory: 
>  * hotkey: 
>  * icon: C:\Program Files\Mozilla Firefox\Firefox.exe,0
>  * src: C:\Program Files\Mozilla Firefox\Firefox.exe
>  * state: present
>  * windowstyle: normal


### win-snmp
***
Configures the Windows SNMP service
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_snmp_module.html


#### Base Command

`win-snmp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| permitted_managers | The list of permitted SNMP managers. | Optional | 
| community_strings | The list of read-only SNMP community strings. | Optional | 
| action | `add` will add new SNMP community strings and/or SNMP managers<br/>`set` will replace SNMP community strings and/or SNMP managers. An empty list for either `community_strings` or `permitted_managers` will result in the respective lists being removed entirely.<br/>`remove` will remove SNMP community strings and/or SNMP managers. Possible values are: add, set, remove. Default is set. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinSnmp.community_strings | unknown | The list of community strings for this machine. | 
| MicrosoftWindows.WinSnmp.permitted_managers | unknown | The list of permitted managers for this machine. | 




### win-stat
***
Get information about Windows files
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_stat_module.html


#### Base Command

`win-stat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| path | The full path of the file/object to get the facts of; both forward and back slashes are accepted. | Required | 
| get_md5 | Whether to return the checksum sum of the file. Between Ansible 1.9 and Ansible 2.2 this is no longer an MD5, but a SHA1 instead. As of Ansible 2.3 this is back to an MD5. Will return None if host is unable to use specified algorithm.<br/>The default of this option changed from `yes` to `no` in Ansible 2.5 and will be removed altogether in Ansible 2.9.<br/>Use `get_checksum=yes` with `checksum_algorithm=md5` to return an md5 hash under the `checksum` return value. Possible values are: Yes, No. Default is No. | Optional | 
| get_checksum | Whether to return a checksum of the file (default sha1). Possible values are: Yes, No. Default is Yes. | Optional | 
| checksum_algorithm | Algorithm to determine checksum of file.<br/>Will throw an error if the host is unable to use specified algorithm. Possible values are: md5, sha1, sha256, sha384, sha512. Default is sha1. | Optional | 
| follow | Whether to follow symlinks or junction points.<br/>In the case of `path` pointing to another link, then that will be followed until no more links are found. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinStat.changed | boolean | Whether anything was changed | 
| MicrosoftWindows.WinStat.stat | unknown | dictionary containing all the stat data | 


#### Command Example
```!win-stat host="123.123.123.123" path="C:/logs.zip" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinStat": {
            "changed": false,
            "host": "123.123.123.123",
            "stat": {
                "attributes": "Archive",
                "checksum": "386bcb29bec1df41bde1cb0324b609338337b893",
                "creationtime": 1624942389.4979205,
                "exists": true,
                "extension": ".zip",
                "filename": "logs.zip",
                "hlnk_targets": [],
                "isarchive": true,
                "isdir": false,
                "ishidden": false,
                "isjunction": false,
                "islnk": false,
                "isreadonly": false,
                "isreg": true,
                "isshared": false,
                "lastaccesstime": 1624942389.4979205,
                "lastwritetime": 1624942389.5135438,
                "nlink": 1,
                "owner": "BUILTIN\\Administrators",
                "path": "C:\\logs.zip",
                "size": 354
            },
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * ## Stat
>    * attributes: Archive
>    * checksum: 386bcb29bec1df41bde1cb0324b609338337b893
>    * creationtime: 1624942389.4979205
>    * exists: True
>    * extension: .zip
>    * filename: logs.zip
>    * isarchive: True
>    * isdir: False
>    * ishidden: False
>    * isjunction: False
>    * islnk: False
>    * isreadonly: False
>    * isreg: True
>    * isshared: False
>    * lastaccesstime: 1624942389.4979205
>    * lastwritetime: 1624942389.5135438
>    * nlink: 1
>    * owner: BUILTIN\Administrators
>    * path: C:\logs.zip
>    * size: 354
>    * ### Hlnk_Targets



### win-tempfile
***
Creates temporary files and directories
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_tempfile_module.html


#### Base Command

`win-tempfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| state | Whether to create file or directory. Possible values are: directory, file. Default is file. | Optional | 
| path | Location where temporary file or directory should be created.<br/>If path is not specified default system temporary directory (%TEMP%) will be used. Default is %TEMP%. | Optional | 
| prefix | Prefix of file/directory name created by module. Default is ansible.. | Optional | 
| suffix | Suffix of file/directory name created by module. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinTempfile.path | string | The absolute path to the created file or directory. | 


#### Command Example
```!win-tempfile host="123.123.123.123" state="directory" suffix="build" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinTempfile": {
            "changed": true,
            "host": "123.123.123.123",
            "path": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\ansible.orvo45xg.ldhbuild",
            "state": "directory",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * path: C:\Users\Administrator\AppData\Local\Temp\ansible.orvo45xg.ldhbuild
>  * state: directory


### win-template
***
Template a file out to a remote server
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_template_module.html


#### Base Command

`win-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| backup | Determine whether a backup should be created.<br/>When set to `yes`, create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| newline_sequence | Specify the newline sequence to use for templating files. Possible values are: \n, \r, \r\n. Default is \r\n. | Optional | 
| force | Determine when the file is being transferred if the destination already exists.<br/>When set to `yes`, replace the remote file when contents are different than the source.<br/>When set to `no`, the file will only be transferred if the destination does not exist. Possible values are: Yes, No. Default is Yes. | Optional | 
| src | Path of a Jinja2 formatted template on the Ansible controller.<br/>This can be a relative or an absolute path.<br/>The file must be encoded with `utf-8` but `output_encoding` can be used to control the encoding of the output template. | Required | 
| dest | Location to render the template to on the remote machine. | Required | 
| block_start_string | The string marking the beginning of a block. Default is {%. | Optional | 
| block_end_string | The string marking the end of a block. Default is %}. | Optional | 
| variable_start_string | The string marking the beginning of a print statement. Default is {{. | Optional | 
| variable_end_string | The string marking the end of a print statement. Default is }}. | Optional | 
| trim_blocks | Determine when newlines should be removed from blocks.<br/>When set to `yes` the first newline after a block is removed (block, not variable tag!). Possible values are: Yes, No. Default is Yes. | Optional | 
| lstrip_blocks | Determine when leading spaces and tabs should be stripped.<br/>When set to `yes` leading spaces and tabs are stripped from the start of a line to a block.<br/>This functionality requires Jinja 2.7 or newer. Possible values are: Yes, No. Default is No. | Optional | 
| output_encoding | Overrides the encoding used to write the template file defined by `dest`.<br/>It defaults to `utf-8`, but any encoding supported by python can be used.<br/>The source template file must always be encoded using `utf-8`, for homogeneity. Default is utf-8. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinTemplate.backup_file | string | Name of the backup file that was created. | 


#### Command Example
```!win-template host="123.123.123.123" "src"="/mytemplates/file.conf.j2" dest="C:\\Temp\\file.conf" ```

#### Human Readable Output

>null

### win-timezone
***
Sets Windows machine timezone
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_timezone_module.html


#### Base Command

`win-timezone`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| timezone | Timezone to set to.<br/>Example: Central Standard Time. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinTimezone.previous_timezone | string | The previous timezone if it was changed, otherwise the existing timezone. | 
| MicrosoftWindows.WinTimezone.timezone | string | The current timezone \(possibly changed\). | 


#### Command Example
```!win-timezone host="123.123.123.123" timezone="Romance Standard Time" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinTimezone": {
            "changed": false,
            "host": "123.123.123.123",
            "previous_timezone": "Romance Standard Time",
            "status": "SUCCESS",
            "timezone": "Romance Standard Time"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * previous_timezone: Romance Standard Time
>  * timezone: Romance Standard Time


### win-toast
***
Sends Toast windows notification to logged in users on Windows 10 or later hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_toast_module.html


#### Base Command

`win-toast`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| expire | How long in seconds before the notification expires. Default is 45. | Optional | 
| group | Which notification group to add the notification to. Default is Powershell. | Optional | 
| msg | The message to appear inside the notification.<br/>May include \n to format the message to appear within the Action Center. Default is Hello, World!. | Optional | 
| popup | If `no`, the notification will not pop up and will only appear in the Action Center. Possible values are: Yes, No. Default is Yes. | Optional | 
| tag | The tag to add to the notification. Default is Ansible. | Optional | 
| title | The notification title, which appears in the pop up.. Default is Notification HH:mm. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinToast.expire_at_utc | string | Calculated utc date time when the notification expires. | 
| MicrosoftWindows.WinToast.no_toast_sent_reason | string | Text containing the reason why a notification was not sent. | 
| MicrosoftWindows.WinToast.sent_localtime | string | local date time when the notification was sent. | 
| MicrosoftWindows.WinToast.time_taken | unknown | How long the module took to run on the remote windows host in seconds. | 
| MicrosoftWindows.WinToast.toast_sent | boolean | Whether the module was able to send a toast notification or not. | 


#### Command Example
```!win-toast host="123.123.123.123" expire="60" title="System Upgrade Notification" msg="Automated upgrade about to start.  Please save your work and log off before 6pm" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinToast": {
            "changed": false,
            "expire_at": "6/29/2021 5:21:50 AM",
            "expire_at_utc": "Tuesday, June 29, 2021 3:21:50 AM",
            "host": "123.123.123.123",
            "sent_localtime": "Tuesday, June 29, 2021 5:21:50 AM",
            "status": "SUCCESS",
            "time_taken": 60.2358145,
            "toast_sent": true
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * expire_at: 6/29/2021 5:21:50 AM
>  * expire_at_utc: Tuesday, June 29, 2021 3:21:50 AM
>  * sent_localtime: Tuesday, June 29, 2021 5:21:50 AM
>  * time_taken: 60.2358145
>  * toast_sent: True


### win-unzip
***
Unzips compressed files and archives on the Windows node
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_unzip_module.html


#### Base Command

`win-unzip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| src | File to be unzipped (provide absolute path). | Required | 
| dest | Destination of zip file (provide absolute path of directory). If it does not exist, the directory will be created. | Required | 
| delete_archive | Remove the zip file, after unzipping. Possible values are: Yes, No. Default is No. | Optional | 
| recurse | Recursively expand zipped files within the src file.<br/>Setting to a value of `yes` requires the PSCX module to be installed. Possible values are: Yes, No. Default is No. | Optional | 
| creates | If this file or directory exists the specified src will not be extracted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinUnzip.dest | string | The provided destination path | 
| MicrosoftWindows.WinUnzip.removed | boolean | Whether the module did remove any files during task run | 
| MicrosoftWindows.WinUnzip.src | string | The provided source path | 


#### Command Example
```!win-unzip host="123.123.123.123" "src"="C:/logs.zip" dest="C:/temp/OldLogs" creates="C:/temp/OldLogs" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinUnzip": {
            "changed": true,
            "dest": "C:/temp/OldLogs",
            "host": "123.123.123.123",
            "removed": false,
            "src": "C:/logs.zip",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * dest: C:/temp/OldLogs
>  * removed: False
>  * src: C:/logs.zip


### win-updates
***
Download and install Windows updates
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_updates_module.html


#### Base Command

`win-updates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| blacklist | A list of update titles or KB numbers that can be used to specify which updates are to be excluded from installation.<br/>If an available update does match one of the entries, then it is skipped and not installed.<br/>Each entry can either be the KB article or Update title as a regex according to the PowerShell regex rules. | Optional | 
| category_names | A scalar or list of categories to install updates from. To get the list of categories, run the module with `state=searched`. The category must be the full category string, but is case insensitive.<br/>Some possible categories are Application, Connectors, Critical Updates, Definition Updates, Developer Kits, Feature Packs, Guidance, Security Updates, Service Packs, Tools, Update Rollups and Updates. Default is ['CriticalUpdates', 'SecurityUpdates', 'UpdateRollups']. | Optional | 
| reboot | Ansible will automatically reboot the remote host if it is required and continue to install updates after the reboot.<br/>This can be used instead of using a `win_reboot` task after this one and ensures all updates for that category is installed in one go.<br/>Async does not work when `reboot=yes`. Possible values are: Yes, No. Default is No. | Optional | 
| reboot_timeout | The time in seconds to wait until the host is back online from a reboot.<br/>This is only used if `reboot=yes` and a reboot is required. Default is 1200. | Optional | 
| server_selection | Defines the Windows Update source catalog.<br/>`default` Use the default search source. For many systems default is set to the Microsoft Windows Update catalog. Systems participating in Windows Server Update Services (WSUS), Systems Center Configuration Manager (SCCM), or similar corporate update server environments may default to those managed update sources instead of the Windows Update catalog.<br/>`managed_server` Use a managed server catalog. For environments utilizing Windows Server Update Services (WSUS), Systems Center Configuration Manager (SCCM), or similar corporate update servers, this option selects the defined corporate update source.<br/>`windows_update` Use the Microsoft Windows Update catalog. Possible values are: default, managed_server, windows_update. Default is default. | Optional | 
| state | Controls whether found updates are downloaded or installed or listed<br/>This module also supports Ansible check mode, which has the same effect as setting state=searched. Possible values are: installed, searched, downloaded. Default is installed. | Optional | 
| log_path | If set, `win_updates` will append update progress to the specified file. The directory must already exist. | Optional | 
| allow list | A list of update titles or KB numbers that can be used to specify which updates are to be searched or installed.<br/>If an available update does not match one of the entries, then it is skipped and not installed.<br/>Each entry can either be the KB article or Update title as a regex according to the PowerShell regex rules.<br/>The allow list is only validated on updates that were found based on `category_names`. It will not force the module to install an update if it was not in the category specified. | Optional | 
| use_scheduled_task | Will not auto elevate the remote process with `become` and use a scheduled task instead.<br/>Set this to `yes` when using this module with async on Server 2008, 2008 R2, or Windows 7, or on Server 2008 that is not authenticated with basic or credssp.<br/>Can also be set to `yes` on newer hosts where become does not work due to further privilege restrictions from the OS defaults. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinUpdates.reboot_required | boolean | True when the target server requires a reboot to complete updates \(no further updates can be installed until after a reboot\). | 
| MicrosoftWindows.WinUpdates.updates | unknown | List of updates that were found/installed. | 
| MicrosoftWindows.WinUpdates.filtered_updates | unknown | List of updates that were found but were filtered based on \`blacklist\`, \`whitelist\` or \`category_names\`. The return value is in the same form as \`updates\`, along with \`filtered_reason\`. | 
| MicrosoftWindows.WinUpdates.found_update_count | number | The number of updates found needing to be applied. | 
| MicrosoftWindows.WinUpdates.installed_update_count | number | The number of updates successfully installed or downloaded. | 
| MicrosoftWindows.WinUpdates.failed_update_count | number | The number of updates that failed to install. | 


#### Command Example
```!win-updates host="123.123.123.123" category_names="['SecurityUpdates', 'CriticalUpdates', 'UpdateRollups']" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinUpdates": {
            "changed": false,
            "filtered_updates": {
                "95335a9a-923a-47b2-abb1-7584d685de6a": {
                    "categories": [
                        "Security Updates",
                        "Windows Server 2016"
                    ],
                    "filtered_reason": "category_names",
                    "id": "95335a9a-923a-47b2-abb1-7584d685de6a",
                    "installed": false,
                    "kb": [
                        "5001402"
                    ],
                    "title": "2021-04 Servicing Stack Update for Windows Server 2016 for x64-based Systems (KB5001402)"
                },
                "a711f6a5-5bf3-4392-95d0-686f748789dd": {
                    "categories": [
                        "Updates",
                        "Windows Server 2016"
                    ],
                    "filtered_reason": "category_names",
                    "id": "a711f6a5-5bf3-4392-95d0-686f748789dd",
                    "installed": false,
                    "kb": [
                        "4103720"
                    ],
                    "title": "2018-05 Cumulative Update for Windows Server 2016 for x64-based Systems (KB4103720)"
                },
                "e0fa0562-d5bf-451f-a63c-1ea947b6eb27": {
                    "categories": [
                        "Update Rollups",
                        "Windows Server 2016",
                        "Windows Server 2019"
                    ],
                    "filtered_reason": "category_names",
                    "id": "e0fa0562-d5bf-451f-a63c-1ea947b6eb27",
                    "installed": false,
                    "kb": [
                        "890830"
                    ],
                    "title": "Windows Malicious Software Removal Tool x64 - v5.90 (KB890830)"
                }
            },
            "found_update_count": 0,
            "host": "123.123.123.123",
            "installed_update_count": 0,
            "reboot_required": false,
            "status": "SUCCESS",
            "updates": {}
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * found_update_count: 0
>  * installed_update_count: 0
>  * reboot_required: False
>  * ## Filtered_Updates
>    * ### 95335A9A-923A-47B2-Abb1-7584D685De6A
>      * filtered_reason: category_names
>      * id: 95335a9a-923a-47b2-abb1-7584d685de6a
>      * installed: False
>      * title: 2021-04 Servicing Stack Update for Windows Server 2016 for x64-based Systems (KB5001402)
>      * #### Categories
>        * 0: Security Updates
>        * 1: Windows Server 2016
>      * #### Kb
>        * 0: 5001402
>    * ### A711F6A5-5Bf3-4392-95D0-686F748789Dd
>      * filtered_reason: category_names
>      * id: a711f6a5-5bf3-4392-95d0-686f748789dd
>      * installed: False
>      * title: 2018-05 Cumulative Update for Windows Server 2016 for x64-based Systems (KB4103720)
>      * #### Categories
>        * 0: Updates
>        * 1: Windows Server 2016
>      * #### Kb
>        * 0: 4103720
>    * ### E0Fa0562-D5Bf-451F-A63C-1Ea947B6Eb27
>      * filtered_reason: category_names
>      * id: e0fa0562-d5bf-451f-a63c-1ea947b6eb27
>      * installed: False
>      * title: Windows Malicious Software Removal Tool x64 - v5.90 (KB890830)
>      * #### Categories
>        * 0: Update Rollups
>        * 1: Windows Server 2016
>        * 2: Windows Server 2019
>      * #### Kb
>        * 0: 890830
>  * ## Updates

### win-uri
***
Interacts with webservices
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_uri_module.html


#### Base Command

`win-uri`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| url | Supports FTP, HTTP or HTTPS URLs in the form of (ftp\|http\|https)://host.domain:port/path. | Required | 
| method | The HTTP Method of the request or response. Default is GET. | Optional | 
| content_type | Sets the "Content-Type" header. | Optional | 
| body | The body of the HTTP request/response to the web service. | Optional | 
| dest | Output the response body to a file. | Optional | 
| creates | A filename, when it already exists, this step will be skipped. | Optional | 
| removes | A filename, when it does not exist, this step will be skipped. | Optional | 
| return_content | Whether or not to return the body of the response as a "content" key in the dictionary result. If the reported Content-type is "application/json", then the JSON is additionally loaded into a key called `json` in the dictionary results. Possible values are: Yes, No. Default is No. | Optional | 
| status_code | A valid, numeric, HTTP status code that signifies success of the request.<br/>Can also be comma separated list of status codes. Default is [200]. | Optional | 
| url_username | The username to use for authentication.<br/>Was originally called `user` but was changed to `url_username` in Ansible 2.9. | Optional | 
| url_password | The password for `url_username`.<br/>Was originally called `password` but was changed to `url_password` in Ansible 2.9. | Optional | 
| follow_redirects | Whether or the module should follow redirects.<br/>`all` will follow all redirect.<br/>`none` will not follow any redirect.<br/>`safe` will follow only "safe" redirects, where "safe" means that the client is only doing a `GET` or `HEAD` on the URI to which it is being redirected. Possible values are: all, none, safe. Default is safe. | Optional | 
| maximum_redirection | Specify how many times the module will redirect a connection to an alternative URI before the connection fails.<br/>If set to `0` or `follow_redirects` is set to `none`, or `safe` when not doing a `GET` or `HEAD` it prevents all redirection. Default is 50. | Optional | 
| client_cert | The path to the client certificate (.pfx) that is used for X509 authentication. This path can either be the path to the `pfx` on the filesystem or the PowerShell certificate path `Cert:\CurrentUser\My\&lt;thumbprint&gt;`.<br/>The WinRM connection must be authenticated with `CredSSP` or `become` is used on the task if the certificate file is not password protected.<br/>Other authentication types can set `client_cert_password` when the cert is password protected. | Optional | 
| client_cert_password | The password for `client_cert` if the cert is password protected. | Optional | 
| use_proxy | If `no`, it will not use the proxy defined in IE for the current user. Possible values are: Yes, No. Default is Yes. | Optional | 
| proxy_url | An explicit proxy to use for the request.<br/>By default, the request will use the IE defined proxy unless `use_proxy` is set to `no`. | Optional | 
| proxy_username | The username to use for proxy authentication. | Optional | 
| proxy_password | The password for `proxy_username`. | Optional | 
| headers | Extra headers to set on the request.<br/>This should be a dictionary where the key is the header name and the value is the value for that header. | Optional | 
| http_agent | Header to identify as, generally appears in web server logs.<br/>This is set to the `User-Agent` header on a HTTP request. Default is ansible-httpget. | Optional | 
| timeout | Specifies how long the request can be pending before it times out (in seconds).<br/>Set to `0` to specify an infinite timeout. Default is 30. | Optional | 
| validate_certs | If `no`, SSL certificates will not be validated.<br/>This should only be used on personally controlled sites using self-signed certificates. Possible values are: Yes, No. Default is Yes. | Optional | 
| force_basic_auth | By default the authentication header is only sent when a webservice responses to an initial request with a 401 status. Since some basic auth services do not properly send a 401, logins will fail.<br/>This option forces the sending of the Basic authentication header upon the original request. Possible values are: Yes, No. Default is No. | Optional | 
| use_default_credential | Uses the current user's credentials when authenticating with a server protected with `NTLM`, `Kerberos`, or `Negotiate` authentication.<br/>Sites that use `Basic` auth will still require explicit credentials through the `url_username` and `url_password` options.<br/>The module will only have access to the user's credentials if using `become` with a password, you are connecting with SSH using a password, or connecting with WinRM using `CredSSP` or `Kerberos with delegation`.<br/>If not using `become` or a different auth method to the ones stated above, there will be no default credentials available and no authentication will occur. Possible values are: Yes, No. Default is No. | Optional | 
| proxy_use_default_credential | Uses the current user's credentials when authenticating with a proxy host protected with `NTLM`, `Kerberos`, or `Negotiate` authentication.<br/>Proxies that use `Basic` auth will still require explicit credentials through the `proxy_username` and `proxy_password` options.<br/>The module will only have access to the user's credentials if using `become` with a password, you are connecting with SSH using a password, or connecting with WinRM using `CredSSP` or `Kerberos with delegation`.<br/>If not using `become` or a different auth method to the ones stated above, there will be no default credentials available and no proxy authentication will occur. Possible values are: Yes, No. Default is No. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinUri.elapsed | unknown | The number of seconds that elapsed while performing the download. | 
| MicrosoftWindows.WinUri.url | string | The Target URL. | 
| MicrosoftWindows.WinUri.status_code | number | The HTTP Status Code of the response. | 
| MicrosoftWindows.WinUri.status_description | string | A summary of the status. | 
| MicrosoftWindows.WinUri.content | string | The raw content of the HTTP response. | 
| MicrosoftWindows.WinUri.content_length | number | The byte size of the response. | 
| MicrosoftWindows.WinUri.json | unknown | The json structure returned under content as a dictionary. | 


#### Command Example
```!win-uri host="123.123.123.123" url="http://google.com/" status_code=200```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinUri": {
            "accept_ranges": "none",
            "cache_control": "private, max-age=0",
            "changed": false,
            "character_set": "ISO-8859-1",
            "content_encoding": "",
            "content_length": -1,
            "content_type": "text/html; charset=ISO-8859-1",
            "cookies": [],
            "date": "Tue, 29 Jun 2021 03:20:39 GMT",
            "elapsed": 0.5468812,
            "expires": "-1",
            "headers": [
                "X-XSS-Protection",
                "X-Frame-Options",
                "Cache-Control",
                "Content-Type",
                "Date",
                "Expires",
                "P3P",
                "Set-Cookie",
                "Server",
                "Accept-Ranges",
                "Vary",
                "Transfer-Encoding"
            ],
            "host": "123.123.123.123",
            "is_from_cache": false,
            "is_mutually_authenticated": false,
            "last_modified": "2021-06-29T05:20:39.5210399+02:00",
            "method": "GET",
            "msg": "OK",
            "p3_p": "CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\"",
            "protocol_version": {
                "Build": -1,
                "Major": 1,
                "MajorRevision": -1,
                "Minor": 1,
                "MinorRevision": -1,
                "Revision": -1
            },
            "response_uri": "http://www.google.com/",
            "server": "gws",
            "set_cookie": "1P_JAR=2021-06-29-03; expires=Thu, 29-Jul-2021 03:20:39 GMT; path=/; domain=.google.com; Secure,NID=218=k9gPfV-dyDTDIEhr83SQqx1tn5-dypVUGdmaL2MChbc_cpeIBSkBxku2aaIgbuc-JQabdIkGeaydImnAa1dTmtSQTj3MhjzGBCuFUY-5erUZ9GkrAFuvcSwS0KrismDc-Y8n0bBg15L4nTx5JJC0OrlhGH-Hofb9xrGAT0A3Qdo; expires=Wed, 29-Dec-2021 03:20:39 GMT; path=/; domain=.google.com; HttpOnly",
            "status": "SUCCESS",
            "status_code": 200,
            "status_description": "OK",
            "supports_headers": true,
            "transfer_encoding": "chunked",
            "url": "http://google.com/",
            "vary": "Accept-Encoding",
            "x_frame_options": "SAMEORIGIN",
            "xxss_protection": "0"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * accept_ranges: none
>  * cache_control: private, max-age=0
>  * changed: False
>  * character_set: ISO-8859-1
>  * content_encoding: 
>  * content_length: -1
>  * content_type: text/html; charset=ISO-8859-1
>  * date: Tue, 29 Jun 2021 03:20:39 GMT
>  * elapsed: 0.5468812
>  * expires: -1
>  * is_from_cache: False
>  * is_mutually_authenticated: False
>  * last_modified: 2021-06-29T05:20:39.5210399+02:00
>  * method: GET
>  * msg: OK
>  * p3_p: CP="This is not a P3P policy! See g.co/p3phelp for more info."
>  * response_uri: http://www.google.com/
>  * server: gws
>  * set_cookie: 1P_JAR=2021-06-29-03; expires=Thu, 29-Jul-2021 03:20:39 GMT; path=/; domain=.google.com; Secure,NID=218=k9gPfV-dyDTDIEhr83SQqx1tn5-dypVUGdmaL2MChbc_cpeIBSkBxku2aaIgbuc-JQabdIkGeaydImnAa1dTmtSQTj3MhjzGBCuFUY-5erUZ9GkrAFuvcSwS0KrismDc-Y8n0bBg15L4nTx5JJC0OrlhGH-Hofb9xrGAT0A3Qdo; expires=Wed, 29-Dec-2021 03:20:39 GMT; path=/; domain=.google.com; HttpOnly
>  * status_code: 200
>  * status_description: OK
>  * supports_headers: True
>  * transfer_encoding: chunked
>  * url: http://google.com/
>  * vary: Accept-Encoding
>  * x_frame_options: SAMEORIGIN
>  * xxss_protection: 0
>  * ## Cookies
>  * ## Headers
>    * 0: X-XSS-Protection
>    * 1: X-Frame-Options
>    * 2: Cache-Control
>    * 3: Content-Type
>    * 4: Date
>    * 5: Expires
>    * 6: P3P
>    * 7: Set-Cookie
>    * 8: Server
>    * 9: Accept-Ranges
>    * 10: Vary
>    * 11: Transfer-Encoding
>  * ## Protocol_Version
>    * Build: -1
>    * Major: 1
>    * MajorRevision: -1
>    * Minor: 1
>    * MinorRevision: -1
>    * Revision: -1


### win-user
***
Manages local Windows user accounts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_user_module.html


#### Base Command

`win-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the user to create, remove or modify. | Required | 
| fullname | Full name of the user. | Optional | 
| description | Description of the user. | Optional | 
| password | Optionally set the user's password to this (plain text) value. | Optional | 
| update_password | `always` will update passwords if they differ.  `on_create` will only set the password for newly created users. Possible values are: always, on_create. Default is always. | Optional | 
| password_expired | `yes` will require the user to change their password at next login.<br/>`no` will clear the expired password flag. | Optional | 
| password_never_expires | `yes` will set the password to never expire.<br/>`no` will allow the password to expire. | Optional | 
| user_cannot_change_password | `yes` will prevent the user from changing their password.<br/>`no` will allow the user to change their password. | Optional | 
| account_disabled | `yes` will disable the user account.<br/>`no` will clear the disabled flag. | Optional | 
| account_locked | `no` will unlock the user account if locked. Possible values are: no. | Optional | 
| groups | Adds or removes the user from this comma-separated list of groups, depending on the value of `groups_action`.<br/>When `groups_action` is `replace` and `groups` is set to the empty string ('groups='), the user is removed from all groups. | Optional | 
| groups_action | If `add`, the user is added to each group in `groups` where not already a member.<br/>If `replace`, the user is added as a member of each group in `groups` and removed from any other groups.<br/>If `remove`, the user is removed from each group in `groups`. Possible values are: add, replace, remove. Default is replace. | Optional | 
| state | When `absent`, removes the user account if it exists.<br/>When `present`, creates or updates the user account.<br/>When `query` (new in 1.9), retrieves the user account details without making any changes. Possible values are: absent, present, query. Default is present. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinUser.account_disabled | boolean | Whether the user is disabled. | 
| MicrosoftWindows.WinUser.account_locked | boolean | Whether the user is locked. | 
| MicrosoftWindows.WinUser.description | string | The description set for the user. | 
| MicrosoftWindows.WinUser.fullname | string | The full name set for the user. | 
| MicrosoftWindows.WinUser.groups | unknown | A list of groups and their ADSI path the user is a member of. | 
| MicrosoftWindows.WinUser.name | string | The name of the user | 
| MicrosoftWindows.WinUser.password_expired | boolean | Whether the password is expired. | 
| MicrosoftWindows.WinUser.password_never_expires | boolean | Whether the password is set to never expire. | 
| MicrosoftWindows.WinUser.path | string | The ADSI path for the user. | 
| MicrosoftWindows.WinUser.sid | string | The SID for the user. | 
| MicrosoftWindows.WinUser.user_cannot_change_password | boolean | Whether the user can change their own password. | 


#### Command Example
```!win-user host="123.123.123.123" name="fed-phil" password="B0bP4ssw0rd" state="present" groups="Users" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinUser": {
            "account_disabled": false,
            "account_locked": false,
            "changed": true,
            "description": "",
            "fullname": "fed-phil",
            "groups": [
                {
                    "name": "Users",
                    "path": "WinNT://WORKGROUP/WIN-U425UI0HPP7/Users"
                }
            ],
            "host": "123.123.123.123",
            "name": "fed-phil",
            "password_expired": false,
            "password_never_expires": false,
            "path": "WinNT://WORKGROUP/WIN-U425UI0HPP7/fed-phil",
            "sid": "S-1-5-21-4202888923-410868521-3023024269-1003",
            "state": "present",
            "status": "CHANGED",
            "user_cannot_change_password": false
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * account_disabled: False
>  * account_locked: False
>  * changed: True
>  * description: 
>  * fullname: fed-phil
>  * name: fed-phil
>  * password_expired: False
>  * password_never_expires: False
>  * path: WinNT://WORKGROUP/WIN-U425UI0HPP7/fed-phil
>  * sid: S-1-5-21-4202888923-410868521-3023024269-1003
>  * state: present
>  * user_cannot_change_password: False
>  * ## Groups
>  * ## Users
>    * name: Users
>    * path: WinNT://WORKGROUP/WIN-U425UI0HPP7/Users


### win-user-profile
***
Manages the Windows user profiles.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_user_profile_module.html


#### Base Command

`win-user-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Specifies the base name for the profile path.<br/>When `state` is `present` this is used to create the profile for `username` at a specific path within the profile directory.<br/>This cannot be used to specify a path outside of the profile directory but rather it specifies a folder(s) within this directory.<br/>If a profile for another user already exists at the same path, then a 3 digit incremental number is appended by Windows automatically.<br/>When `state` is `absent` and `username` is not set, then the module will remove all profiles that point to the profile path derived by this value.<br/>This is useful if the account no longer exists but the profile still remains. | Optional | 
| remove_multiple | When `state` is `absent` and the value for `name` matches multiple profiles the module will fail.<br/>Set this value to `yes` to force the module to delete all the profiles found. Possible values are: Yes, No. Default is No. | Optional | 
| state | Will ensure the profile exists when set to `present`.<br/>When creating a profile the `username` option must be set to a valid account.<br/>Will remove the profile(s) when set to `absent`.<br/>When removing a profile either `username` must be set to a valid account, or `name` is set to the profile's base name. Possible values are: absent, present. Default is present. | Optional | 
| username | The account name of security identifier (SID) for the profile.<br/>This must be set when `state` is `present` and must be a valid account or the SID of a valid account.<br/>When `state` is `absent` then this must still be a valid account number but the SID can be a deleted user's SID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinUserProfile.path | string | The full path to the profile for the account. This will be null if \`state=absent\` and no profile was deleted. | 


#### Command Example
```!win-user-profile host="123.123.123.123" username="fed-phil" state="present" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinUserProfile": {
            "changed": true,
            "host": "123.123.123.123",
            "path": "C:\\Users\\fed-phil",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * path: C:\Users\fed-phil


### win-user-right
***
Manage Windows User Rights
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_user_right_module.html


#### Base Command

`win-user-right`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | The name of the User Right as shown by the `Constant Name` value from `https://technet.microsoft.com/en-us/library/dd349804.aspx`.<br/>The module will return an error if the right is invalid. | Required | 
| users | A list of users or groups to add/remove on the User Right.<br/>These can be in the form DOMAIN\user-group, user-group@DOMAIN.COM for domain users/groups.<br/>For local users/groups it can be in the form user-group, .\user-group, SERVERNAME\user-group where SERVERNAME is the name of the remote server.<br/>You can also add special local accounts like SYSTEM and others.<br/>Can be set to an empty list with `action=set` to remove all accounts from the right. | Required | 
| action | `add` will add the users/groups to the existing right.<br/>`remove` will remove the users/groups from the existing right.<br/>`set` will replace the users/groups of the existing right. Possible values are: add, remove, set. Default is set. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinUserRight.added | unknown | A list of accounts that were added to the right, this is empty if no accounts were added. | 
| MicrosoftWindows.WinUserRight.removed | unknown | A list of accounts that were removed from the right, this is empty if no accounts were removed. | 


#### Command Example
```!win-user-right host="123.123.123.123" name="SeDenyInteractiveLogonRight" users="Guest" action="set" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinUserRight": {
            "added": [
                "WIN-U425UI0HPP7\\Guest"
            ],
            "changed": true,
            "host": "123.123.123.123",
            "removed": [],
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True
>  * ## Added
>    * 0: WIN-U425UI0HPP7\Guest
>  * ## Removed


### win-wait-for
***
Waits for a condition before continuing
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_wait_for_module.html


#### Base Command

`win-wait-for`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| connect_timeout | The maximum number of seconds to wait for a connection to happen before closing and retrying. Default is 5. | Optional | 
| delay | The number of seconds to wait before starting to poll. | Optional | 
| exclude_hosts | The list of hosts or IPs to ignore when looking for active TCP connections when `state=drained`. | Optional | 
| ansible-module-host | A resolvable hostname or IP address to wait for.<br/>If `state=drained` then it will only check for connections on the IP specified, you can use '0.0.0.0' to use all host IPs. Default is 127.0.0.1. | Optional | 
| path | The path to a file on the filesystem to check.<br/>If `state` is present or started then it will wait until the file exists.<br/>If `state` is absent then it will wait until the file does not exist. | Optional | 
| port | The port number to poll on `host`. | Optional | 
| regex | Can be used to match a string in a file.<br/>If `state` is present or started then it will wait until the regex matches.<br/>If `state` is absent then it will wait until the regex does not match.<br/>Defaults to a multiline regex. | Optional | 
| sleep | Number of seconds to sleep between checks. Default is 1. | Optional | 
| state | When checking a port, `started` will ensure the port is open, `stopped` will check that is it closed and `drained` will check for active connections.<br/>When checking for a file or a search string `present` or `started` will ensure that the file or string is present, `absent` will check that the file or search string is absent or removed. Possible values are: absent, drained, present, started, stopped. Default is started. | Optional | 
| timeout | The maximum number of seconds to wait for. Default is 300. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinWaitFor.wait_attempts | number | The number of attempts to poll the file or port before module finishes. | 
| MicrosoftWindows.WinWaitFor.elapsed | unknown | The elapsed seconds between the start of poll and the end of the module. This includes the delay if the option is set. | 


#### Command Example
```!win-wait-for host="123.123.123.123" port="3389" delay="10" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinWaitFor": {
            "changed": false,
            "elapsed": 10.031336099999999,
            "host": "123.123.123.123",
            "status": "SUCCESS",
            "wait_attempts": 1
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * elapsed: 10.031336099999999
>  * wait_attempts: 1


### win-wait-for-process
***
Waits for a process to exist or not exist before continuing.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_wait_for_process_module.html


#### Base Command

`win-wait-for-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| process_name_exact | The name of the process(es) for which to wait.  The name of the process(es) should not include the file extension suffix. | Optional | 
| process_name_pattern | RegEx pattern matching desired process(es). | Optional | 
| sleep | Number of seconds to sleep between checks.<br/>Only applies when waiting for a process to start.  Waiting for a process to start does not have a native non-polling mechanism. Waiting for a stop uses native PowerShell and does not require polling. Default is 1. | Optional | 
| process_min_count | Minimum number of process matching the supplied pattern to satisfy `present` condition.<br/>Only applies to `present`. Default is 1. | Optional | 
| pid | The PID of the process. | Optional | 
| owner | The owner of the process.<br/>Requires PowerShell version 4.0 or newer. | Optional | 
| pre_wait_delay | Seconds to wait before checking processes. Default is 0. | Optional | 
| post_wait_delay | Seconds to wait after checking for processes. Default is 0. | Optional | 
| state | When checking for a running process `present` will block execution until the process exists, or until the timeout has been reached. `absent` will block execution until the process no longer exists, or until the timeout has been reached.<br/>When waiting for `present`, the module will return changed only if the process was not present on the initial check but became present on subsequent checks.<br/>If, while waiting for `absent`, new processes matching the supplied pattern are started, these new processes will not be included in the action. Possible values are: absent, present. Default is present. | Optional | 
| timeout | The maximum number of seconds to wait for a for a process to start or stop before erroring out. Default is 300. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinWaitForProcess.elapsed | unknown | The elapsed seconds between the start of poll and the end of the module. | 
| MicrosoftWindows.WinWaitForProcess.matched_processes | unknown | List of matched processes \(either stopped or started\). | 


#### Command Example
```!win-wait-for-process host="123.123.123.123" process_name_pattern="v(irtual)?box(headless|svc)?" state="absent" timeout="500" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinWaitForProcess": {
            "changed": false,
            "elapsed": 0.0468785,
            "host": "123.123.123.123",
            "matched_processes": [],
            "status": "SUCCESS"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * changed: False
>  * elapsed: 0.0468785
>  * ## Matched_Processes


### win-wakeonlan
***
Send a magic Wake-on-LAN (WoL) broadcast packet
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_wakeonlan_module.html


#### Base Command

`win-wakeonlan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| mac | MAC address to send Wake-on-LAN broadcast packet for. | Required | 
| broadcast | Network broadcast address to use for broadcasting magic Wake-on-LAN packet. Default is 255.255.255.255. | Optional | 
| port | UDP port to use for magic Wake-on-LAN packet. Default is 7. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!win-wakeonlan host="123.123.123.123" mac="00:00:5E:00:53:66" broadcast="192.0.2.23" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinWakeonlan": {
            "changed": true,
            "host": "123.123.123.123",
            "status": "CHANGED"
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  CHANGED 
>  * changed: True


### win-webpicmd
***
Installs packages using Web Platform Installer command-line
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_webpicmd_module.html


#### Base Command

`win-webpicmd`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| name | Name of the package to be installed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |




### win-whoami
***
Get information about the current user and process
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_whoami_module.html


#### Base Command

`win-whoami`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinWhoami.authentication_package | string | The name of the authentication package used to authenticate the user in the session. | 
| MicrosoftWindows.WinWhoami.user_flags | string | The user flags for the logon session, see UserFlags in \`https://msdn.microsoft.com/en-us/library/windows/desktop/aa380128\`. | 
| MicrosoftWindows.WinWhoami.upn | string | The user principal name of the current user. | 
| MicrosoftWindows.WinWhoami.logon_type | string | The logon type that identifies the logon method, see \`https://msdn.microsoft.com/en-us/library/windows/desktop/aa380129.aspx\`. | 
| MicrosoftWindows.WinWhoami.privileges | unknown | A dictionary of privileges and their state on the logon token. | 
| MicrosoftWindows.WinWhoami.label | unknown | The mandatory label set to the logon session. | 
| MicrosoftWindows.WinWhoami.impersonation_level | string | The impersonation level of the token, only valid if \`token_type\` is \`TokenImpersonation\`, see \`https://msdn.microsoft.com/en-us/library/windows/desktop/aa379572.aspx\`. | 
| MicrosoftWindows.WinWhoami.login_time | string | The logon time in ISO 8601 format | 
| MicrosoftWindows.WinWhoami.groups | unknown | A list of groups and attributes that the user is a member of. | 
| MicrosoftWindows.WinWhoami.account | unknown | The running account SID details. | 
| MicrosoftWindows.WinWhoami.login_domain | string | The name of the domain used to authenticate the owner of the session. | 
| MicrosoftWindows.WinWhoami.rights | unknown | A list of logon rights assigned to the logon. | 
| MicrosoftWindows.WinWhoami.logon_server | string | The name of the server used to authenticate the owner of the logon session. | 
| MicrosoftWindows.WinWhoami.logon_id | number | The unique identifier of the logon session. | 
| MicrosoftWindows.WinWhoami.dns_domain_name | string | The DNS name of the logon session, this is an empty string if this is not set. | 
| MicrosoftWindows.WinWhoami.token_type | string | The token type to indicate whether it is a primary or impersonation token. | 


#### Command Example
```!win-whoami host="123.123.123.123" ```

#### Context Example
```json
{
    "MicrosoftWindows": {
        "WinWhoami": {
            "account": {
                "account_name": "Administrator",
                "domain_name": "WIN-U425UI0HPP7",
                "sid": "S-1-5-21-4202888923-410868521-3023024269-500",
                "type": "User"
            },
            "authentication_package": "NTLM",
            "changed": false,
            "dns_domain_name": "",
            "groups": [
                {
                    "account_name": "None",
                    "attributes": [
                        "Mandatory",
                        "Enabled by default",
                        "Enabled"
                    ],
                    "domain_name": "WIN-U425UI0HPP7",
                    "sid": "S-1-5-21-4202888923-410868521-3023024269-513",
                    "type": "Group"
                }
            ],
            "host": "123.123.123.123",
            "impersonation_level": "SecurityAnonymous",
            "label": {
                "account_name": "High Mandatory Level",
                "domain_name": "Mandatory Label",
                "sid": "S-1-16-12288",
                "type": "Label"
            },
            "login_domain": "WIN-U425UI0HPP7",
            "login_time": "2021-06-29T05:17:41.3808413+02:00",
            "logon_id": 17293435,
            "logon_server": "WIN-U425UI0HPP7",
            "logon_type": "Network",
            "privileges": {
                "SeBackupPrivilege": "enabled-by-default",
                "SeChangeNotifyPrivilege": "enabled-by-default",
                "SeCreateGlobalPrivilege": "enabled-by-default",
                "SeCreatePagefilePrivilege": "enabled-by-default",
                "SeCreateSymbolicLinkPrivilege": "enabled-by-default",
                "SeDebugPrivilege": "enabled-by-default",
                "SeDelegateSessionUserImpersonatePrivilege": "enabled-by-default",
                "SeImpersonatePrivilege": "enabled-by-default",
                "SeIncreaseBasePriorityPrivilege": "enabled-by-default",
                "SeIncreaseQuotaPrivilege": "enabled-by-default",
                "SeIncreaseWorkingSetPrivilege": "enabled-by-default",
                "SeLoadDriverPrivilege": "enabled-by-default",
                "SeManageVolumePrivilege": "enabled-by-default",
                "SeProfileSingleProcessPrivilege": "enabled-by-default",
                "SeRemoteShutdownPrivilege": "enabled-by-default",
                "SeRestorePrivilege": "enabled-by-default",
                "SeSecurityPrivilege": "enabled-by-default",
                "SeShutdownPrivilege": "enabled-by-default",
                "SeSystemEnvironmentPrivilege": "enabled-by-default",
                "SeSystemProfilePrivilege": "enabled-by-default",
                "SeSystemtimePrivilege": "enabled-by-default",
                "SeTakeOwnershipPrivilege": "enabled-by-default",
                "SeTimeZonePrivilege": "enabled-by-default",
                "SeUndockPrivilege": "enabled-by-default"
            },
            "rights": [
                "SeNetworkLogonRight",
                "SeInteractiveLogonRight",
                "SeBatchLogonRight",
                "SeRemoteInteractiveLogonRight"
            ],
            "status": "SUCCESS",
            "token_type": "TokenPrimary",
            "upn": "",
            "user_flags": []
        }
    }
}
```

#### Human Readable Output

># 123.123.123.123 -  SUCCESS 
>  * authentication_package: NTLM
>  * changed: False
>  * dns_domain_name: 
>  * impersonation_level: SecurityAnonymous
>  * login_domain: WIN-U425UI0HPP7
>  * login_time: 2021-06-29T05:17:41.3808413+02:00
>  * logon_id: 17293435
>  * logon_server: WIN-U425UI0HPP7
>  * logon_type: Network
>  * token_type: TokenPrimary
>  * upn: 
>  * ## Account
>    * account_name: Administrator
>    * domain_name: WIN-U425UI0HPP7
>    * sid: S-1-5-21-4202888923-410868521-3023024269-500
>    * type: User
>  * ## Groups
>  * ## None
>    * account_name: None
>    * domain_name: WIN-U425UI0HPP7
>    * sid: S-1-5-21-4202888923-410868521-3023024269-513
>    * type: Group
>    * ### Attributes
>      * 0: Mandatory
>      * 1: Enabled by default
>      * 2: Enabled
>  * ## Privileges
>    * SeBackupPrivilege: enabled-by-default
>    * SeChangeNotifyPrivilege: enabled-by-default
>    * SeCreateGlobalPrivilege: enabled-by-default
>    * SeCreatePagefilePrivilege: enabled-by-default
>    * SeCreateSymbolicLinkPrivilege: enabled-by-default
>    * SeDebugPrivilege: enabled-by-default
>    * SeDelegateSessionUserImpersonatePrivilege: enabled-by-default
>    * SeImpersonatePrivilege: enabled-by-default
>    * SeIncreaseBasePriorityPrivilege: enabled-by-default
>    * SeIncreaseQuotaPrivilege: enabled-by-default
>    * SeIncreaseWorkingSetPrivilege: enabled-by-default
>    * SeLoadDriverPrivilege: enabled-by-default
>    * SeManageVolumePrivilege: enabled-by-default
>    * SeProfileSingleProcessPrivilege: enabled-by-default
>    * SeRemoteShutdownPrivilege: enabled-by-default
>    * SeRestorePrivilege: enabled-by-default
>    * SeSecurityPrivilege: enabled-by-default
>    * SeShutdownPrivilege: enabled-by-default
>    * SeSystemEnvironmentPrivilege: enabled-by-default
>    * SeSystemProfilePrivilege: enabled-by-default
>    * SeSystemtimePrivilege: enabled-by-default
>    * SeTakeOwnershipPrivilege: enabled-by-default
>    * SeTimeZonePrivilege: enabled-by-default
>    * SeUndockPrivilege: enabled-by-default
>  * ## Rights
>    * 0: SeNetworkLogonRight
>    * 1: SeInteractiveLogonRight
>    * 2: SeBatchLogonRight
>    * 3: SeRemoteInteractiveLogonRight
>  * ## User_Flags


### win-xml
***
Manages XML file content on Windows hosts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/win_xml_module.html


#### Base Command

`win-xml`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname or IP of target. Optionally the port can be specified using :PORT. If multiple targets are specified using an array, the integration will use the configured concurrency factor for high performance. | Required | 
| attribute | The attribute name if the type is 'attribute'.<br/>Required if `type=attribute`. | Optional | 
| count | When set to `yes`, return the number of nodes matched by `xpath`. Possible values are: Yes, No. Default is No. | Optional | 
| backup | Determine whether a backup should be created.<br/>When set to `yes`, create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly. Possible values are: Yes, No. Default is No. | Optional | 
| fragment | The string representation of the XML fragment expected at xpath.  Since ansible 2.9 not required when `state=absent`, or when `count=yes`. | Optional | 
| path | Path to the file to operate on. | Required | 
| state | Set or remove the nodes (or attributes) matched by `xpath`. Possible values are: present, absent. Default is present. | Optional | 
| type | The type of XML node you are working with. Possible values are: attribute, element, text. Default is element. | Required | 
| xpath | Xpath to select the node or nodes to operate on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftWindows.WinXml.backup_file | string | Name of the backup file that was created. | 
| MicrosoftWindows.WinXml.count | number | Number of nodes matched by xpath. | 
| MicrosoftWindows.WinXml.msg | string | What was done. | 
| MicrosoftWindows.WinXml.err | unknown | XML comparison exceptions. | 


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
