Adds a remote system (such as a desktop under investigation) to an investigation. This allows you to install an agent on the system.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | management |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name |  The unique name that will be used in the investigation. (default) |
| username | The user name in the remote system. |
| host | The host IP address or network identifiable name. (mandatory) |
| workgroup | The workgroup or domain of the user. |
| password | The users password used to log in to the remote system. By default you will be prompted to enter the password once you hit enter. However, the password can be typed in the command line. If the password is entered in the command line, it will be shown. |
| credentialSet | The credentials to be chosen to apply to the system (instead of username & password). |
| dmbPort | The non-standard SMB port to be chosen. |
| sshPort | The non-standard SSH port to be chosen. The default is 22.
| os | The OS of the remote system. Can be, "windows", "linux", or "OSX") |
| arch | Select "amd64" for 64bit systems or "i386" for 32bit systems. |
| engineName | The engine to be used if required. |

## Outputs
---
There are no outputs for this script.
