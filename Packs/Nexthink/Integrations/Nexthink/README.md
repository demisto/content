Nexthink helps IT teams deliver on the promise of the modern digital workplace. Nexthink is the only solution to provide enterprises with a way to visualize, act and engage across the entire IT ecosystem to lower IT cost and improve digital employee experience.
This integration was integrated and tested with version 1.0 of Nexthink

## Configure Nexthink on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nexthink.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Engine Host (e.g. connector.nexthink.com) |  | True |
    | Nexthink Connector Port |  | False |
    | Username |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
    | Use system proxy settings | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nt_compliance_check
***
Verify antivirus/antispyware status.


#### Base Command

`nt_compliance_check`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | Endpoint IP Address. Default is None. | Required |
| hostname | Endpoint Hostname. Default is None. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Compliance.Device Name | unknown | Endpoint Device Host Name |
| Nexthink.Compliance.Last Logged On User | unknown | Last Logged On User |
| Nexthink.Compliance.IP Address | unknown | Endpoint IP Address |
| Nexthink.Compliance.MAC Address | unknown | Endpoint MAC Address |
| Nexthink.Compliance.Device Antivirus | unknown | Endpoint Antivirus Name |
| Nexthink.Compliance.Device Antivirus RTP | unknown | Endpoint Antivirus Real Time Protection Status |
| Nexthink.Compliance.Device Antivirus Updated | unknown | Endpoint Antivirus Update Status |
| Nexthink.Compliance.Device Antispyware | unknown | Endpoint Antispyware Name |
| Nexthink.Compliance.Device Antispyware RTP | unknown | Endpoint Antispyware Real Time Protection Status |
| Nexthink.Compliance.Device Antispyware Updated | unknown | Endpoint Antispyware Update Status |


#### Command Example
``` ```

#### Human Readable Output



### nt_installed_packages
***
Verify software installed in endpoint.


#### Base Command

`nt_installed_packages`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint Hostname. | Required |
| package | Installed Software Name. Default is agent. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Package.Package Name | unknown | Package Name |
| Nexthink.Package.Package Publisher | unknown | Packaged Publisher |
| Nexthink.Package.Package Version | unknown | Package Version |
| Nexthink.Package.Device Name | unknown | Endpoint Device Host Name |
| Nexthink.Package.Last Logged On User | unknown | Last Logged On User |
| Nexthink.Package.IP Address | unknown | Endpoint IP Address |
| Nexthink.Package.MAC Address | unknown | Endpoint MAC Address |


#### Command Example
``` ```

#### Human Readable Output



### nt_endpoint_details
***
Get endpoint details.


#### Base Command

`nt_endpoint_details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint Hostname. Default is None. | Required |
| ipaddress | Endpoint IP Address. Default is None. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Endpoint.Endpoint Name | unknown | Endpoint Device Host Name |
| Nexthink.Endpoint.Last Logged On User | unknown | Last Logged On User |
| Nexthink.Endpoint.IP Address | unknown | Endpoint IP Address |
| Nexthink.Endpoint.MAC Address | unknown | Endpoint MAC Address |


#### Command Example
``` ```

#### Human Readable Output


