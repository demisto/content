Nexthink helps IT teams deliver on the promise of the modern digital workplace. Nexthink is the only solution to provide enterprises with a way to visualize, act and engage across the entire IT ecosystem to lower IT cost and improve digital employee experience.
This integration was integrated and tested with version 1.0 of Nexthink.

## Configure Nexthink on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nexthink.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Engine Host (e.g. connector.nexthink.com) | True |
    | Nexthink Connector Port| False |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
     Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nt-compliance-check
***
Verify antivirus/antispyware status.


#### Base Command

`nt-compliance-check`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | Endpoint IP Address. Default is None. | Required |
| hostname | Endpoint Hostname. Default is None. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Compliance.DeviceName | string | Endpoint Device Host Name |
| Nexthink.Compliance.LastLoggedOnUser | string | Last Logged On User |
| Nexthink.Compliance.IPAddress | string | Endpoint IP Address |
| Nexthink.Compliance.MACAddress | string | Endpoint MAC Address |
| Nexthink.Compliance.DeviceAntivirus | string | Endpoint Antivirus Name |
| Nexthink.Compliance.DeviceAntivirusRTP | string | Endpoint Antivirus Real Time Protection Status |
| Nexthink.Compliance.DeviceAntivirusUpdated | string | Endpoint Antivirus Update Status |
| Nexthink.Compliance.DeviceAntispyware | string | Endpoint Antispyware Name |
| Nexthink.Compliance.DeviceAntispywareRTP | string | Endpoint Antispyware Real Time Protection Status |
| Nexthink.Compliance.DeviceAntispywareUpdated | string | Endpoint Antispyware Update Status |


#### Command Example
``` ```

#### Human Readable Output



### nt-installed-packages
***
Query installed software in endpoint.


#### Base Command

`nt-installed-packages`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint Hostname. | Required |
| package | Installed Software Name. Default is agent. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Package.PackageName | string | Package Name |
| Nexthink.Package.PackagePublisher | string | Packaged Publisher |
| Nexthink.Package.PackageVersion | string | Package Version |
| Nexthink.Package.DeviceName | string | Endpoint Device Host Name |
| Nexthink.Package.LastLoggedOnUser | string | Last Logged On User |
| Nexthink.Package.IPAddress | string | Endpoint IP Address |
| Nexthink.Package.MACAddress | string | Endpoint MAC Address |


#### Command Example
``` ```

#### Human Readable Output



### nt-endpoint-details
***
Get endpoint details.


#### Base Command

`nt-endpoint-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint Hostname. Default is None. | Required |
| ipaddress | Endpoint IP Address. Default is None. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Endpoint.EndpointName | string | Endpoint Device Host Name |
| Nexthink.Endpoint.LastLoggedOnUser | string | Last Logged On User |
| Nexthink.Endpoint.IPAddress | string | Endpoint IP Address |
| Nexthink.Endpoint.MACAddress | string | Endpoint MAC Address |


#### Command Example
``` ```

#### Human Readable Output


