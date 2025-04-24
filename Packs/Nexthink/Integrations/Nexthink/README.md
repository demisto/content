Nexthink helps IT teams deliver on the promise of the modern digital workplace. Nexthink is the only solution to provide enterprises with a way to visualize, act and engage across the entire IT ecosystem to lower IT cost and improve digital employee experience.
This integration was integrated and tested with version 1.0.1 of Nexthink

## Configure Nexthink in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Engine Host (e.g. connector.nexthink.com) |  | True |
| Nexthink Engine Port (e.g. 1671) |  | False |
| Username |  | True |
| Password |  | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nt-compliance-check
***
Verify antivirus/antispyware status.


#### Base Command

`nt-compliance-check`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | Endpoint IP Address. | Optional |
| hostname | Endpoint Hostname. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Compliance.DeviceName | string | Endpoint device host name. |
| Nexthink.Compliance.LastLoggedOnUser | string | Last logged on user. |
| Nexthink.Compliance.IPAddress | string | Endpoint IP address. |
| Nexthink.Compliance.MACAddress | string | Endpoint MAC address. |
| Nexthink.Compliance.DeviceAntivirus | string | Endpoint antivirus name. |
| Nexthink.Compliance.DeviceAntivirusRTP | string | Endpoint antivirus real time protection status. |
| Nexthink.Compliance.DeviceAntivirusUpdated | string | Endpoint antivirus update status. |
| Nexthink.Compliance.DeviceAntispyware | string | Endpoint Antispyware name. |
| Nexthink.Compliance.DeviceAntispywareRTP | string | Endpoint Antispyware real time protection status. |
| Nexthink.Compliance.DeviceAntispywareUpdated | string | Endpoint Antispyware update status. |


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
| Nexthink.Package.PackageName | string | Package name. |
| Nexthink.Package.PackagePublisher | string | Packaged publisher. |
| Nexthink.Package.PackageVersion | string | Package version. |
| Nexthink.Package.DeviceName | string | Endpoint device host name. |
| Nexthink.Package.LastLoggedOnUser | string | Last logged on user. |
| Nexthink.Package.IPAddress | string | Endpoint IP address. |
| Nexthink.Package.MACAddress | string | Endpoint MAC address. |


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
| hostname | Endpoint hostname. | Optional |
| ipaddress | Endpoint IP Address. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexthink.Endpoint.EndpointName | string | Endpoint device host name. |
| Nexthink.Endpoint.LastLoggedOnUser | string | Last logged on user. |
| Nexthink.Endpoint.IPAddress | string | Endpoint IP address. |
| Nexthink.Endpoint.MACAddress | string | Endpoint MAC address. |


#### Command Example
``` ```

#### Human Readable Output

