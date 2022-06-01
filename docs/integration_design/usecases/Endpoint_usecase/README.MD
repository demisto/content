# Endpoint
Top Use-Cases:
- Fetch Incidents & Events
- [Get event details (from specified incident)](#info-example)
- [Quarantine File](#quarantine-example)
- Isolate and contain endpoints
- Update Indicators (Network, hashes, etc.) by policy (can be block, monitor) – Block list
- Add indicators to allow list
- Search for indicators in the system (Seen indicators and related incidents/events)
- Download file (based on hash, path)
- Trigger scans on specified hosts
- Update .DAT files for signatures and compare existing .DAT file to the newest one on the server
- [Get information for a specified host (OS, users, addresses, hostname)](#scan)
- Get policy information and assign policies to endpoints

**Endpoint Integration Example** – EDRs, AV, HIPS


## Command Examples

### sep-endpoints-info <a name="info-example"> <\a>
---
Get information about endpoints.
##### Base Command
`sep-endpoints-info`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| columns | The columns to show. | Optional | 
| computerName | Filter by the host name of a computer. Wild card is supported as '*'. | Optional | 
| lastUpdate | Indicates when a computer last updated its status. The default value of 0 gets all the results. | Optional | 
| os | Operating system to filter. | Optional | 
| pageSize | The number of results to include on each page. The default is 20. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SEPM.Endpoint.Hostname | string | The endpoint's hostname. | 
| SEPM.Endpoint.Domain | string | The endpoint's domain. | 
| SEPM.Endpoint.IPAddresses | string | The endpoint's IP addresses. | 
| SEPM.Endpoint.OS | string | The endpoint's OS information. | 
| SEPM.Endpoint.Description | string | The endpoint's description. | 
| SEPM.Endpoint.MACAddresses | string | The endpoint's MAC address. | 
| SEPM.Endpoint.BIOSVersion | string | The endpoint's BIOS version. | 
| SEPM.Endpoint.DHCPServer | string | The endpoint's DHCP server address. | 
| SEPM.Endpoint.HardwareKey | String |  Hardware-Key of the client to be moved | 
##### Command Example
` sep-endpoints-info`
##### Context Example
```
{
    "SEPM": {
        "Endpoint": [
            {
                "Domain": "WORKGROUP", 
                "IPAddresses": [
                    "192.168.1.17", 
                    "FE80:0000:0000:0000:A46F:6886:CEF3:8203"
                ], 
                "BIOSVesrsion": "INTEL  - 6040000 PhoenixBIOS 4.0 Release 6.0", 
                "Hostname": "demisto-PC", 
                "MACAddresses": [
                    "00-50-56-B1-A9-3F", 
                    "00-50-56-B1-A9-3F"
                ], 
                "HardwareKey": "065A82DBECE6B2B3184CBC9911AC13D1", 
                "OS": "Windows 7 Enterprise Edition | x64", 
                "DHCPServer": "192.168.1.8"
            }, 
            {
                "Domain": "WORKGROUP", 
                "IPAddresses": [
                    "192.168.1.125"
                ], 
                "BIOSVesrsion": "INTEL  - 6040000 PhoenixBIOS 4.0 Release 6.0", 
                "Hostname": "DESKTOP-TF35B9B", 
                "MACAddresses": [
                    "00-0C-29-7C-C5-AE"
                ], 
                "HardwareKey": "269CE816FDB1BA25A2505D0A5A59294C", 
                "OS": "Windows 10 Professional Edition | x64", 
                "DHCPServer": "192.168.1.8"
            }
        ]
    }
}
```
##### Human Readable Output
![screen shot 2019-02-03 at 16 44 55](https://user-images.githubusercontent.com/44666568/52178121-1d059a80-27d3-11e9-8479-e3873d269238.png)
### sep-endpoint-quarantine <a name="quarantine-example"> </a>
---
Quarantines the endpoint according to its policy.
##### Base Command
`sep-endpoint-quarantine`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | IP or Hostname of the endpoint | Required | 
| actionType | Add or remove endpoint from quarantine. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SEPM.Quarantine.CommandID | string | ID of the invoked command | 
| SEPM.Quarantine.Action | string | The action type ('Add' or 'Remove') | 
| SEPM.Quarantine.Endpoint | string | The endpoint identifier (IP or Host Name) | 
##### Command Example
`sep-endpoint-quarantine actionType=add endpoint=demisto-PC`
##### Context Example
```
{
    "SEPM": {
        "Quarantine": {
            "Action": "add", 
            "Endpoint": "demisto-PC", 
            "CommandID": "B173598AD071467E89B4474A54FC86DE"
        }
}
```
##### Human Readable Output
![screen shot 2019-02-03 at 20 44 13](https://user-images.githubusercontent.com/44666568/52180931-9b266900-27f4-11e9-92f8-7ecc62c89e21.png)
### sep-scan-endpoint <a name="scan"><\a>
---
Scans an endpoint.
##### Base Command
`sep-scan-endpoint`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | IP or Hostname of the endpoint | Required | 
| scanType | Type of scan. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SEPM.Scan.CommandID | string | ID of the invoked command | 
| SEPM.Scan.Type | string | Type of the scan (ScanNow_Quick, ScanNow_Full or ScanNow_Custom) | 
| SEPM.Scan.Endpoint | Unknown | The endpoint identifier (IP or Host Name) | 
##### Command Example
`sep-scan-endpoint endpoint=demisto-PC scanType=ScanNow_Quick`
##### Context Example
```
{
    "SEPM": {
        "Scan": {
            "Endpoint": "demisto-PC", 
            "Type": "ScanNow_Quick", 
            "CommandID": "4DAAA323B5284399AC4790A24A5E477F"
        }
    }
}
```
##### Human Readable Output
![screen shot 2019-02-03 at 21 25 22](https://user-images.githubusercontent.com/44666568/52181420-3bcb5780-27fa-11e9-85aa-323915e46420.png)
