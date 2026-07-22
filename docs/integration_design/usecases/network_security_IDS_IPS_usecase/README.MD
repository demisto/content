# Network Security (IDS/IPS)
Top Use-Cases:
- [Get/Fetch alerts.](#query)
- [Get pcap file, packet.](#pcap)
- Get network logs filtered by time range, ip addresses, ports, etc.
- [Create/manage/delete policies and rules.](#policy)
- Update signatures from an online source / upload + Get last signature update information.
- [Install policy (if existing).](#assign-policy)

## Command Examples

`awake-query-devices` <a name="query">
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryExpression | A query expression in Awake Query Language | False | 
| startTime | Query start time ("2000-01-01T00:00:00Z") | True | 
| endTime | Query end time ("2000-01-01T00:00:00Z") | True | 
| ipAddress | IP address to filter by (exact match) | False | 
| deviceName | Device name to filter by (regular expression) | False | 
| domainName | Domain name to filter by (regular expression) | False | 
| protocol | Protocol to filter by (all uppercase, i.e. "TLS") | False | 
| tag | Tag to filter by (regular expression) | False | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AwakeSecurity.Devices.deviceId | string | Awake Security unique identifier for the specified device | 
| AwakeSecurity.Devices.deviceName | string | Device name | 
| AwakeSecurity.Devices.firstSeen | string | Date that the specified device was first seen | 
| AwakeSecurity.Devices.lastSeen | string | Date that the specified device was last seen | 
| AwakeSecurity.Devices.os | string | Operating system associated with the specified device | 
| AwakeSecurity.Devices.deviceType | string | Device type | 
| AwakeSecurity.Devices.ips | unknown | List of IP addresses associated with the specified device | 
| AwakeSecurity.Devices.monitoringPointIds | string | List of monitoring point IDs the specified device was seen on | 
| AwakeSecurity.Devices.application | string | List of applications the specified device was seen using | 
| AwakeSecurity.Devices.notabilityPercentile | number | How the notability of this device compares to other devices | 
| AwakeSecurity.Devices.numberSimilarDevices | number | Number of devices that are similar to this device | 
| AwakeSecurity.Devices.numberSessions | number | Number of TCP sessions for this device | 
| AwakeSecurity.Devices.ackTime | number | Date of the last TCP session acknowledgment of the device associated with the specified email address | 
| AwakeSecurity.Devices.whiteListed | bool | Is the device associated with the specified email address in the allow list | 
##### Command Example
!awake-query-devices startTime="2018-07-18T07:00:00Z" endTime="2018-07-18T07:30:00Z"
##### Human Readable Output
![screen shot 2018-11-27 at 15 47 31](https://user-images.githubusercontent.com/37335599/49085895-c96b5380-f25b-11e8-981f-49094d9f5995.png)
### awake-pcap-download <a name="pcap">
---
Download a PCAP
##### Base Command
`awake-pcap-download`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| protocol | Protocol to filter by (all uppercase, e.g., "TLS") | False | 
| hostA | First host's address | False | 
| portA | First host's port | False | 
| hostB | Second host's address | False | 
| portB | Second host's port | False | 
| startTime | Query start time ("2000-01-01T00:00:00Z") | False | 
| endTime | Query end time ("2000-01-01T00:00:00Z") | False | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size | 
| File.MD5 | string | MD5 of the file | 
| File.SHA1 | string | SHA-1 of the file | 
| File.SHA256 | string | SHA-256 of the file | 
| File.Name | string | File name | 
| File.SSDeep | string | SSDeep hash of the file | 
| File.EntryID | string | War room Entry ID of the file | 
| File.Info | string | File common metadata | 
| File.Type | string | File type | 
| File.Extension | string | File Extension e.g: "pcap" | 
##### Command Example
!awake-pcap-download hostA="10.200.103.100" hostB="10.200.103.100" portA="67" portB="68"
##### Human Readable Output
![screen shot 2018-11-27 at 15 51 46](https://user-images.githubusercontent.com/37335599/49086088-5e6e4c80-f25c-11e8-8166-377e45e63fee.png)
### Create an ANC policy <a name="ANC">
---
Creates an ANC policy.
##### Base Command
`cisco-ise-create-policy` <a name="policy">
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_actions | The actions of the policy. Can be "QUARANTINE", "PORTBOUNCE", or "SHUTDOWN". | Required | 
| policy_name | The name of the new adaptive network control policy. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoISE.Policy.Action | String | The actions of the ANC policy. | 
| CiscoISE.Policy.Name | String | The name of the new ANC policy. | 
##### Command Example
```!cisco-ise-create-policy policy_name=quarantinePolicy policy_actions=QUARANTINE```
##### Context Example
```
{
    "CiscoISE.Policy": {
        "Action": [
            "QUARANTINE"
        ], 
        "Name": "quarantinePolicy"
    }
}
```
##### Human Readable Output
The policy "quarantinePolicy" has been created successfully
### Assign an ANC policy to an endpoint
---
Assigns an Adapative Network Control policy to an endpoint.
##### Base Command
`cisco-ise-assign-policy` <a name="assign-policy">
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac_address | The MAC address to which to apply the policy.  | Required | 
| policy_name | The name of the policy to assign to the endpoint. | Required | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoISE.Endpoint.MACAddress | String | The MAC address of the endpoint. | 
| CiscoISE.Endpoint.PolicyName | String | The policy name that was applied to the endpoint. | 
##### Command Example
```!cisco-ise-assign-policy mac_address=50080fc0-a07a-11e8-808e-000c295fdd32 policy_name=policy3```
##### Human Readable Output
### The policy "policy3" has been applied successfully
