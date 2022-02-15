Enriches an endpoint by hostname using one or more integrations.

Supported integrations:
- Active Directory Query v2
- McAfee ePolicy Orchestrator
- McAfee ePolicy Orchestrator v2
- Carbon Black Enterprise Response v2
- Cylance Protect v2
- CrowdStrike Falcon Host
- ExtraHop Reveal(x)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Endpoint Enrichment - Cylance Protect v2

### Integrations
* epo
* carbonblack-v2
* Active Directory Query v2

### Scripts
* Exists

### Commands
* epo-find-system
* extrahop-device-search
* cb-sensor-info
* ad-get-computer
* cs-device-details
* cs-device-search


## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Hostname | The hostname of the endpoint to enrich. | Hostname | Endpoint | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The endpoint object of the endpoint that was enriched. | unknown |
| Endpoint.Hostname | The hostnames of the endpoints that were enriched. | string |
| Endpoint.OS | The operating systems running on the endpoints that were enriched. | string |
| Endpoint.IP | A list of the IP addresses of the endpoints. | unknown |
| Endpoint.MAC | A list of the MAC addresses of the endpoints that were enriched. | unknown |
| Endpoint.Domain | The domain names of the endpoints that were enriched. | string |
| CylanceProtectDevice | The device information about the hostname that was enriched using Cylance Protect v2. | unknown |
| ExtraHop.Device.Macaddr | The MAC Address of the device. | String |
| ExtraHop.Device.DeviceClass | The class of the device. | String |
| ExtraHop.Device.UserModTime | The time of the most recent update, expressed in milliseconds since the epoch. | Number |
| ExtraHop.Device.AutoRole | The role automatically detected by the ExtraHop. | String |
| ExtraHop.Device.ParentId | The ID of the parent device. | Number |
| ExtraHop.Device.Vendor | The device vendor. | String |
| ExtraHop.Device.Analysis | The level of analysis preformed on the device. | string |
| ExtraHop.Device.DiscoveryId | The UUID given by the Discover appliance. | String |
| ExtraHop.Device.DefaultName | The default name of the device. | String |
| ExtraHop.Device.DisplayName | The display name of device. | String |
| ExtraHop.Device.OnWatchlist | Whether the device is on the advanced analysis allow list. | Boolean |
| ExtraHop.Device.ModTime | The time of the most recent update, expressed in milliseconds since the epoch. | Number |
| ExtraHop.Device.IsL3 | Indicates whether the device is a Layer 3 device. | Boolean |
| ExtraHop.Device.Role | The role of the device. | String |
| ExtraHop.Device.DiscoverTime | The time that the device was discovered. | Number |
| ExtraHop.Device.Id | The ID of the device. | Number |
| ExtraHop.Device.Ipaddr4 | The IPv4 address of the device. | String |
| ExtraHop.Device.Vlanid | The ID of VLan. | Number |
| ExtraHop.Device.Ipaddr6 | The IPv6 address of the device. | string |
| ExtraHop.Device.NodeId | The Node ID of the Discover appliance. | number |
| ExtraHop.Device.Description | A user customizable description of the device. | string |
| ExtraHop.Device.DnsName | The DNS name associated with the device. | string |
| ExtraHop.Device.DhcpName | The DHCP name associated with the device. | string |
| ExtraHop.Device.CdpName | The Cisco Discovery Protocol name associated with the device. | string |
| ExtraHop.Device.NetbiosName | The NetBIOS name associated with the device. | string |
| ExtraHop.Device.Url | Link to the device details page in ExtraHop. | string |

## Playbook Image
---
![Endpoint_Enrichment_Generic_v2.1](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Endpoint_Enrichment_Generic_v2.1.png)
