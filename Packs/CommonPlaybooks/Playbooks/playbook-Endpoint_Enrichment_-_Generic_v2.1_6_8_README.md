Enrich an endpoint by hostname using one or more integrations.
Supported integrations:
- Active Directory Query v2
- McAfee ePO v2
- VMware Carbon Black EDR v2
- Cylance Protect v2
- CrowdStrike Falcon
- ExtraHop Reveal(x)
- Cortex XDR (endpoint enrichment and reputation)
- Endpoint reputation using !endpoint command

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Endpoint Enrichment - Cylance Protect v2

### Integrations

This playbook does not use any integrations.

### Scripts

* Exists

### Commands

* ad-get-computer
* epo-find-system
* endpoint
* extrahop-devices-search
* xdr-get-endpoints
* cs-falcon-search-device
* cb-edr-sensors-list
* xdr-list-risky-hosts

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname of the endpoint to enrich. | Endpoint.Hostname | Optional |
| UseReputationCommand | Define if you would like to use the \!endpoint command.<br/>Note: This input should be used whenever there is no auto-extract enabled in the investigation flow.<br/>Possible values: True / False. | False | Required |
| IPAddress | The IP address of the endpoint to enrich. |  | Optional |
| EndpointID | The endpoint ID of the endpoint to enrich. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The endpoint object of the endpoint that was enriched. | string |
| Endpoint.Hostname | The hostnames of the endpoints that were enriched. | string |
| Endpoint.OS | The operating systems running on the endpoints that were enriched. | string |
| Endpoint.IP | A list of the IP addresses of the endpoints. | string |
| Endpoint.MAC | A list of the MAC addresses of the endpoints that were enriched. | string |
| Endpoint.Domain | The domain names of the endpoints that were enriched. | string |
| CylanceProtectDevice | The device information about the hostname that was enriched using Cylance Protect v2. | string |
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
| Endpoint.IPAddress | The endpoint IP address. | string |
| Endpoint.ID | The endpoint ID. | string |
| Endpoint.Status | The endpoint status. | string |
| Endpoint.IsIsolated | The endpoint isolation status. | string |
| Endpoint.MACAddress | The endpoint MAC address. | string |
| Endpoint.Vendor | The integration name of the endpoint vendor. | string |
| Endpoint.Relationships | The endpoint relationships of the endpoint that was enriched. | string |
| Endpoint.Processor | The model of the processor. | string |
| Endpoint.Processors | The number of processors. | string |
| Endpoint.Memory | Memory on this endpoint. | string |
| Endpoint.Model | The model of the machine or device. | string |
| Endpoint.BIOSVersion | The endpoint's BIOS version. | string |
| Endpoint.OSVersion | The endpoint's operation system version. | string |
| Endpoint.DHCPServer | The DHCP server of the endpoint. | string |
| McAfee.ePO.Endpoint | The endpoint that was enriched. | string |
| Endpoint.Groups | Groups for which the computer is listed as a member. | string |
| ActiveDirectory.ComputersPageCookie | An opaque string received in a paged search, used for requesting subsequent entries. | string |
| ActiveDirectory.Computers.dn | The computer distinguished name. | string |
| ActiveDirectory.Computers.memberOf | Groups for which the computer is listed. | string |
| ActiveDirectory.Computers.name | The computer name. | string |
| CrowdStrike.Device | The information about  the endpoint. | string |
| ActiveDirectory.Computers | The information about the hostname that was enriched using Active Directory. | string |
| CarbonBlackEDR.Sensor.systemvolume_total_size | The size, in bytes, of the system volume of the endpoint on which the sensor is installed. installed. | number |
| CarbonBlackEDR.Sensor.emet_telemetry_path | The path of the EMET telemetry associated with the sensor. | string |
| CarbonBlackEDR.Sensor.os_environment_display_string | Human-readable string of the installed OS. | string |
| CarbonBlackEDR.Sensor.emet_version | The EMET version associated with the sensor. | string |
| CarbonBlackEDR.Sensor.emet_dump_flags | The flags of the EMET dump associated with the sensor. | string |
| CarbonBlackEDR.Sensor.clock_delta | The clock delta associated with the sensor. | string |
| CarbonBlackEDR.Sensor.supports_cblr | Whether the sensor supports Carbon Black Live Response \(CbLR\). | string |
| CarbonBlackEDR.Sensor.sensor_uptime | The uptime of the process. | string |
| CarbonBlackEDR.Sensor.last_update | When the sensor was last updated. | string |
| CarbonBlackEDR.Sensor.physical_memory_size | The size in bytes of physical memory. | number |
| CarbonBlackEDR.Sensor.build_id | The sensor version installed on this endpoint. From the /api/builds/ endpoint. | string |
| CarbonBlackEDR.Sensor.uptime | Endpoint uptime in seconds. | string |
| CarbonBlackEDR.Sensor.is_isolating | Boolean representing sensor-reported isolation status. | boolean |
| CarbonBlackEDR.Sensor.event_log_flush_time | If event_log_flush_time is set, the server will instruct the sensor to immediately<br/>send all data before this date, ignoring all other throttling mechanisms.<br/>To force a host current, set this value to a value far in the future.<br/>When the sensor has finished sending its queued data, this value will be null. | string |
| CarbonBlackEDR.Sensor.computer_dns_name | The DNS name of the endpoint on which the sensor is installed. | string |
| CarbonBlackEDR.Sensor.emet_report_setting | The report setting of the EMET associated with the sensor. | string |
| CarbonBlackEDR.Sensor.id | The ID of this sensor. | string |
| CarbonBlackEDR.Sensor.emet_process_count | The number of EMET processes associated with the sensor. | string |
| CarbonBlackEDR.Sensor.emet_is_gpo | Whether the EMET is a GPO. | string |
| CarbonBlackEDR.Sensor.power_state | The sensor power state. | string |
| CarbonBlackEDR.Sensor.network_isolation_enabled | Boolean representing the network isolation request status. | boolean |
| CarbonBlackEDR.Sensor.systemvolume_free_size | The amount of free bytes on the system volume. | string |
| CarbonBlackEDR.Sensor.status | The sensor status. | string |
| CarbonBlackEDR.Sensor.num_eventlog_bytes | The number of event log bytes. | number |
| CarbonBlackEDR.Sensor.sensor_health_message | Human-readable string indicating the sensor’s self-reported status. | string |
| CarbonBlackEDR.Sensor.build_version_string | Human-readable string of the sensor version. | string |
| CarbonBlackEDR.Sensor.computer_sid | Machine SID of this host. | string |
| CarbonBlackEDR.Sensor.next_checkin_time | Next expected communication from this computer in server-local time and zone. | string |
| CarbonBlackEDR.Sensor.node_id | The node ID associated with the sensor. | string |
| CarbonBlackEDR.Sensor.cookie | The cookie associated with the sensor. | string |
| CarbonBlackEDR.Sensor.emet_exploit_action | The EMET exploit action associated with the sensor. | string |
| CarbonBlackEDR.Sensor.computer_name | NetBIOS name of this computer. | string |
| CarbonBlackEDR.Sensor.license_expiration | When the license of the sensor expires. | string |
| CarbonBlackEDR.Sensor.supports_isolation | Whether the sensor supports isolation. | string |
| CarbonBlackEDR.Sensor.parity_host_id | The ID of the parity host associated with the sensor. | string |
| CarbonBlackEDR.Sensor.supports_2nd_gen_modloads | Whether the sensor support modload of 2nd generation. | string |
| CarbonBlackEDR.Sensor.network_adapters | A pipe-delimited list of IP,MAC pairs for each network interface. | string |
| CarbonBlackEDR.Sensor.sensor_health_status | Self-reported health score, from 0 to 100. Higher numbers indicate a better health status. | string |
| CarbonBlackEDR.Sensor.registration_time | Time this sensor was originally registered in server-local time and zone. | string |
| CarbonBlackEDR.Sensor.restart_queued | Whether a restart of the sensor is queued. | string |
| CarbonBlackEDR.Sensor.notes | The notes associated with the sensor. | string |
| CarbonBlackEDR.Sensor.num_storefiles_bytes | Number of storefiles bytes associated with the sensor. | string |
| CarbonBlackEDR.Sensor.os_environment_id | The ID of the OS environment of the sensor. | string |
| CarbonBlackEDR.Sensor.shard_id | The ID of the shard associated with the sensor. | string |
| CarbonBlackEDR.Sensor.boot_id | A sequential counter of boots since the sensor was installed. | string |
| CarbonBlackEDR.Sensor.last_checkin_time | Last communication with this computer in server-local time and zone. | string |
| CarbonBlackEDR.Sensor.os_type | The operating system type of the computer. | string |
| CarbonBlackEDR.Sensor.group_id | The sensor group ID this sensor is assigned to. | string |
| CarbonBlackEDR.Sensor.uninstall | When set, indicates that the sensor will be directed to uninstall on next check-in. | string |
| PaloAltoNetworksXDR.Endpoint | The endpoint object of the endpoint that was enriched. | string |
| PaloAltoNetworksXDR.Endpoint.endpoint_id | The endpoint ID. | string |
| PaloAltoNetworksXDR.Endpoint.endpoint_name | The endpoint name. | string |
| PaloAltoNetworksXDR.Endpoint.endpoint_type | The endpoint type. | string |
| PaloAltoNetworksXDR.Endpoint.endpoint_status | The status of the endpoint. | string |
| PaloAltoNetworksXDR.Endpoint.os_type | The endpoint OS type. | string |
| PaloAltoNetworksXDR.Endpoint.ip | A list of IP addresses. | string |
| PaloAltoNetworksXDR.Endpoint.users | A list of users. | string |
| PaloAltoNetworksXDR.Endpoint.domain | The endpoint domain. | string |
| PaloAltoNetworksXDR.Endpoint.alias | The endpoint's aliases. | string |
| PaloAltoNetworksXDR.Endpoint.first_seen | First seen date/time in Epoch \(milliseconds\). | string |
| PaloAltoNetworksXDR.Endpoint.last_seen | Last seen date/time in Epoch \(milliseconds\). | string |
| PaloAltoNetworksXDR.Endpoint.content_version | Content version. | string |
| PaloAltoNetworksXDR.Endpoint.installation_package | Installation package. | string |
| PaloAltoNetworksXDR.Endpoint.active_directory | Active directory. | string |
| PaloAltoNetworksXDR.Endpoint.install_date | Install date in Epoch \(milliseconds\). | string |
| PaloAltoNetworksXDR.Endpoint.endpoint_version | Endpoint version. | string |
| PaloAltoNetworksXDR.Endpoint.is_isolated | Whether the endpoint is isolated. | string |
| PaloAltoNetworksXDR.Endpoint.group_name | The name of the group to which the endpoint belongs. | string |
| PaloAltoNetworksXDR.Endpoint.count | Number of endpoints returned. | number |
| Account | The account object of the endpoint that was enriched. | string |
| Account.Username | The username in the relevant system. | string |
| Account.Domain | The domain of the account. | string |
| PaloAltoNetworksXDR.RiskyHost | The endpoint object. | string |
| PaloAltoNetworksXDR.RiskyHost.type | Form of identification element. | string |
| PaloAltoNetworksXDR.RiskyHost.id | Identification value of the type field. | string |
| PaloAltoNetworksXDR.RiskyHost.score | The score assigned to the host. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons | The endpoint risk objects. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.date created | Date when the incident was created. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.description | Description of the incident. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.severity | The severity of the incident | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.status | The incident status | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.points | The score. | string |

## Playbook Image

---

![Endpoint Enrichment - Generic v2.1](../doc_files/Endpoint_Enrichment_-_Generic_v2.1.png)
