This script gathers endpoint data from multiple integrations and returns an Endpoint entity with consolidated information to the context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| agent_id | List of agent IDs of the agent to retrieve. |
| agent_ip | List of agent IPs of the agent to retrieve. |
| agent_hostname | List of agent hostnames of the agent to retrieve. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select provide a comma-separated list. For example: "SailPointIdentityNow,Active Directory Query v2,PingOne". |
| verbose | Whether to retrieve human readable entry for every command or only the final result. True means to retrieve human readable entry for every command. False means to human readable only for the final result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname.value | The endpoint's hostname. | String |
| Endpoint.Hostname.source | The vendor from which the hostname of this endpoint was retrieved. | String |
| Endpoint.EntityA.value | The source of the relationship. | String |
| Endpoint.EntityA.source | The vendor from which EntityA of this endpoint was retrieved. | String |
| Endpoint.EntityB.value | The destination of the relationship. | String |
| Endpoint.EntityB.source | The vendor from which EntityB of this endpoint was retrieved. | String |
| Endpoint.Relationship.value | The name of the relationship. | String |
| Endpoint.Relationship.source | The vendor from which the Relationship of this endpoint was retrieved. | String |
| Endpoint.EntityAType.value | The type of the source of the relationship. | String |
| Endpoint.EntityAType.source | The vendor from which the type of the source of the relationship of this endpoint was retrieved. | String |
| Endpoint.EntityBType.value | The type of the destination of the relationship. | String |
| Endpoint.EntityBType.source | The vendor from which the type of the destination of the relationship of this endpoint was retrieved. | String |
| Endpoint.ID.value | The endpoint's id. | String |
| Endpoint.ID.source | The vendor from which the id of this endpoint was retrieved. | String |
| Endpoint.IPAddress.value | The endpoint's ip address. | String |
| Endpoint.IPAddress.source | The vendor from which the ip address of this endpoint was retrieved. | String |
| Endpoint.Domain.value | The endpoint's domain. | String |
| Endpoint.Domain.source | The vendor from which the domain of this endpoint was retrieved. | String |
| Endpoint.MACAddress.value | The endpoint's MAC address. | String |
| Endpoint.MACAddress.source | The vendor from which the Mac address of this endpoint was retrieved. | String |
| Endpoint.DHCPServer.value | The DHCP server of the endpoint. | String |
| Endpoint.DHCPServer.source | The vendor from which the DHCP server of this endpoint was retrieved. | String |
| Endpoint.OS.value | The endpoint's operating system. | String |
| Endpoint.OS.source | The vendor from which the OS of this endpoint was retrieved. | String |
| Endpoint.OSVersion.value | The endpoint's operating system version. | String |
| Endpoint.OSVersion.source | The vendor from which the OSVersion of this endpoint was retrieved. | String |
| Endpoint.BIOSVersion.value | The endpoint's BIOS version. | String |
| Endpoint.BIOSVersion.source | The vendor from which the BIOSVersion of this endpoint was retrieved. | String |
| Endpoint.Model.value | The model of the machine or device. | String |
| Endpoint.Model.source | The vendor from which the Model of this endpoint was retrieved. | String |
| Endpoint.Memory.value | Amount of memory on this endpoint. | Integer |
| Endpoint.Memory.source | The vendor from which the amount of memory of this endpoint was retrieved. | String |
| Endpoint.Processors.value | The number of processors. | Integer |
| Endpoint.Processors.source | The vendor from which the Processors of this endpoint was retrieved. | String |
| Endpoint.Processor.value | The model of the processor. | String |
| Endpoint.Processor.source | The vendor from which the Processor of this endpoint was retrieved. | String |
| Endpoint.IsIsolated.value | The endpoint's isolation status. | String |
| Endpoint.IsIsolated.source | The vendor from which the IsIsolated of this endpoint was retrieved. | String |
| Endpoint.Status.value | The endpoint's status. | String |
| Endpoint.Status.source | The vendor from which the Status of this endpoint was retrieved. | String |
| Endpoint.Vendor.value | The integration name of the endpoint vendor. | String |
| Endpoint.Vendor.source | The vendor from which the Vendor of this endpoint was retrieved. | String |
