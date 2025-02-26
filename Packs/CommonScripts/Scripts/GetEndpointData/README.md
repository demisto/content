This script gathers endpoint data from multiple integrations and returns an endpoint entity with consolidated information to the context.

## Script Data

---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.10.0          |

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                                                                               |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| agent_id | List of agent IDs of the endpoint to retrieve.                                                                                                                                                                                                |
| agent_ip | List of agent IPs of the endpoint to retrieve.                                                                                                                                                                                                |
| agent_hostname | List of agent hostnames of the endpoint to retrieve.                                                                                                                                                                                          |
| verbose | Set to true to display human-readable output for each step of the command. Set to false \(default\) to only display the final result.                                                                                                         |

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
| Endpoint.Relationship.source | The vendor from which the relationship of this endpoint was retrieved. | String |
| Endpoint.EntityAType.value | The type of the source of the relationship. | String |
| Endpoint.EntityAType.source | The vendor from which the type of the source of the relationship of this endpoint was retrieved. | String |
| Endpoint.EntityBType.value | The type of the destination of the relationship. | String |
| Endpoint.EntityBType.source | The vendor from which the type of the destination of the relationship of this endpoint was retrieved. | String |
| Endpoint.ID.value | The endpoint's ID. | String |
| Endpoint.ID.source | The vendor from which the ID of this endpoint was retrieved. | String |
| Endpoint.IPAddress.value | The endpoint's IP address. | String |
| Endpoint.IPAddress.source | The vendor from which the IP address of this endpoint was retrieved. | String |
| Endpoint.Domain.value | The endpoint's domain. | String |
| Endpoint.Domain.source | The vendor from which the domain of this endpoint was retrieved. | String |
| Endpoint.MACAddress.value | The endpoint's MAC address. | String |
| Endpoint.MACAddress.source | The vendor from which the MAC address of this endpoint was retrieved. | String |
| Endpoint.DHCPServer.value | The DHCP server of the endpoint. | String |
| Endpoint.DHCPServer.source | The vendor from which the DHCP server of this endpoint was retrieved. | String |
| Endpoint.OS.value | The endpoint's operating system. | String |
| Endpoint.OS.source | The vendor from which the operating system of this endpoint was retrieved. | String |
| Endpoint.OSVersion.value | The endpoint's operating system version. | String |
| Endpoint.OSVersion.source | The vendor from which the operating system version of this endpoint was retrieved. | String |
| Endpoint.BIOSVersion.value | The endpoint's BIOS version. | String |
| Endpoint.BIOSVersion.source | The vendor from which the BIOS version of this endpoint was retrieved. | String |
| Endpoint.Model.value | The model of the machine or device. | String |
| Endpoint.Model.source | The vendor from which the model of this endpoint was retrieved. | String |
| Endpoint.Memory.value | Amount of memory on this endpoint. | Integer |
| Endpoint.Memory.source | The vendor from which the amount of memory of this endpoint was retrieved. | String |
| Endpoint.Processors.value | The number of processors. | Integer |
| Endpoint.Processors.source | The vendor from which the processors of this endpoint was retrieved. | String |
| Endpoint.Processor.value | The model of the processor. | String |
| Endpoint.Processor.source | The vendor from which the processor of this endpoint was retrieved. | String |
| Endpoint.IsIsolated.value | The endpoint's isolation status. | String |
| Endpoint.IsIsolated.source | The vendor from which the isolation of this endpoint was retrieved. | String |
| Endpoint.Status.value | The endpoint's status. | String |
| Endpoint.Status.source | The vendor from which the status of this endpoint was retrieved. | String |
| Endpoint.Vendor.value | The integration name of the endpoint vendor. | String |
| Endpoint.Vendor.source | The vendor from which the Vendor of this endpoint was retrieved. | String |
