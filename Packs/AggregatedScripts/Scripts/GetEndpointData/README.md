This script gathers endpoint data from multiple integrations and returns an endpoint entity with consolidated information to the context.

The following brands run by default:

- 'Active Directory Query v2'
- 'McAfee ePO v2'
- 'CrowdstrikeFalcon'
- 'Cortex XDR - IR'
- 'Cortex Core - IR'
- 'FireEyeHX v2'

**Note**:

If the *brands* argument is not provided to the script, all brands will be executed and the ***!endpoint*** command will run across all available brands.

If you provide specific brands, only those brands will be executed.
If you include additional brands not on the defaultlist, the predefined list of default brands and the ***!endpoint*** command will run only for those brands.

### Examples

**brands="Active Directory Query v2,FireEyeHX v2"** → the script will run the Active Directory Query v2 and the FireEyeHX v2 commands.

**brands="Microsoft Defender Advanced Threat Protection"** → the script will run !endpoint only with this brand.

**brands="Active Directory Query v2,FireEyeHX v2,Microsoft Defender Advanced Threat Protection"** → the script will run the Active Directory Query v2 command, the FireEyeHX v2 command and the !endpoint command with the Microsoft Defender Advanced Threat Protection brand.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| endpoint_id | List of endpoint IDs retrieve. |
| endpoint_ip | List of endpont IPs to retrieve. |
| endpoint_hostname | List of endpoint hostnames retrieve. |
| brands | Specify the integration brands to run the command for. If not provided, the command will run for all available integrations. For multi-select, provide a comma-separated list. For example: 'Active Directory Query v2'. |
| verbose | Set to true to display human-readable output for each step of the command. Set to false \(default\) to only display the final result. |
| additional_fields | When set to true, retrieves additional fields from every brand beyond standard endpoint data. Default is false. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EndpointData.Hostname.value | The endpoint's hostname. | String |
| EndpointData.Hostname.source | The vendor from which the hostname of this endpoint was retrieved. | String |
| EndpointData.EntityA.value | The source of the relationship. | String |
| EndpointData.EntityA.source | The vendor from which EntityA of this endpoint was retrieved. | String |
| EndpointData.EntityB.value | The destination of the relationship. | String |
| EndpointData.EntityB.source | The vendor from which EntityB of this endpoint was retrieved. | String |
| EndpointData.Relationship.value | The name of the relationship. | String |
| EndpointData.Relationship.source | The vendor from which the relationship of this endpoint was retrieved. | String |
| EndpointData.EntityAType.value | The type of the source of the relationship. | String |
| EndpointData.EntityAType.source | The vendor from which the type of the source of the relationship of this endpoint was retrieved. | String |
| EndpointData.EntityBType.value | The type of the destination of the relationship. | String |
| EndpointData.EntityBType.source | The vendor from which the type of the destination of the relationship of this endpoint was retrieved. | String |
| EndpointData.ID.value | The endpoint's ID. | String |
| EndpointData.ID.source | The vendor from which the ID of this endpoint was retrieved. | String |
| EndpointData.RiskLevel | The endpoint's risk level. | String |
| EndpointData.IPAddress.value | The endpoint's IP address. | String |
| EndpointData.IPAddress.source | The vendor from which the IP address of this endpoint was retrieved. | String |
| EndpointData.Domain.value | The endpoint's domain. | String |
| EndpointData.Domain.source | The vendor from which the domain of this endpoint was retrieved. | String |
| EndpointData.MACAddress.value | The endpoint's MAC address. | String |
| EndpointData.MACAddress.source | The vendor from which the MAC address of this endpoint was retrieved. | String |
| EndpointData.DHCPServer.value | The DHCP server of the EndpointData. | String |
| EndpointData.DHCPServer.source | The vendor from which the DHCP server of this endpoint was retrieved. | String |
| EndpointData.OS.value | The endpoint's operating system. | String |
| EndpointData.OS.source | The vendor from which the operating system of this endpoint was retrieved. | String |
| EndpointData.OSVersion.value | The endpoint's operating system version. | String |
| EndpointData.OSVersion.source | The vendor from which the operating system version of this endpoint was retrieved. | String |
| EndpointData.BIOSVersion.value | The endpoint's BIOS version. | String |
| EndpointData.BIOSVersion.source | The vendor from which the BIOS version of this endpoint was retrieved. | String |
| EndpointData.Model.value | The model of the machine or device. | String |
| EndpointData.Model.source | The vendor from which the model of this endpoint was retrieved. | String |
| EndpointData.Memory.value | Amount of memory on this EndpointData. | Integer |
| EndpointData.Memory.source | The vendor from which the amount of memory of this endpoint was retrieved. | String |
| EndpointData.Processors.value | The number of processors. | Integer |
| EndpointData.Processors.source | The vendor from which the processors of this endpoint was retrieved. | String |
| EndpointData.Processor.value | The model of the processor. | String |
| EndpointData.Processor.source | The vendor from which the processor of this endpoint was retrieved. | String |
| EndpointData.IsIsolated.value | The endpoint's isolation status. | String |
| EndpointData.IsIsolated.source | The vendor from which the isolation of this endpoint was retrieved. | String |
| EndpointData.Status.value | The endpoint's status. | String |
| EndpointData.Status.source | The vendor from which the status of this endpoint was retrieved. | String |
| EndpointData.Vendor.value | The integration name of the endpoint vendor. | String |
| EndpointData.Vendor.source | The vendor from which the Vendor of this endpoint was retrieved. | String |
