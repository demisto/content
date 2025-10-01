A polling wrapper script; retrieves machines that have communicated with Microsoft Defender for Endpoint cloud. At least one of the following arguments is required: IP, hostname, or ID. Otherwise, an error appears.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| id | The endpoint ID. |
| ip | The endpoint IP address. |
| hostname | The endpoint hostname. |
| ran_once_flag | Flag for the rate limit retry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.ID | The endpoint's identifier. | String |
| Endpoint.Hostname | The hostname of the endpoint. | String |
| Endpoint.OS | The endpoint's operating system. | String |
| Endpoint.OSVersion | The endpoint's operating system's version. | String |
| Endpoint.IPAddress | The endpoint's IP address. | String |
| Endpoint.Status | The health status of the endpoint. | String |
| Endpoint.MACAddress | The endpoint's MAC address. | String |
| Endpoint.Vendor | The integration name of the endpoint vendor. | String |
| MicrosoftATP.Machine.ID | The machine ID. | String |
| MicrosoftATP.Machine.ComputerDNSName | The machine DNS name. | String |
| MicrosoftATP.Machine.FirstSeen | The first date and time the machine was observed by Microsoft Defender ATP. | Date |
| MicrosoftATP.Machine.LastSeen | The last date and time the machine was observed by Microsoft Defender ATP. | Date |
| MicrosoftATP.Machine.OSPlatform | The operating system platform. | String |
| MicrosoftATP.Machine.OSVersion | The operating system version. | String |
| MicrosoftATP.Machine.OSProcessor | The operating system processor. | String |
| MicrosoftATP.Machine.LastIPAddress | The last IP on the machine. | String |
| MicrosoftATP.Machine.LastExternalIPAddress | The last machine IP to access the internet. | String |
| MicrosoftATP.Machine.OSBuild | The operating system build number. | Number |
| MicrosoftATP.Machine.HealthStatus | The machine health status. | String |
| MicrosoftATP.Machine.RBACGroupID | The machine RBAC group ID. | Number |
| MicrosoftATP.Machine.RBACGroupName | The machine RBAC group name. | String |
| MicrosoftATP.Machine.RiskScore | The machine risk score. | String |
| MicrosoftATP.Machine.ExposureLevel | The machine exposure score. | String |
| MicrosoftATP.Machine.IsAADJoined | Whether the machine is AAD joined. | Boolean |
| MicrosoftATP.Machine.AADDeviceID | The AAD Device ID. | String |
| MicrosoftATP.Machine.MachineTags | The set of machine tags. | String |
| MicrosoftATP.Machine.IPAddresses.ipAddress | The machine IP address. | String |
| MicrosoftATP.Machine.IPAddresses.MACAddress | The machine MAC address. | String |
| MicrosoftATP.Machine.IPAddresses.operationalStatus | The machine operational status. | String |
| MicrosoftATP.Machine.IPAddresses.type | The machine IP address type. | String |
| MicrosoftATP.Machine.AgentVersion | The machine Agent version. | String |
