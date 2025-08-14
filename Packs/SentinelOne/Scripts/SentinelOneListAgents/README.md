This script is used to wrap the list-agents command in SentinelOne v2. Returns all agents that match the specified criteria.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |

## Dependencies

---
This script uses the following commands and scripts.

* sentinelone-list-agents

## Inputs

---

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname by which to filter the results. It can match a partial computer name value (substring). | Optional |
| scan_status | A comma-separated list of scan statuses by which to filter the results, for example: "started,aborted". Possible values are: started, none, finished, aborted. | Optional |
| os_type | Included operating system types, for example: "windows". Possible values are: windows, windows_legacy, macos, linux. | Optional |
| created_at | Endpoint creation timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional |
| min_active_threats | Minimum number of threats per agent. | Optional |
| limit | The maximum number of agents to return. Default is 10. | Optional |
| agent_ip | The agent IP address. | Optional |

## Outputs

---

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agents.NetworkStatus | string | The agent network status. |
| SentinelOne.Agents.ID | string | The agent ID. |
| SentinelOne.Agents.AgentVersion | string | The agent software version. |
| SentinelOne.Agents.IsDecommissioned | boolean | Whether the agent is decommissioned. |
| SentinelOne.Agents.IsActive | boolean | Whether the agent is active. |
| SentinelOne.Agents.LastActiveDate | date | When was the agent last active. |
| SentinelOne.Agents.RegisteredAt | date | The registration date of the agent. |
| SentinelOne.Agents.ExternalIP | string | The agent IP address. |
| SentinelOne.Agents.ThreatCount | number | Number of active threats. |
| SentinelOne.Agents.EncryptedApplications | boolean | Whether disk encryption is enabled. |
| SentinelOne.Agents.OSName | string | Name of operating system. |
| SentinelOne.Agents.ComputerName | string | Name of agent computer. |
| SentinelOne.Agents.MachineType | string | Machine type. |
| SentinelOne.Agents.Domain | string | Domain name of the agent. |
| SentinelOne.Agents.CreatedAt | date | Creation time of the agent. |
| SentinelOne.Agents.SiteName | string | Site name associated with the agent. |
| SentinelOne.Agents.Tags | unknown | Tags associated with the agent. |
