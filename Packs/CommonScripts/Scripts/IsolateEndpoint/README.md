This script isolates endpoints using multiple integrations and returns a success or failure message.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                                                                                         |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| agent_id | List of agent IDs of the endpoint to isolate.                                                                                                                                                                                                           |
| agent_ip | List of agent IPs of the endpoint to isolate.                                                                                                                                                                                                           |
| agent_hostname | List of agent hostnames of the endpoint to isolate.                                                                                                                                                                                                     |
| force | Should the isolate be force.                                                                                                                                                                                                                            |
| brands | Specify the integration brands to run the command for. If not provided, the command will run for all available integrations. For multi-select, provide a comma-separated list. For example: 'Active Directory Query v2, CrowdstrikeFalcon, ExtraHop v2'. |
| verbose | Set to true to display human-readable output for each step of the command. Set to false \(default\) to only display the final result.                                                                                                                   |
| server_os | List of servers to isolate, in addition to the predefined list.                                                                                                                                                                               |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsolateEndpointResults.EndpointName | The endpoint's hostname. | String |
| IsolateEndpointResults.Results | The results of the isolation. | Array |
| IsolateEndpointResults.Results.Result | The result of the isolation. | String |
| IsolateEndpointResults.Results.Brand | The used brand for the isolation. | String |
| IsolateEndpointResults.Results.Message | An informative message for the isolation results. | String |
