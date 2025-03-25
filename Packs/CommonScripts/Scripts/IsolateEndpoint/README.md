This script isolates endpoints using multiple integrations and returns a success or failure message.
The isolation action can be executed using the next integrations:
  - Cortex Core - IR
  - Cybereason
  - Cortex XDR - IR
  - CrowdstrikeFalcon
  - FireEyeHX v2
  - VMware Carbon Black EDR v2
  - Microsoft Defender Advanced Threat Protection

## Script Data

---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.10.0          |

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                                                                                        |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| agent_id | List of agent IDs of the endpoint to isolate.                                                                                                                                                                                                          |
| agent_ip | List of agent IPs of the endpoint to isolate.                                                                                                                                                                                                          |
| agent_hostname | List of agent hostnames of the endpoint to isolate.                                                                                                                                                                                                    |
| brands | Specify the integration brands to run the command for. If not provided, the command will run for all available integrations. For multi-select, provide a comma-separated list. For example: 'Active Directory Query v2, CrowdstrikeFalcon'. |
| verbose | Set to true to display human-readable output for each step of the command. Set to false \(default\) to only display the final result.                                                                                                                  |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsolateEndpointResults.EndpointName | The endpoint's hostname. | String |
| IsolateEndpointResults.Results | The results of the isolation. | Array |
| IsolateEndpointResults.Results.Result | The result of the isolation. | String |
| IsolateEndpointResults.Results.Brand | The used brand for the isolation. | String |
| IsolateEndpointResults.Results.Message | An informative message for the isolation results. | String |
