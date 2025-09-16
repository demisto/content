This script isolates endpoints using multiple integrations and returns a success or failure message.
The isolation action can be executed using the next integrations:

- Cortex Core - IR
- CrowdstrikeFalcon
- FireEyeHX v2
- Microsoft Defender Advanced Threat Protection

## Script Data

---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.10.0          |

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                                                                             | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| endpoint_id | List of agent IDs of the endpoint to isolate. | False        |
| endpoint_ip | List of agent IPs of the endpoint to isolate. | False        |
| brands | Specify the integration brands to run the command for. If not provided, the command will run for all available integrations. For multi-select, provide a comma-separated list. For example: 'Active Directory Query v2, CrowdstrikeFalcon'. |

## Outputs

---

| **Path**                             | **Description**                                   | **Type** |
|--------------------------------------|---------------------------------------------------| --- |
| IsolateEndpointResults.Endpoint      | The endpoint's id, ip or hostname.                | String |
| IsolateEndpointResults.Result        | The result of the isolation.                      | String |
| IsolateEndpointResults.Brand   | The used brand for the isolation.                 | String |
| IsolateEndpointResults.Message | An informative message for the isolation results. | String |
