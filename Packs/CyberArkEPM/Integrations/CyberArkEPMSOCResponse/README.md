Use the CyberArk EPM integration to activate and deactivate CyberArk EPM risk plans for specific endpoints.
This integration was integrated and tested with the CyberArk EPM API.

## Configure CyberArk EPM SOC Response in Cortex

| **Parameter** | **Description**                                                                                   | **Required** |
| --- |---------------------------------------------------------------------------------------------------| --- |
| EPM Region-based tenant URL | The tenant URL for EPM region \(e.g., https://api-na.epm.cyberark.cloud\).                        | True |
| Identity URL | The CyberArk Identity FQDN for OAuth2 authentication \(e.g., https://abc1234.id.cyberark.cloud\). | True |
| Web App ID | The Application ID of the OAuth2 Server web app configured in Identity Administration.            | True |
| Client ID | Service username \(configured as OAuth confidential client\).                                     | True |
| Client Secret | Service user password for OAuth2 authentication.                                                  | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberarkepm-activate-risk-plan

***
Activates a CyberArk EPM risk plan for a specified endpoint.

#### Base Command

`cyberarkepm-activate-risk-plan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risk_plan | The name of the risk plan to activate. | Required |
| endpoint_name | The name of the endpoint to target. | Required |
| logged_in_user | The logged-in username of the endpoint. | Optional |
| external_ip | (Deprecated) The external IP address of the endpoint. This argument is deprecated and no longer used. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkEPMSOCResponse.EndpointIDs | String | The IDs of the endpoints added to the risk plan. |
| CyberArkEPMSOCResponse.RiskPlan | String | The name of activated risk plan. |
| CyberArkEPMSOCResponse.Action | String | The action performed on the risk plan \(add/remove\). |

### cyberarkepm-deactivate-risk-plan

***
Deactivates a CyberArk EPM risk plan for a specified endpoint.

#### Base Command

`cyberarkepm-deactivate-risk-plan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risk_plan | The name of the risk plan to deactivate. | Required |
| endpoint_name | The name of the endpoint to target. | Required |
| logged_in_user | The logged-in username of the endpoint. | Optional |
| external_ip | (Deprecated) The external IP address of the endpoint. This argument is deprecated and no longer used. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkEPMSOCResponse.EndpointIDs | String | The IDs of the endpoints removed from risk plan. |
