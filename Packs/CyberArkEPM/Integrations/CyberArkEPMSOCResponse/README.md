Use the CyberArk EPM integration to activate and deactivate CyberArk EPM risk plans for specific endpoints.
This integration was integrated and tested with version xx of CyberArkEPMSOCResponse.

## Configure CyberArk EPM SOC Response (Beta) in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| EPM Logon URL | Example: https://login.epm.cyberark.com | True |
| Username |  | True |
| Password |  | True |
| Application ID | Required for local\(EPM\) authentication only. For more information on how to get the application ID, see https://docs.cyberark.com/Idaptive/Latest/en/Content/Applications/AppsOvw/SpecifyAppID.htm\#%23SpecifytheApplicationID | False |

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
| external_ip | The external IP address of the endpoint. | Optional |

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
| external_ip | The external IP address of the endpoint. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkEPMSOCResponse.EndpointIDs | String | The IDs of the endpoints removed from risk plan. |
