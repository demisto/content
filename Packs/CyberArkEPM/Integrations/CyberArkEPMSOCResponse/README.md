This integration allows you to automate risk plan management in CyberArk Endpoint Privilege Manager (EPM) by adding and removing endpoints from specified risk plans.

## Configure CyberArk EPM SOC Response in Cortex

| **Parameter** | **Description**                                                                                                   | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------| --- |
| EPM Logon URL | Example: https://login.epm.cyberark.com.                                                                          | True |
| Username |                                                                                                                   | True |
| Password |                                                                                                                   | True |
| Application ID | Required for local\(EPM\) authentication only.                                                                    | False | 

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
| --- | --- |--------------|
| risk_plan | The name of the risk plan to activate. | True         |
| endpoint_name | The name of the endpoint to target. | True         |
| external_ip | The external IP address of the endpoint. | Fasle        |

#### Human Readable Output

### Risk Plan changed successfully
|Endpoint IDs|Risk Plan|Action|
|---|---|---|
| endpoint_id1 | HighRisk | add |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkEPMSOCResponse.Endpoint.ID | String | The ID of the endpoint added to the risk plan. |

### cyberarkepm-deactivate-risk-plan

***
Deactivates a CyberArk EPM risk plan for a specified endpoint.

#### Base Command

`cyberarkepm-deactivate-risk-plan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- |--------------|
| risk_plan | The name of the risk plan to deactivate. | True         |
| endpoint_name | The name of the endpoint to target. | True         |
| external_ip | The external IP address of the endpoint. | False        |

#### Human Readable Output

### Risk Plan changed successfully
|Endpoint IDs|Risk Plan|Action|
|---|---|---|
| endpoint_id1 | HighRisk | remove |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkEPMSOCResponse.Endpoint.ID | String | The ID of the endpoint removed from the risk plan. |
