## CyberArk EPM ARR Help

This integration allows you to automate risk plan management in CyberArk Endpoint Privilege Manager (EPM) by adding and removing endpoints from specified risk plans.

## Configure CyberArk EPM ARR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberArk EPM ARR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                                        |
    | --- |----------------------------------------------------------------------------------------|
    | Server URL | The Login URL of CyberArk EPM service.                                                 |
    | Credentials | The username and password for authentication.                                          |
    | Application ID | The Application ID for the integration. If not provided, `CyberArkXSOAR` will be used. |
    | Trust any certificate (not secure) | Select this option to trust self-signed certificates.                                  |
    | Use system proxy settings | Select this option to use the system's proxy settings.                                 |

4. Click **Test** to validate the URLs, credentials, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberarkepm-activate-risk-plan

Activates a risk plan for a specified endpoint.

#### Base Command

`cyberarkepm-activate-risk-plan`

#### Input

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| risk_plan | The name of the risk plan to activate. | Required |
| endpoint_name | The name of the endpoint to target. | Required |
| external_ip | The external IP address of the endpoint. | Required |

#### Context Output

| **Path**                    | **Type** | **Description**                                 |
|-----------------------------| --- |-------------------------------------------------|
| CyberArkEPMARR.Endpoint.IDs | String | The IDs of the endpoint added to the risk plan. |
| CyberArkEPMARR.Risk.Plan    | String | Name of Risk Plan endpoints were added to.      |

### cyberarkepm-deactivate-risk-plan

Deactivates a risk plan for a specified endpoint.

#### Base Command

`cyberarkepm-deactivate-risk-plan`

#### Input

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| risk_plan | The name of the risk plan to deactivate. | Required |
| endpoint_name | The name of the endpoint to target. | Required |
| external_ip | The external IP address of the endpoint. | Required |

#### Context Output

| **Path**                    | **Type** | **Description**                                     |
|-----------------------------| --- |-----------------------------------------------------|
| CyberArkEPMARR.Endpoint.IDs | String | The IDs of the endpoint removed from the risk plan. |
| CyberArkEPMARR.Risk.Plan    | String | Name of Risk Plan endpoints were removed from.      |