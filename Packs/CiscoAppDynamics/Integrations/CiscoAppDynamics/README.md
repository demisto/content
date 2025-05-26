AppDynamics enables you to automate incident management, gain real-time performance metrics, and optimize applications to meet business needs moment to moment. No other solution offers application modernization, cloud and hybrid monitoring, and application security with business context.

## API Clients:

To create API clients, you are required to be assigned to the role of an **Account Owner or an Administer**. You can view the API Client settings in the Settings > Administration page of the Controller.

## How to Create API Clients:

You can create new API Client identity types that can be used to generate OAuth tokens.

1. Log in to the Controller UI as an Account Owner or other roles with the Administer users, groups, roles ... permission.
2. Click  > Administration.
3. Click the API Clients tab to view the list of existing clients.
4. Click + Create.
5. Enter the Client Name and Description.
6. Click Generate Secret to populate the Client Secret. 
7. This will generate a UUID as the secret of the API Client. 
8. Set the Default API-generated Token Expiration. This expiration only applies to authentication tokens generated through the /controller/api/oauth/access_token REST API, not to Temporary Access Tokens generated from the UI. See Using the Access Token.
9. Add the Roles you would like to associate with this API Client. You can add or remove roles at any time. 
10. Click Save at the top right.


## Configure Cisco AppDynamics on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco AppDynamics.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                | **Required** |
    | Server URL                                                   | True         |
    | Client ID                                                    | True         |
    | Client Secret                                                | True         |
    | Application ID                                               | True         |
    | Fetch Events                                                 | False        |
    | Event types to fetch (Multi-select list)                     | False        |
    | Trust any certificate (not secure)                           | False        |
    | Use system proxy settings                                    | False        |
    | The maximum number of Audit History API per fetch            | False        |
    | The maximum number of Healthrule Violations Events per fetch | False        |

4. Click **Test** to validate the URLs, credentials, and connection.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-appdynamics-get-events

***
Retrieves a list of events from the cisappdynamics instance.

#### Base Command

`cisco-appdynamics-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise it will only display them. Possible values are: True, False. | Required | 
| limit | The maximum number of events to fetch. Default is 1000. | Optional | 
| events_type_to_fetch | Which events to fetch. Possible values are: Audit, Healthrule Violations Events. Default is Audit,Healthrule Violations Events. | Optional | 
| start_date | The starting date from which events should be fetched. The date should be in the format "YYYY-MM-DDTHH:MM:SS". Example: 2025-01-01T11:27:08. | Optional | 
| end_date | The date up to which events should be fetched. The date should be in the format "YYYY-MM-DDTHH:MM:SS". Example: 2025-01-01T11:27:08. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAppDynamics | List | The list of events. | 
