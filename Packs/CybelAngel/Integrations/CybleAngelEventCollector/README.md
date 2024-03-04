CybleAngel Event Collector collects reports from Cyble Angel platform which specializes in external attack surface protection and management.

## Configure CybleAngel Event Collector On XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for CybleAngel Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Client ID | True |
    | Client Secret | True |
    | The maximum number of events per fetch | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cybleangel-get-events

***
Collect reports from cyble angel, used mainly for debugging.

#### Base Command

`cybleangel-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Get reports from a specific start date. | Required | 
| end_date | Get reports until a specific end date. | Required | 

#### Context Output

There is no context output for this command.
