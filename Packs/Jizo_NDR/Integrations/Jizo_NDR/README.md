This integration ensures interaction with the JizoM API.

## Configure Jizo NDR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Jizo
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | username/password| True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
   

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jizo-device-alerts-get
***
Get jizo device alerts

#### Base Command

`jizo-device-alerts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src |  ip address of source machine | Optional| 
| ip_dest | ip address of destination machine | Optional | 
| port_src | port of source machine| Optional | 
| port_dest | port of destination machine | Optional | 
| probe_name | name of the probe | Optional | 
| port | port | Optional | 
| datetime_from| default -7 days from the current datetime | Optional |
| datetime_to | default now | Optional |
| timestamp | timestamp| Optional |
| page | page number (pagination) | Optional |
| limit | maximum number of samples to display per alert | Optional |

#### Context Output

There is no context output for this command.
