[Enter a comprehensive, yet concise, description of what the integration does, what use cases it is designed for, etc.]
This integration was integrated and tested with version xx of Neosec

## Configure Neosec on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Neosec.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key to use for connection | True |
    | URL |  | False |
    | Tenant Key |  | False |
    | Fetch alerts with status |  | False |
    | Fetch alerts with type |  | False |
    | Severity of alerts to fetch |  | False |
    | Max incident to fetch |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |
    | First fetch time |  | False |
    | De-tokenize alerts |  | False |
    | Neosec Node URL |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### neosec-alert-status-set
***
Set alert status(Open, Closed)


#### Base Command

`neosec-alert-status-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert id(UUID) in the Neosec platform. Possible values are: . | Required | 
| alert_status | The alert status, the options are "Open" or "Closed". Possible values are: Open, Closed. | Required | 


#### Context Output

There is no context output for this command.