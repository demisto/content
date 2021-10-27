The penfield-api-call command takes in necessary context data, and returns the analyst that Penfield believes the incident should be assigned to based on Penfield's models of skill and process. The test command verfies that the endpoint is reachable.
This integration was integrated and tested with version xx of Penfield

## Configure Penfield on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Penfield.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
    | Use system proxy settings | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### penfield-get-assignee
***
Calls the Penfield API and returns the analyst Penfield recommends assigning the incident to. This information is saved in the output, but the incident will not be automatically assigned.


#### Base Command

`penfield-get-assignee`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analyst_ids | An array of XSOAR analyst IDs for Penfield to choose from when determining who to assign to. | Required | 
| category | The category of the incident to assign. Can be taken from incident Context Data. | Required | 
| created | The creation_date of the incident to assign. Can be taken from incident Context Data. | Required | 
| id | The id of the incident to assign. Can be taken from incident Context Data. | Required | 
| name | The name of the incident to assign. Can be taken from incident Context Data. | Required | 
| severity | The severity of the incident to assign. Can be taken from incident Context Data. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


