Uses the deprecated crowdstrike graph api to return process and other information.

Version History
- v2.1.3 lint tidy
- V2.1.2 no change, just reversioned following git restructuring and changed tags for deployment
- V1.1.1 support multiple sensors
- V1.1.0 added test method
- V1.0.0 original version
This integration was integrated and tested with version xx of Threatgraph

## Configure Threatgraph on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Threatgraph.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://falconapi.us-2.crowdstrike.com) |  | True |
    | API Key | Threatgraph API key | True |
    | API Secret | Threatgraph API secret | True |
    | Fetch indicators |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bt-get-tree
***
Gets the parent and child processes for a crowdstrike process/processes for given sensor id(s)


#### Base Command

`bt-get-tree`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_ids | The ID of the sensor the process was running on. | Required | 
| process_ids | The ID of the process to get the parents and children for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatGraph_data | unknown | An output of the threatgraph query | 


#### Command Example
``` ```

#### Human Readable Output


