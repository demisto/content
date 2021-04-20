This integration will run a server that will listen for PingCastle XML reports.
This integration was integrated and tested with version 6.0.0 of PingCastle
## Configure PingCastle on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PingCastle.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key PingCastle must use to send reports | True |
    | Long running instance | Whether this instance should listen for reports | False |
    | Listen port, e.g. 7000 |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pingcastle-get-report
***
Get the Currently saved Ping Castle Report


#### Base Command

`pingcastle-get-report`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PingCastle.Report.report | String | The XML report sent by Ping Castle | 


#### Command Example
``` ```

#### Human Readable Output
