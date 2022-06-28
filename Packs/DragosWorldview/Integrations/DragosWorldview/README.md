Custom integration designed to pull in reports from the Dragos Worldview API as incidents 
This integration was integrated and tested with version 1.0 of Dragos Worldview 

## Configure Dragos Worldview  on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Dragos Worldview .
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://portal.dragos.com) |  | True |
    | API Token |  | True |
    | API Key |  | True |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Fetch Limit |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dragos-get-indicators
***
Get Indicators from the Dragos WorldView API


#### Base Command

`dragos-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Report serial number to get indicators from, if no serial number provided command will retrieve all indicators from the last 48 hours. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dragos-get-full-report
***
Get the report file from the given serial number


#### Base Command

`dragos-get-full-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number for the report to retrieve. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dragos-get-ioc-csv
***
Get csv file with indicators from a given report


#### Base Command

`dragos-get-ioc-csv`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the report from which to get the file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### dragos-get-stix2
***
Get the stix2 json bundle of indicators from a given report


#### Base Command

`dragos-get-stix2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the report from which to retrieve the file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


