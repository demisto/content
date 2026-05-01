DeCYFIR API's provides External Threat Landscape Management insights.
This integration was integrated and tested with version v2 of decyfir

## Configure DeCYFIR in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| DeCYFIR Server URL (e.g. <https://decyfir.cyfirma.com>) |  | True |
| DeCYFIR API Key |  | True |
| Fetch incidents |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| How much time before the first fetch to retrieve incidents |  | False |
| Maximum number of incidents per fetch | The maximum number of incidents to fetch per sub-category. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### decyfir-takedown-initiate

***
Initiate a take down request.

#### Base Command

`decyfir-takedown-initiate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert for which to initiate the take down request. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!decyfir-takedown-initiate alert_id=123```
#### Human Readable Output
>The take down request was initiated successfully.

### decyfir-takedown-list

***
Get take down list.

#### Base Command

`decyfir-takedown-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sub_category | The sub-category for which to retrieve the take down list. If not provided, the take down list for all sub-categories will be retrieved. | Optional | 
| size | The number of records to retrieve. If not provided, the default value is 100. Default is 100. | Optional | 
| page | The page number to retrieve. If not provided, the default value is 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!decyfir-takedown-list alert_id=123```
#### Human Readable Output
>The take down list retrieved successfully..