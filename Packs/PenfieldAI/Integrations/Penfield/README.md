The penfield-get-assignee command takes in necessary context data, and returns the analyst that Penfield believes the incident should be assigned to based on Penfield's models of skill and process. The test command verfies that the endpoint is reachable.
This integration was integrated and tested with version 0.1.4 of Penfield

## Configure Penfield in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

| **Parameter** | **Description** |
| --- | --- |
| Penfield.Recommended | The analyst Penfield recommends assigning this incident too. |

#### Command Example
```!penfield-get-assignee analyst_ids=['analystid1', 'analystid2'] category='my cat' created='2021-09-13T01:58:22.621033322Z' id=34 name='big rootkit attack' severity='High'```

#### Human Readable Output
peter