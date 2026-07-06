Fetches malicious Cisco ETD email logs and creates incidents in Cortex XSOAR.
This integration was integrated and tested with ETDXsoarConnector.

## Configure ETDXsoarConnector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| ETD Base URL | True |
| API Key | True |
| Password | True |
| Client ID | True |
| Client Secret | True |
| Password | True |
| First Fetch Time | False |
| Max fetch | False |
| Use system proxy settings | False |
| Incident type | False |
| Fetch incidents |  |
| Incidents Fetch Interval |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### test-connectivity

***
Test connectivity.


#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### test-fetch

***
Debug fetch incidents.

#### Base Command

`test-fetch`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### etd-move-message

***
Reclassify and Remediate ETD message.

#### Base Command

`etd-move-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | ETD message ID. | Required | 
| verdict | New verdict. | Required | 
| folder | New folder action. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ETD.Message.ID | String | Message ID. | 
| ETD.Message.Verdict | String | Updated verdict. | 
| ETD.Message.Folder | String | Updated folder. | 
