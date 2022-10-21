Armorblox is an API-based platform that stops targeted email attacks,
  protects sensitive data, and automates incident response.
This integration was integrated and tested with version xx of Armorblox

## Configure Armorblox on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Armorblox.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Armorblox tenant name | True |
    | Incident type | False |
    | API key | True |
    | Fetch limit | False |
    | First fetch timestamp | False |
    | Incidents Fetch Interval | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fetch-incidents
***
Gets a list of armorblox incidents


#### Base Command

`fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### armorblox-check-remediation-action
***
Check the recommended remediation action for any incident


#### Base Command

`armorblox-check-remediation-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident id of the incident under inspection. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Armorblox.Threat.remediation_actions | string | Should be the remediation action name for the incident under inspection | 

### armorblox-get-incident
***
Get details of the incident


#### Base Command

`armorblox-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


#### Context Output

There is no context output for this command.
### armorblox-get-threat-incidents
***
Get threat incidents


#### Base Command

`armorblox-get-threat-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Custom time filter parameter. | Optional | 
| toDate | Custom time filter parameter. | Optional | 
| sortBy | Sorts the incidents. Possible values are: DATE, TITLE, PRIORITY. Default is DATE. | Optional | 
| orderBy | Order the fetched incidents. Possible values are: ASC, DESC. Default is DESC. | Optional | 
| priorityTypesFilter | Sets the severity to be fetched. Possible values are: HIGH, MEDIUM, LOW. | Optional | 


#### Context Output

There is no context output for this command.
### armorblox-get-dlp-incidents
***
Get dlp incidents


#### Base Command

`armorblox-get-dlp-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Custom time filter parameter. | Optional | 
| toDate | Custom time filter parameter. | Optional | 
| sortBy | Sorts the incidents. Possible values are: DATE, TITLE, PRIORITY. Default is DATE. | Optional | 
| orderBy | Order the fetched incidents. Possible values are: ASC, DESC. Default is DESC. | Optional | 
| priorityTypesFilter | Sets the severity to be fetched. Possible values are: HIGH, MEDIUM, LOW. | Optional | 


#### Context Output

There is no context output for this command.
### armorblox-get-abuse-incidents
***
Get abuse incidents


#### Base Command

`armorblox-get-abuse-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Custom time filter parameter. | Optional | 
| toDate | Custom time filter parameter. | Optional | 
| sortBy | Sorts the incidents. Possible values are: DATE, TITLE, PRIORITY. Default is DATE. | Optional | 
| orderBy | Order the fetched incidents. Possible values are: ASC, DESC. Default is DESC. | Optional | 
| priorityTypesFilter | Sets the severity to be fetched. Possible values are: HIGH, MEDIUM, LOW. | Optional | 


#### Context Output

There is no context output for this command.