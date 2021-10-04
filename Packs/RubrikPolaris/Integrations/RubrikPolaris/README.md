Create a new incident when a Polaris Radar anomaly event is detected and determine if any Sonar data classification hits were found on that object.
This integration was integrated and tested with RubrikPolaris
## Configure RubrikPolaris on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RubrikPolaris.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Polaris Account (e.g. ${polarisAccount}.my.rubrik.com) |  | True |
    | Email |  | True |
    | Password |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First fetch time | The time interval for the first fetch \(retroactive\). Examples of supported values can be found at https://dateparser.readthedocs.io/en/latest/\#relative-date. | False |
    | Fetch Limit (Maximum of 200) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rubrik-radar-analysis-status
***
Check the Radar Event for updates.


#### Base Command

`rubrik-radar-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activitySeriesId | The ID of the Polaris Event Series. When used in combination with "Rubrik Radar Anomaly" incidents, this value will automatically be looked up using the incident context. Otherwise it is a required value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rubrik.Radar.EventComplete | Boolean | Flag that indicates whether Radar has finished analysing the object. | 
| Rubrik.Radar.Message | Unknown | The text, ID, and timestamp of each message in the Activity Series. | 
| Rubrik.Radar.ActivitySeriesId | String | The ID of the Rubrik Polaris Activity Series. | 


#### Command Example
``` ```

#### Human Readable Output



### rubrik-sonar-sensitive-hits
***
Find data classification hits on an object.


#### Base Command

`rubrik-sonar-sensitive-hits`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| objectName | The name of the Rubrik object to check for sensitive hits.  When used in combination with "Rubrik Radar Anomaly" incidents, this value will automatically be looked up using the incident context. Otherwise it is a required value.<br/>. | Optional | 
| searchTimePeriod | The number of days in the past to look for sensitive hits.  If no value is provided, the command will default to 7 days.<br/>. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rubrik.Sonar.TotalHits | String | The total number of data classification hits found on the provided object. | 
| Rubrik.Radar.Message | Unknown | The text, ID, and timestamp of each message in the Activity Series. | 
| Rubrik.Radar.ActivitySeriesId | String | The ID of the Rubrik Polaris Activity Series. | 


#### Command Example
``` ```

#### Human Readable Output


