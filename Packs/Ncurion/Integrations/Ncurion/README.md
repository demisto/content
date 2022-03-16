This is the Ncurion integration for getting started.
This integration was integrated and tested with version xx of Ncurion

## Configure Ncurion on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Ncurion.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL  | True |
    | Fetch incidents | False |
    | Incident type | False |
    | username | False |
    | Password | False |
    | Maximum number of incidents per fetch | False |
    | First fetch time | False |
    | Trust any certificate (not secure) | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ncurion-get-log-list
***
 


#### Base Command

`ncurion-get-log-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ncurion.sensor.ID | string |  | 
| Ncurion.sensor.Name | string |  | 
| Ncurion.sensor.Host | string |  | 
| Ncurion.sensor.Log_storage_month_period | string |  | 
| Ncurion.sensor.Useno | string |  | 
| Ncurion.sensor.Sync_state | string |  | 
| Ncurion.sensor.Is_connected | string |  | 
| Ncurion.sensor.Description | string |  | 
| Ncurion.sensor.Created_at | date |  | 
| Ncurion.sensor.Updated_at | date |  | 


#### Command Example
``` ```

#### Human Readable Output


