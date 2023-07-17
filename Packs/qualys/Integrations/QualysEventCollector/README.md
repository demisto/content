Qualys Event Collector fetches Activity Logs (Audit Logs) and Host Vulnerabilities.
This integration was integrated and tested with version 3.15.2.0-1 of Qualys.

## Configure Qualys Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**. 
2. Search for Qualys Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Username |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | First fetch time | If "First Fetch Time" is set for a long time ago, it may cause performance issues. | True |
    | Vulnerability Fetch Interval | Time between fetches of vulnerabilities \(for example 12 hours, 60 minutes, etc.\). | True |
    | Activity Logs Fetch Interval | Time between fetches of activity logs. | False |
    | Activity Logs Fetch Limit | Maximum number of activity logs to fetch per fetch iteration. | True |
    | Host Detections Fetch Limit | Maximum number of hosts to return in a single fetch iteration. | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### qualys-get-activity-logs

***
Gets activity logs from Qualys.

#### Base Command

`qualys-get-activity-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 
| since_datetime | Date to return results from. | Optional | 
| offset | Offset which events to return. | Optional | 

#### Context Output

There is no context output for this command.
### qualys-get-host-detections

***
Gets host detections from Qualys.

#### Base Command

`qualys-get-host-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 
| offset | Offset which events to return. | Optional | 
| vm_scan_date_after | Date to return results from. | Optional | 

#### Context Output

There is no context output for this command.
