Alibaba log event collector integration for XSIAM.
This integration was integrated and tested with API version 0.6 of Alicloud Log Service.

## Configure Alibaba Action Trail Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Endpoint | The URL used to access your project and the data of your project. |True |
| Access key id | The ID  used to identify the user. | True |
| Access key | The key provided to you by Alibaba Cloud for authentication. | True |
| Project name | The name of your project in your Log Service used to isolate the resources of different users and control access to specific resources. | True |
| Logstore name | The unit in your Log Service that is used to collect, store, and query logs. | True |
| Query | The filter conditions in search statements used to obtain specific logs. Each query statement consists of a search statement and an analytic statement. The search statement and the analytic statement are separated with a vertical bar (\|).A search statement can be a keyword, a numeric value, a numeric value range, a space, or an asterisk . If you specify a space or an asterisk  as the search statement, no conditions are used for searching, and all logs are returned. <br />For example: *(\|) select * from actiontrail_pa_trail, will retrieve all the events from the project as set above. | True |
| Number of incidents to fetch per fetch. | The maximum number of incidents to fetch each time. | False |
| First fetch time interval | The period to retrieve events for. format: [number] [time unit], for example 12 hours, 1 day, 3 months. Default is 3 days. | False |
| Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
| Use Secured Connection | Use SSL secure connection or ‘None’. | False |

## Commands
You can execute these commands Alert War Room in the CLI in XSIAM.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### alibaba-get-events
***
Manual command to fetch events and display them.


#### Base Command

`alibaba-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | The date after which to search for logs in seconds Example: 1652617222. | Optional | 
| limit | Number of events to fetch. Default is 1. | Required | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 


#### Context Output

There is no context output for this command.