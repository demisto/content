Cyble Events for Vision Users. Must have Vision API access to use the threat intelligence.
This integration was integrated and tested with version 2.0 of cybleeventsv2

## Configure CybleEventsV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CybleEventsV2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | URL | Server URL \(e.g. https://example.net\) | True |
    | Access Token | Access Token | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident Fetch Limit | Maximum incidents to be fetched every time. Upper limit is 50 incidents. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### subscribed-services

***
Get list of Subscribed services

#### Base Command

`subscribed-services`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEventsV2.SubscribedServices | String | List of subscribed services from Cyble vision | 

### cyble-vision-v2-fetch-iocs

***
Fetch the indicators for the given timeline

#### Base Command

`cyble-vision-v2-fetch-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| iocType | Returns record by type like(Domain,FileHash-MD5,FileHash-SHA1,FileHash-SHA256,IPv4,IPv6,URL,Email). Default is Domain,FileHash-MD5,FileHash-SHA1,FileHash-SHA256,IPv4,IPv6,URL,Email. | Optional | 
| ioc | Returns records for the specified indicator value. | Optional | 
| from | Returns records started with given value. Default is 0. | Optional | 
| limit | Number of records to return (max 1000). Using a smaller limit will get faster responses. Default is 1. | Optional | 
| sortBy | Sorting based on the column(last_seen,first_seen,ioc_type). Possible values are: last_seen, first_seen, ioc_type. Default is last_seen. | Optional | 
| order | Sorting order for ioc either Ascending or Descending based on sort by. Default is desc. | Optional | 
| tags | Returns records for the specified tags. | Optional | 
| startDate | Timeline start date in the format "YYYY-MM-DD". Need to used with end_date as timeline range. | Optional | 
| endDate | Timeline end date in the format "YYYY-MM-DD". Need to used with end_date as timeline range. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEventsV2.IoCs.Data | String | Returns indicator with risk score, confident rating, first seen and last seen | 

### cyble-vision-v2-fetch-alerts

***
Fetch Incident event alerts based on the given parameters. Alerts would have multiple events grouped into one based on specific service type. So user would see in few cases more events than the limit provided.

#### Base Command

`cyble-vision-v2-fetch-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of records to return (max 50). Using a smaller limit will get faster responses. Default is 5. | Optional | 
| startDate | Timeline start date in the format "%Y-%m-%dT%H:%M:%S%z" (iso-8601). | Required | 
| endDate | Timeline end date in the format "%Y-%m-%dT%H:%M:%S%z" (iso-8601). | Required | 
| orderBy | Sorting order for alert fetch either Ascending or Descending. Possible values are: asc, desc. Default is asc. | Optional | 
| from | Returns records for the timeline starting from given indice. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEventsV2.Events.name | String | Return Event name | 
| CybleEventsV2.Events.alert_group_id | String | Return alert group id | 
| CybleEventsV2.Events.event_id | String | Return event id  | 
| CybleEventsV2.Events.keyword | Unknown | Return keywords | 

### fetch-alert-groups

***
Fetch incident event group

#### Base Command

`fetch-alert-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orderBy | Sorting order for alert fetch either Ascending or Descending. Possible values are: asc, desc. Default is asc. | Optional | 
| limit | Number of records to return (max 50). Using a smaller limit will get faster responses. Default is 5. | Optional | 
| startDate | Timeline start date in the format "%Y-%m-%dT%H:%M:%S%z" (iso-8601). | Required | 
| endDate | Timeline end date in the format "%Y-%m-%dT%H:%M:%S%z"  (iso-8601). | Required | 
| from | Returns records for the timeline starting from given indice. Default is 0. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEventsV2.AlertGroup | String | Fetch all the alert groups | 

