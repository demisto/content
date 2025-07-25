Cyble Events for Vision Users. Must have Vision API access to use the threat intelligence.
This integration was integrated and tested with version 2.0 of cybleeventsv2

## Configure CybleEventsV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
 Search for CybleEventsV2.
 Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                      | **Description**                                                         | **Required** |
    |------------------------------------|-------------------------------------------------------------------------|--------------|
    | URL                                | Server URL \(e.g., <https://example.net\>)                              | True         |
    | Access Token                       | Access Token                                                            | True         |
    | Collections to Fetch               | Select collections of incidents to be fetched from the dropdown menu    | False        |
    | Severities to Fetch                | Select severities of incident to be fetched from the dropdown menu      | False        |
    | Trust any certificate (not secure) |                                                                         | False        |
    | Use system proxy settings          |                                                                         | False        |
    | Incident Fetch Limit               | Maximum incidents to be fetched every time. Upper limit is 50 incidents | False        |
    | Hide Card Details                  | Select to hide CVV and Expiry date of card                              | False        |
    | Update Incident to Remote System   | Select to update changes in any incident to Vision                      | False        |

4. To ensure that fetch incidents works:
    * Select the Fetches incidents radio button.
    * Under Incident type, select Cyble Vision Alert V2.

5. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyble-vision-subscribed-services

***
Get list of Subscribed services

#### Base Command

`cyble-vision-subscribed-services`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path**                       | **Type** | **Description**                                 |
|--------------------------------|----------|-------------------------------------------------|
| CybleEvents.SubscribedServices | String   | A list of subscribed services from Cyble vision |

### cyble-vision-fetch-iocs

***
Fetch the indicators in the given timeline.

#### Base Command

`cyble-vision-fetch-iocs`

#### Input

| **Argument Name** | **Description**                                                                                                                                            | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| ioc_type          | Returns records according to their type (Domain, FileHash-MD5, FileHash-SHA1, FileHash-SHA256, IPv4, IPv6, URL, Email, Wallet-Address). Default is Domain. | Optional     |
| ioc               | Returns records for the specified indicator value.                                                                                                         | Optional     |
| from              | Returns records that starts from the given page number (the value of the form parameter) in the results list. Default is 1.                                | Optional     |
| limit             | Number of records to return (max 100). Using a smaller limit will get faster responses. Default is 1.                                                      | Optional     |
| sort_by           | Sorting based on the column(last_seen,first_seen,ioc_type). Possible values are: last_seen, first_seen, ioc_type. Default is last_seen.                    | Optional     |
| order             | Sorting order for ioc either Ascending or Descending based on sort by. Default is desc.                                                                    | Optional     |
| tags              | Returns records for the specified tags.                                                                                                                    | Optional     |
| start_date        | Timeline start date in the format "YYYY-MM-DD". Should be used with start_date as timeline range.                                                          | Optional     |
| end_date          | Timeline end date in the format "YYYY-MM-DD". Should be used with end_date as timeline range.                                                              | Optional     |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEvents.IoCs.Data | String | Returns indicator with risk score, confident rating, first seen and last seen |

### cyble-vision-fetch-alerts

***
Fetch alerts based on the given parameters. The alerts would have multiple events grouped into one, based on a specific service type. This way the user will see, in some cases, more events than the limit provides.

#### Base Command

`cyble-vision-fetch-alerts`

#### Input

| **Argument Name** | **Description**                                                                                               | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------| --- |
| limit             | Number of records to return (max 50). Using a smaller limit will get faster responses. Default is 5.          | Optional |
| start_date        | Timeline start date in the format "%Y-%m-%dT%H:%M:%S%z" (iso-8601).                                           | Required |
| end_date          | Timeline end date in the format "%Y-%m-%dT%H:%M:%S%z" (iso-8601).                                             | Required |
| order_by          | Sorting order for alert fetch either Ascending or Descending. Possible values are: asc, desc. Default is asc. | Optional |
| from              | Returns records for the timeline starting from the given indice. Default is 0.                                | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleEvents.Events.name | String | Return Event name |
| CybleEvents.Events.alert_group_id | String | Return alert group id |
| CybleEvents.Events.event_id | String | Return event id  |
| CybleEvents.Events.keyword | Unknown | Return keywords |

### cyble-vision-fetch-alert-groups

***
Fetch incident event group

#### Base Command

`cyble-vision-fetch-alert-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| order_by          | Sorting order for alert fetch either Ascending or Descending. Possible values are: asc, desc. Default is asc. | Optional |
| limit             | Number of records to return (max 50). Using a smaller limit will get faster responses. Default is 5. | Optional |
| start_date        | Timeline start date in the format "%Y-%m-%dT%H:%M:%S%z" (iso-8601). | Required |
| end_date          | Timeline end date in the format "%Y-%m-%dT%H:%M:%S%z"  (iso-8601). | Required |
| from              | `Returns records that starts from the given page number (the value of the form parameter) in the results list. Default is 0. | Required |

#### Context Output

| **Path**               | **Type** | **Description** |
|------------------------| --- | --- |
| CybleEvents.AlertGroup | String | Fetch all the alert groups |

### update-alert-data

***
Update the status and/or severity of one or more alerts by ID.

#### Base Command

`update-alert-data`

#### Input

| **Argument Name** | **Description**                                                                                      | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------|--------------|
| ids               | The alert ID(s) to update. Comma-separated if multiple.                                              | Required     |
| status            | The new status to assign to the alert(s). Provide a single value or one per alert, comma-separated. | Optional     |
| severity          | The new severity to assign to the alert(s). Provide a single value or one per alert, comma-separated.| Optional     |

#### Context Output

| **Path**                             | **Type** | **Description**                       |
|-------------------------------------|----------|---------------------------------------|
| CybleEvents.AlertUpdate.id          | String   | The alert ID that was updated.        |
| CybleEvents.AlertUpdate.status      | String   | The updated status.                   |
| CybleEvents.AlertUpdate.user_severity | String | The updated user severity.            |
| CybleEvents.AlertUpdate.service     | String   | The service associated with the alert.|

#### Command Example

```bash
!update-alert-data ids="id1,id2" status="UNDER_REVIEW,RESOLVED" severity="HIGH,LOW"

