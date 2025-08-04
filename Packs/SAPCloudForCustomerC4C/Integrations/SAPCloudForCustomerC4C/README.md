Use the SAP Cloud for Customer C4C integration to fetch events from SAP Cloud API.

## Configure SAP Cloud For Customer C4C in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Confirm that the pre-filled URL matches the correct API endpoint for your SAP C4C integration instance. | True |
| Username | The credentials to associate with the instance. | True |
| Password | The password to set for the user. | True |
| Report ID | The unique identifier of the report to retrieve data from SAP Cloud for Customer (C4C). | True |
| Trust any certificate (not secure) | |  False |
| Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
| Maximum number of audit events per fetch | Maximum number of events to retrieve per fetch. The default value is 10000. | False |

### Timezone Configuration

Before configuring this integration, you **must** ensure that the timezone for the user configured in your SAP C4C instance matches the UTC format. Failure to do so may result in errors when fetching events due to timestamp mismatches.

To configure the timezone for your technical user in SAP C4C, follow these steps:

1. Log in to your SAP C4C system with an administrator account.
2. Navigate to **Application and User Management** -> **Business Users**.
3. Find and select the technical user that will be used for this integration.
4. Go to the **Details** section for the selected user.
5. Under the **General** tab, locate the **Time Zone** field.
6. Set the time zone to a UTC format (e.g., "UTC", "UTC+01:00", "UTC-05:00").
7. Save your changes.

For a detailed explanation and visual guide, please refer to the following SAP Community blog post: [Technical User Date Time Format Settings Change in C4C](https://community.sap.com/t5/crm-and-cx-blog-posts-by-members/technical-user-date-time-format-settings-change-in-c4c/ba-p/13581365).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### sap-cloud-get-events

***
Retrieves events from the SAP Cloud for Customer API.

#### Base Command

`sap-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The **start date** for filtering events. Events newer than or equal to this date will be retrieved.<br/>Must be in `DD-MM-YYYY HH:MM:SS` format (e.g., `10-07-2025 14:17:46`).<br/>. | Required |
| days_from_start | The **number of days** to include events after the `start_date`. For example, if `start_date` is <br/>'10-07-2025 10:00:00' and `days_from_start` is '2', events will be retrieved up to '12-07-2025 10:00:00'.<br/>It's recommended to keep this value no more than 5 days to avoid very large result sets.<br/>. Default is 2. | Optional |
| should_push_events | Set to **true** to create events in your system from the retrieved data. <br/>If **false** (default), the command will only display the events without creating them.<br/>. Possible values are: true, false. Default is false. | Optional |
| limit | The **maximum number of events** to retrieve. If more events match the criteria, only this<br/>specified amount will be returned.<br/>. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!sap-cloud-get-events start_date="01-07-2025 14:00:00" limit="5"```

#### Human Readable Output

>### Indicators from Anomali ThreatStream Feed
>
>|BROWSER|CBROWSER_VERSION|CCAL_DAY|CCLIENT_TYPE|CCOLD_START_IND|CDEVICE_TYPE|
>|---|---|---|---|---|---|
>| 02 | ver1 | 2025-04-05 | RUI | 1 | default |
>| 02 | ver2 | 2025-04-05 | RUI | 2 | default |
>| 02 | ver3 | 2025-04-05 | RUI | 2 | default |
>| 02 | ver4 | 2025-04-05 | RUI | 1 | default |
>| 02 | ver5 | 2025-04-05 | RUI | 1 | default |
