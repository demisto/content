Use this integration to fetch audit logs events, alerts events and computers assets from Jamf Protect to Cortex XSIAM.
## Configure Jamf Protect Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., <https://example.protect.jamfcloud.com>) | REST API Endpoint of Jamf Protect server. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client ID | The unique identifier for the client application, provided by Jamf when the application is registered. This is used to authenticate the client with the Jamf Protect server. | True |
| Password | The password for the client application. This is used to authenticate the client with the Jamf Protect server. | True |
| Max alert events per fetch | Maximum number of alert events to fetch at a time. Default is 1000| False |
| Max audit events per fetch | Maximum number of audit events to fetch at a time. Default is 20,000| False |
| Fetch Computer Assets Interval | The fetch interval. It is recommended to set it to 12 hours. The minimum interval is 1 hour. | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jamf-protect-get-events

***
Gets events from Jamf Protect.

#### Base Command

`jamf-protect-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional | 
| start_date | The start date from which to filter events. | Optional | 
| end_date | The end date to which to filter events. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.

### jamf-protect-get-computer-assets

***
Gets computer assets from Jamf Protect.

#### Base Command

`jamf-protect-get-computer-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of computer assets to return. Default is 10. | Optional | 

#### Context Output

There is no context output for this command.
