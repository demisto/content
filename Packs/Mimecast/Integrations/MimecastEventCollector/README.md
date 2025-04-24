This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Mimecast Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| Application ID |  | True |
| Application Key |  | True |
| Access Key |  | True |
| Secret Key |  | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, 3 months, 1 year) | This parameter is used only for the Audit logs configuration. SIEM logs always set to "7 days ago". For additional information, review the pack README. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## General information 
This integration is collecting events from 2 end points. 
* ### audit events
    All events are fetched at once when activating the integration from **first fetch timestamp** until now.
    After that the fetch mechanism will call every 1 minute to update the audit events from Mimecast.
* ### SIEM logs 
    The logs will **always be fetched from 7 days ago**. Once the integration is activated, the logs will 
    stream in batches of 350 logs per fetch.
    When all available logs are retrieved, the fetch mechanism will call every 1 minute to update the SIEM logs from Mimecast.  

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mimecast-get-events
***
Manual command to fetch events and display them.


#### Base Command

`mimecast-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 


#### Context Output

There is no context output for this command.