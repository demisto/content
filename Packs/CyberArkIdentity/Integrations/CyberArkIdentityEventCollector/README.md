CyberArk Identity log event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 22.4 of CyberArk Identity Event Collector.

## Configure CyberArk Identity Event Collector in Cortex


| **Parameter** | **Description**                                                    | **Required** |
|------------------------------------------------------------------------------| --- | --- |
| Server URL | The CyberArk Identity URL to get the logs from. For example, https://{{tenant}}.my.idaptive.app.       | True |
| App ID | The application ID to fetch the logs from.                                | True |
| User name | The user that was created in CyberArk for the XSIAM integration. For example, `admin@example.com`.                  | True |
| Password | The password for the user that was created in CyberArk for the XSIAM integration.                                                      | True |
| First fetch time  | The period to retrieve events for. <br/>Format: &lt;number&gt; &lt;time unit&gt;, for example 12 hours, 1 day, 3 months. <br/>Default is 3 days. | True |
| Maximum number of events per fetch | The maximum number of items to retrieve per request from CyberArk's API. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked.  | False |
| Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration.  | False |

## Commands
You can execute these commands from the Cortex XSIAM Alerts War Room as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberarkidentity-get-events
***
Returns a list of events


#### Base Command

`cyberarkidentity-get-events`
#### Input

| **Argument Name** | **Description**                                                                                                    | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------| --- |
| should_push_events | Set this argument to True to create events, otherwise events will only be displayed. Default is False.             | Required |
| limit | The maximum number of events per fetch. Default is 1000.                                                           | Optional | 
| from | The first fetch time (&lt;number&gt; &lt;time unit&gt;, for example 12 hours, 1 day, 3 months). Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
`!cyberarkidentity-get-events should_push_events=false limit=10 from="3 days"`
#### Human Readable Output

>### CyberArkIdentity RedRock records
>|Auth Method|Directory Service Uuid|From IP Address|ID|Level|Normalized User|Request Device OS|Request Host Name|Request Is Mobile Device|Tenant|User Guid|When Logged|When Occurred|_ Table Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdef | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376432605)/ | /Date(1652376432605)/ | events |
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdeg | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376492682)/ | /Date(1652376492682)/ | events |
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdeh | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376552546)/ | /Date(1652376552546)/ | events |