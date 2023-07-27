Palo Alto Networks Trend Micro Vision One Event Collector integration for Cortex XSIAM collects the Workbench, Observed Attack Techniques, Search Detections and Audit logs.
Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.
## Configure Trend Micro Vision One Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for Trend Micro Vision One Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter**                                                                    | **Description**                                                                                                                                                                                                   | **Required** |
|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Your server URL                                                                  | The api endpoint to the trend micro vision one instance, see domains list: https://automation.trendmicro.com/xdr/Guides/First-Steps-Toward-Using-the-APIs                                                         | True         |
| Trend Micro Vision One API Key                                                   | The Trend Micro Vision One API Key. Refer to the help section or to the information below on how to retrieve the API key.                                                                                         | False        |
| The maximum number of events per fetch                                           | The maximum number of events to fetch every time fetch is executed for a single log-type \(Workbench, Observed Attack Techniques, Search Detections and Audit logs\).                                             | False        |
| Observed attack techniques and Search detections logs date-time range (hours)    | Defines the date-range (hours) in each api call that retrieves observed attack techniques and search detections logs. Used mainly to prevent timeouts by looping over large amount of logs.  Default is 24 hours. | False        |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | The first fetch time, since when to start fetching events                                                                                                                                                         | False        |
| Fetch events                                                                     |                                                                                                                                                                                                                   | False        |
| Trust any certificate (not secure)                                               |                                                                                                                                                                                                                   | False        |
| Use system proxy settings                                                        |                                                                                                                                                                                                                   | False        |
4. Click **Test** to validate the URLs, token, and connection.

***
This integration fetches the following logs/alerts from Trend Micro Vision One and requires the following permissions:

| **Log Type**                    | **Action Role Permission Required** | **Api Documentation**                                                                                |
|---------------------------------|-------------------------------------|------------------------------------------------------------------------------------------------------|
| Workbench Logs                  | Workbench                           | https://automation.trendmicro.com/xdr/api-v3#tag/Workbench                                           |
| Observed Attack Techniques Logs | Observed Attack Techniques          | https://automation.trendmicro.com/xdr/api-v3#tag/Observed-Attack-Techniques                          |
| Search Detection Logs           | Search                              | https://automation.trendmicro.com/xdr/api-v3#tag/Search/paths/~1v3.0~1search~1endpointActivities/get |
| Audit Logs                      | Audit Logs                          | https://automation.trendmicro.com/xdr/api-v3#tag/Audit-Logs                                          | 


***
You can then create a user account and generate an API key to be used for the Cortex XSIAM integration by following these steps in Trend Micro Vision One.

1. Navigate to **Administration** > **User Accounts**.
2. Click **Add Account**.
3. Fill in the **Add Account** details assigning the role you created in the previous step and choosing **APIs only** as the access level.
4. Complete the account creation process by following the steps in the email you receive.
5. This will generate an **Authentication token** that can then be used to configure the Cortex XSIAM integration.

***
**Built-in Roles:**
Trend Vision One has built-in roles with fixed permissions that Master Administrators can assign to accounts.

The following table provides a brief description of each role. 


| **Role**                          | **Description**                                                                                               |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------- 
| Master Administrator              | Can access all apps and Trend Vision One features.                                                            |
| Operator (formerly Administrator) | Can configure system settings and connect products.                                                           |
| Auditor                           | Has "View" access to specific Trend Vision One apps and features.                                             |
| Senior Analyst                    | Can investigate XDR alerts, take response actions, approve managed XDR requests, and manage detection models. |
| Analyst                           | Can investigate XDR alerts and take response actions.                                                         |


### API Limitations
* You cannot retrieve audit logs that are older than 180 days. Therefore, if setting a first fetch that is more than 180 days, for audit logs it will be a maximum of 180 days.
* For API rate limits, refer [here](https://automation.trendmicro.com/xdr/Guides/API-Request-Limits)
* Observed Attack Techniques Logs and Search Detection Logs are fetched from the newest to the oldest as its the logs are returned in descending order from the api.
* For Observed Attack Techniques Logs and Search Detection Logs it is possible that the limit will be exceeded due to api limitations.


## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### trend-micro-vision-one-get-events

***
Returns a list of logs.

#### Base Command

`trend-micro-vision-one-get-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                                                    | **Required** |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| limit              | The maximum number of logs to retrieve. Default is 50.                                                                                                             | Optional    | 
| from_time          | From which time to retrieve the log(s) (&lt;number&gt; &lt;time unit&gt;, for example 12 hours, 1 day, 3 months). Default is 3 days.                               | Optional    | 
| to_time            | To which time to retrieve the log(s) in ISO8601 format. Defaults to the current time if not provided.                                                              | Optional    | 
| should_push_events | Whether to push the fetched events to Cortex XSIAM or not. Possible values are: false, true. Default is false.                                                     | Optional    | 
| log_type           | Comma-separated list of log-types to retrieve, options are audit, observed_attack_techniques, search_detections and workbench. Default is to retrieve all of them. | Optional    | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroVisionOne.Events | Unknown | Trend Micro Vision One events. | 
