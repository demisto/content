Endpoint Standard (formerly called Carbon Black Defense), a Next-Generation Anti-Virus + EDR. Collect Anti-Virus & EDR alerts and Audit Log Events.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Carbon Black Endpoint Standard Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API ID | The API Key to use for connection | True |
| API Secret Key |  | True |
| Organization Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Include Audit Logs |  | False |
| Maximum number of alerts per fetch | Default 100,000. | False |
| Maximum number of audit logs per fetch | Default 25,000. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### carbonblack-endpoint-standard-get-events

***
Fetch alerts and audit logs from Carbon Black Endpoint Standard.

#### Base Command

`carbonblack-endpoint-standard-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| alerts_limit | The maximum number of alerts to return (maximum value - 100000). Default is 10000. | Optional | 
| audit_logs_limit | The maximum number of audit logs to return (maximum value - 25000). Default is 2500. | Optional | 

#### Context Output

There is no context output for this command.