# Cisco ThousandEyes Integration for Cortex XSIAM

This is the Cisco ThousandEyes event collector integration for Cortex XSIAM. This integration enables you to fetch events such as alerts and audit logs from Cisco ThousandEyes and process them within Cortex XSIAM.

This integration was developed and tested with version 1.0.0 of Cisco ThousandEyes.

## Configure CiscoThousandEyes in Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for **CiscoThousandEyes**.
3. Click **Add instance** to create and configure a new integration instance.


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of the Cisco ThousandEyes server (e.g., `https://api.thousandeyes.com`). | True |
| User API Token | The API token for authenticating with Cisco ThousandEyes. | True |
| The maximum number of audit events per fetch | Maximum number of audit events to retrieve per fetch cycle. Default is 50. | False |
| The maximum number of alerts per fetch | Maximum number of alert events to retrieve per fetch cycle. Default is 50. | False |
| Trust any certificate (not secure) | If enabled, the integration will trust self-signed certificates. | False |
| Use system proxy settings | If enabled, the integration will use the system proxy settings. | False |


## Note:
>This API returns a list of activity log events **in the current account group**.
If the user has View activity log permission for all users in the account group, the logs returned include events across all the account groups they belong to.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-thousandeyes-get-events

***
Gets events from Cisco ThousandEyes.

#### Base Command

`!cisco-thousandeyes-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional | 
| start_date | The start date from which to filter events. | Optional | 
| end_date | The end date to which to filter events. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Optional | 

#### Example Usage

```shell
!cisco-thousandeyes-get-events limit="100" start_date="2024-10-10T00:00:00Z" should_push_events=true
```

#### Context Output

There is no context output for this command.
