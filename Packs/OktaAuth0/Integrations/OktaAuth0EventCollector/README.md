Okta Auth0 logs event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 2.0 of Okta Auth0.
Please see the [Okta Auth0 rate limit policy](https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy).

## Configure Okta Auth0 Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Client ID | The API key to use for connection. | True |
| Client Secret |  | True |
| First fetch (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| The maximum number of events per fetch |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### okta-auth0-get-events

***
Manual command to fetch events and display them.

#### Base Command

`okta-auth0-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. Maximum is 2000. Default is 10. | Optional | 
| since | Occurrence time of the least recent event to include (inclusive). Default is 3 days. | Optional | 

#### Context Output

There is no context output for this command.