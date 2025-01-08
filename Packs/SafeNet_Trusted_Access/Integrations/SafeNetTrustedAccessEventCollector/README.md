Retrieve access, authentication, and audit logs and stores them in a Security Information and Event Management (SIEM) system, local repository, or syslog file server. You can retrieve the logs only for the tenant that is associated with the API key, or for a direct or delegated child of that tenant.

## Configure SafeNetTrustedAccessEventCollector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL | The URL consists of the root part of the REST API Endpoint URL provided in SafeNet Trusted Access, and has the form https://api.\[name\].com | True |
| Tenant Code | Tenant code for your virtual server or account. | True |
| API Key for the authentication. |  | True |
| The product name corresponding to the integration that originated the events |  | False |
| The vendor name corresponding to the integration that originated the events |  | False |
| The maximum number of audit logs to fetch. Valid limit is multiples of 1000 and less than 10,000. |  | True |
| First fetch timestamp |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sta-get-events
***
Get access, authentication, and audit logs from SafeNet Trusted Access.


#### Base Command

`sta-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| since | Since date. | Optional | 
| until | Until date. | Optional | 
| marker | A string pointing at the next page of results. The marker can be found within the previous response. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!sta-get-events should_push_events=false since="10 seconds"```
#### Human Readable Output

>### Event Logs
>Marker: 111111
>|category|context|details|id|logVersion|timeStamp|
>|---|---|---|---|---|---|
>| AUDIT | tenantId: TENENTID<br/>originatingAddress: 1.1.1.1<br/>principalId: ID<br/>globalAccessId: ID | type: AUTHENTICATION<br/>serial: SERIAL<br/>action: 0<br/>actionText: AUTH_ATTEMPT<br/>result: 1<br/>resultText: AUTH_SUCCESS<br/>agentId: ID<br/>message: MSG <br/>credentialType: TYPE | $ID | 1.0 | 2022-01-01T00:00:00.00000Z |
>| AUDIT | tenantId: TENENTID<br/>originatingAddress: 1.1.1.1<br/>principalId: ID<br/>globalAccessId: ID | type: AUTHENTICATION<br/>serial: SERIAL<br/>action: 0<br/>actionText: AUTH_ATTEMPT<br/>result: 2<br/>resultText: CHALLENGE<br/>agentId: ID<br/>message: MSG <br/>usedName: NAME<br/>credentialType: TYPE | $ID | 1.0 | 2022-01-01T00:00:00.00000Z |
