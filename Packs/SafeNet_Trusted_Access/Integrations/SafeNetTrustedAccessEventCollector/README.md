Retrieve access, authentication, and audit logs and store them on a Security Information and Event Management (SIEM) system, local repository, or syslog file server. You can retrieve the logs only for the tenant that is associated with the API key, or for a direct or delegated child of that tenant.
This integration was integrated and tested with version xx of SafeNetTrustedAccessEventCollector

## Configure SafeNetTrustedAccessEventCollector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SafeNetTrustedAccessEventCollector.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

#### Command Example
```!sta-get-events should_push_events=false```

