SaaS Security is an integrated CASB (Cloud Access Security Broker) solution that helps Security teams like yours meet 
the challenges of protecting the growing availability of sanctioned and unsanctioned SaaS applications and maintaining 
compliance consistently in the cloud while stopping threats to sensitive information, users, and resources. 
SaaS Security options include SaaS Security API (formerly Prisma SaaS) and the SaaS Security Inline add-on.


## Configure SaaS Security on Cortex XSIAM


## Create the Client ID and Client Secret on SaaS Security
In the SaaS Security UI, do the following:
1. Navigate to **Settings** > **External Service**.
2. Click **Add API Client**.
3. Specify a unique name for the API client.
4. Authorize the API client for the required scopes. You use these scopes in the POST request to the /oauth/token endpoint. The Required Scopes are:
    - Log access — Access log files. You can either provide the client log access API or add a syslog receiver.
    - Incident management — Retrieve and change the incident status.
    - Quarantine management — Quarantine assets and restore quarantined assets.
6. Copy the client ID and client secret.
Tip: Record your API client secret somewhere safe. For security purposes, it’s only shown when you create or reset the API client. If you lose your secret you must reset it, which removes access for any integrations that still use the previous secret.
7. Add the **Client ID** and **Client Secret** to Cortex XSOAR.
Note: For more information see the [SaaS Security Administrator's Guide](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/add-your-api-client-app.html)


## Commands
You can execute these commands from the Cortex XSIAM CLI as part of an automation or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### saas-security-get-events
***
Manual command to fetch events and display them.


#### Base Command

`saas-security-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to get. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SaasSecurity.Event.log_type | String | Event type. | 
| SaasSecurity.Event.item_type | String | Item type \(File, Folder, or User\). | 
| SaasSecurity.Event.item_name | String | Name of the file, folder, or user associated with the event. | 
| SaasSecurity.Event.item_unique_id | String | Unique ID number for an asset’s related asset. | 
| SaasSecurity.Event.user | String | Cloud app user that performed the action. | 
| SaasSecurity.Event.source_ip | String | Original session source IP address. | 
| SaasSecurity.Event.location | String | Location of the cloud app user that performed the event. | 
| SaasSecurity.Event.action | String | Action performed. | 
| SaasSecurity.Event.target_name | String | Target name. | 
| SaasSecurity.Event.target_type | String | Target type. | 
| SaasSecurity.Event.serial | String | Serial number of the organization using the service \(tenant\). | 
| SaasSecurity.Event.cloud_app_instance | String | Cloud app name \(not cloud app type\). | 
| SaasSecurity.Event.timestamp | Date | ISO8601 timestamp to show when the event occurred. | 

#### Command example
```!saas-security-get-events limit=5```
#### Context Example
```json
{
    "SaasSecurity": {
        "Event": {
            "action": "login",
            "cloud_app_instance": "Box 1",
            "item_name": "test",
            "item_type": "user",
            "item_unique_id": "1234",
            "location": "Tel Aviv, Central District, Israel",
            "log_type": "activity_monitoring",
            "serial": null,
            "severity": 1,
            "source_ip": "1.1.1.1",
            "target_name": null,
            "target_type": "",
            "timestamp": "2022-05-25T08:32:08Z",
            "user": "test@gmail.com"
        }
    }
}
```

#### Human Readable Output

>### SaaS Security Logs
>|Action|CloudAppInstance|ItemName|ItemType|ItemUniqueId|Location|LogType|Serial|Severity|SourceIp|TargetName|TargetType|Timestamp|User|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| login | Box 1 | test | user | 1234 | Tel Aviv, Central District, Israel | activity_monitoring |  | 1.0 | 1.1.1.1 |  |  | 2022-05-25T08:32:43Z | test@gmail.com |
