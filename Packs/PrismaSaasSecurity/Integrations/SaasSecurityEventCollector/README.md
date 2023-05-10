SaaS Security is an integrated CASB (Cloud Access Security Broker) solution that helps Security teams like yours meet 
the challenges of:
* protecting the growing availability of sanctioned and unsanctioned SaaS applications
* maintaining compliance consistently in the cloud
* stopping threats to sensitive information, users, and resources


## Configure SaaS Security on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Saas Security Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL | The instance configuration URL based on the server location. | True |
    | Client ID | The SaaS Security Client ID. | True |
    | Client Secret | The SaaS Security Secret ID. | True |
    | Trust any certificate (not secure) | By default, SSL verification is enabled. If selected, the connection isn’t secure and all requests return an SSL error because the certificate cannot be verified. | False |
    | Use system proxy settings | Uses the system proxy server to communicate with the  integration. If not selected, the integration will not use the system proxy server. | False |
    | The maximum number of events per fetch. | The maximum number of events to fetch every time fetch is being executed. This number must be divisible by 100 due to Saas-Security api limitations. Default is 1000. In case this is empty, all available events will be fetched. | False |
    | The maximum number of iterations to retrieve events. | In order to prevent timeouts, set this parameter to limit the number of iterations for retrieving events. Note - the default value is the recommended value to prevent timeouts. Default is 150. | False |
5. Click **Test** to validate the URLs, token, and connection.

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


## Limitations
1) Occurring events expire after one hour in Saas-Security cache, so setting a low limit could cause events to expire if there are a large number of events in the Saas-Security cache.
2) If the ```max_fetch``` is not dividable by 10, it will be rounded down to a number that is dividable by 10 due to SaaS Security api limits.
3) **reset last fetch** has no effect.
4) On initial activation this integration will pull events starting from one hour prior.
5) Using the ```saas-security-get-events``` command may take upwards of twenty seconds in some cases.
6) In some rare cases more than ```max_fetch``` events could be fetched.
7) The maximum recommended max fetch is 5000 to avoid fetch timeouts.
8) In case not providing the ```max_fetch``` argument, the default will be 1000.

## Fetch Events
Requires the scope of *api_access* in order to fetch log events. See [Documentation](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/api-client-authentication/retrieve-a-token#idd543d5f0-c56e-4899-957f-74f921fd0976)
Since those events are saved only 1 hour at cache, it is highly recommended giving *Events Fetch Interval* in minutes rather than hours.

In case not stating a max fetch in the integration parameters, all available events will be fetched.

Log types could be one of policy_violation, activity_monitoring, remediation, incident, and admin_audit.
Every type returns a different api response that is unique.

**Example Activity Monitoring Response**
```json
{
    "log_type" : "activity_monitoring",
    "item_type" : "File",
    "item_name" : "My File",
    "user" : "John Smith",
    "source_ip" : "10.10.10.10",
    "location" : "Somewhere, USA",
    "action" : "delete",
    "target_name" : null,
    "target_type" : null,
    "severity" : 1.0,
    "serial" : "mySerial",
    "cloud_app_instance" : "My Cloud App",
    "timestamp" : "2018-11-09T18:30:33.155Z"
}
```

**Example Incident Response**
```json
{
    "log_type" : "incident",
    "severity" : 4.0,
    "item_type" : "File",
    "item_name" : "My File",
    "asset_id" : "ce7c9ed11e6f4891ae73c1601af7f741",
    "item_owner" : "John Smith",
    "container_name" : "Container",
    "item_creator" : "John Smith",
    "exposure" : "public",
    "occurrences_by_rule" : 5,
    "item_owner_email" : "owner@<--domain-->.com",
    "item_creator_email" : "creator@<--domain-->.com",
    "serial" : "mySerial",
    "cloud_app_instance" : "My Cloud App",
    "timestamp" : "2018-11-09T18:30:32.572Z",
    "incident_id" : "9610efdcd8a74a259bf031843eac0309",
    "policy_rule_name" : "PCI Policy",
    "incident_category" : "Testing",
    "incident_owner" : "John Smith"
}
```

**Example Remediation Response**
```json
{
    "log_type" : "remediation",
    "item_type" : "File",
    "item_name" : "My File",
    "asset_id" : "ce7c9ed11e6f4891ae73c1601af7f741",
    "item_owner" : "John Smith",
    "container_name" : "Container",
    "item_creator" : "John Smith",
    "action_taken" : "quarantine",
    "action_taken_by" : "John Smith",
    "item_owner_email" : "owner@<--domain-->.com",
    "item_creator_email" : "creator@<--domain-->.com",
    "serial" : "mySerial",
    "cloud_app_instance" : "My Cloud App",
    "timestamp" : "2018-11-09T18:30:30.909Z",
    "incident_id" : "9610efdcd8a74a259bf031843eac0309",
    "policy_rule_name" : "PCI Policy"
}
```

**Example Policy Violation Response**
```json
{
    "log_type" : "policy_violation",
    "severity" : 3.0,
    "item_type" : "File",
    "item_name" : "My File",
    "item_owner" : "John Smith",
    "item_creator" : "John Smith",
    "action_taken" : "download",
    "action_taken_by" : "John Smith",
    "asset_id" : "ce7c9ed11e6f4891ae73c1601af7f741",
    "item_owner_email" : null,
    "item_creator_email" : null,
    "serial" : "serial",
    "cloud_app_instance" : "My Cloud App",
    "timestamp" : "2017-01-06T19:04:06Z",
    "policy_rule_name" : "Policy Rule",
    "incident_id" : "1234"
}
```

**Example Admin Audit Response**
```json
{
    "log_type" : "admin_audit",
    "admin_id" : "admin id",
    "admin_role" : "admin role",
    "ip" : "ip address",
    "event_type" : "event type",
    "item_type" : "File",
    "item_name" : "My File",
    "field" : "field",
    "action" : "action",
    "resource_value_old" : "old val",
    "resource_value_new" : "new val",
    "timestamp" : "2018-11-09T18:30:29.739Z",
    "serial" : "mySerial"
}
```
for more information see [documentation](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/public-api-references/log-events-api#id2bfde842-f708-4e0b-bc41-9809903a6021_id51ace1dd-a6cd-4d8b-8014-094d1d7c26b2)

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
| limit | The maximum number of events to get. Must be divisible by 100 due to Saas-Security api limitations. Overrides the max-fetch parameter of the integration. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. *If setting to 'False' The returned events will be lost.* Possible values are: True, False. Default is False. | Required | 


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
| SaasSecurity.Event.severity | Number | Severity \(0-5\). | 
| SaasSecurity.Event.incident_id | String | Incident/risk id. | 
| SaasSecurity.Event.exposure | String | Exposure level \(public, external, company, or internal\). | 
| SaasSecurity.Event.asset_id | String | The asset ID. | 
| SaasSecurity.Event.item_owner | String | The item owner. | 
| SaasSecurity.Event.container_name | String | Item’s container name. | 
| SaasSecurity.Event.item_creator | String | Item creator. | 
| SaasSecurity.Event.occurrences_by_rule | Number | Number of times the asset violated the policy. | 
| SaasSecurity.Event.policy_rule_name | String | Violated policy’s name. | 
| SaasSecurity.Event.incident_owner | String | Incident owner. | 
| SaasSecurity.Event.incident_category | String | Incident category. | 
| SaasSecurity.Event.item_creator_email | String | Item creator’s email. | 
| SaasSecurity.Event.action_taken | String | Action taken. | 
| SaasSecurity.Event.action_taken_by | String | Action taken by. | 
| SaasSecurity.Event.field | String | Name of field \(optional\). | 
| SaasSecurity.Event.resource_value_old | String | Old resource value. \(optional\). | 
| SaasSecurity.Event.resource_value_new | String | New resource value. \(optional\). | 

#### Command example
```!saas-security-get-events limit=200 should_push_events=False```
#### Context Example
```json
{
    "SaasSecurity": {
        "Event": [
            {
                "action": "preview",
                "cloud_app_instance": "Box 1",
                "item_name": "ssn_test3.txt",
                "item_type": "file",
                "item_unique_id": "123",
                "location": "somewhere, usa",
                "log_type": "activity_monitoring",
                "serial": null,
                "severity": 1,
                "source_ip": "2.2.2.2",
                "target_name": null,
                "target_type": "",
                "timestamp": "2022-05-30T06:40:59Z",
                "user": "some email"
            },
            {
                "action": "preview",
                "cloud_app_instance": "Box 1",
                "item_name": "SP0605 copy.java.txt",
                "item_type": "file",
                "item_unique_id": "1234",
                "location": "somewhere usa, Israel",
                "log_type": "activity_monitoring",
                "serial": null,
                "severity": 1,
                "source_ip": "1.1.1.1",
                "target_name": null,
                "target_type": "",
                "timestamp": "2022-05-30T06:40:47Z",
                "user": "some email"
            }
        ]
    }
}
``` 

#### Human Readable Output

>### SaaS Security Logs
>|LogType|ItemType|ItemName|Timestamp|
>|---|---|---|---|
>| activity_monitoring | file | ssn_test3.txt | 2022-05-30T06:40:59Z |
>| activity_monitoring | file | SP0605 copy.java.txt | 2022-05-30T06:40:47Z |

