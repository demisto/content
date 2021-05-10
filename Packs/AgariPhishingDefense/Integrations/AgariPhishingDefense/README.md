Agari Phishing Defense stops phishing, BEC, and other identity deception attacks that trick employees into harming your business.
This integration was integrated and tested with a standard version of Agari Phishing Defense.
## Configure Agari Phishing Defense on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Agari Phishing Defense.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to connect to Agari | True |
| apikey | API Key | True |
| apisecret | Secret Key | True |
| max_fetch | Maximum number of incidents to fetch every time | True |
| first_fetch | First fetch time interval | False |
| fetch_policy_actions | Policy Action | False |
| exclude_alert_type | Exclude alerts | False |
| policy_filter | Fetches policy events to limit the amount of data. Can be applied to specific fields | False |
| incidentType | Incident type | False |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### apd-list-policy-events
***
Retrieves a list of policy events.


#### Base Command

`apd-list-policy-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to be returned in the paged response. | Optional | 
| start_date | The earliest date time (UTC) a search should target (ISO 8601 format).<br/>Formats accepted: YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days<br/>N hours<br/>Example: 2020-05-01<br/>2020-05-01T00:00:00<br/>2 days<br/>5 hours. | Optional | 
| end_date | The latest date time (UTC) a search should target (ISO 8601 format).<br/>Formats accepted: YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days<br/>N hours<br/>Example: 2020-05-01 <br/>2020-05-01T00:00:00<br/>2 days<br/>5 hours. | Optional | 
| page_id | To page through a collection of policy events. | Optional | 
| sort | A comma-delimited string that specifies the field ordering to be applied to the response. Example: created_at DESC, id ASC. | Optional | 
| add_fields | A comma-delimited list of optional fields to add to the default payload. Additional fields would add data in the entry context. | Optional | 
| rem_fields | A comma-delimited list of fields to remove from the default payload. Limited fields would return limited data in entry context. | Optional | 
| fields | A comma-delimited list of fields to include in the payload. Limited fields would return limited data in entry context. | Optional | 
| filter | Search filters that can be applied to the response. | Optional | 
| exclude_alert_types | Exclude policy types such as 'MessageAlert' or 'SystemAlert'. | Optional | 
| policy_name | Find by policy name. | Optional | 
| policy_action | Filter by policy action: 'deliver', 'mark-spam', 'move', 'inbox', 'delete' and 'none'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AgariPhishingDefense.Alert.alert_definition_name | String | Alert definition name. | 
| AgariPhishingDefense.Alert.id | String | Unique alert id. | 
| AgariPhishingDefense.Alert.summary | String | Summary of the alert. | 
| AgariPhishingDefense.Alert.policy_action | String | Alert policy action. | 
| AgariPhishingDefense.Alert.policy_enabled | Boolean | Indicates if policy is enabled. | 
| AgariPhishingDefense.Alert.updated_at | Date | Updated time of the alert. The format is ISO8601. | 
| AgariPhishingDefense.Alert.created_at | Date | Created time of the alert. The format is ISO8601. | 
| AgariPhishingDefense.Alert.admin_recipients | Unknown | List of notified admin recipients. | 
| AgariPhishingDefense.Alert.notified_original_recipients | Boolean | Indicates whether the original recipient was notified. | 


#### Command Example
```!apd-list-policy-events limit=2```

#### Context Example
```json
{
    "AgariPhishingDefense": {
        "Alert": [
            {
                "alert_definition_name": "Spoof of Partner Domains",
                "created_at": "2020-12-03T04:32:23Z",
                "id": 549904303,
                "notified_original_recipients": false,
                "policy_action": "none",
                "policy_enabled": true,
                "summary": false,
                "updated_at": "2020-12-03T04:32:23Z"
            },
            {
                "alert_definition_name": "Untrusted Messages",
                "created_at": "2020-12-03T04:32:23Z",
                "id": 549904302,
                "notified_original_recipients": false,
                "policy_action": "none",
                "policy_enabled": true,
                "summary": false,
                "updated_at": "2020-12-03T04:32:23Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policy Events
>|Event ID|Alert Definition Name|Policy Action|Notified Original Recipients|Created|Updated|
>|---|---|---|---|---|---|
>| 549904303 | Spoof of Partner Domains | none | false | 2020-12-03T04:32:23Z | 2020-12-03T04:32:23Z |
>| 549904302 | Untrusted Messages | none | false | 2020-12-03T04:32:23Z | 2020-12-03T04:32:23Z |


### apd-list-message-data
***
Retrieves a list of messages.


#### Base Command

`apd-list-message-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The earliest date time (UTC) a search should target (ISO 8601 format).<br/>Formats accepted: YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days<br/>N hours<br/>Example: 2020-05-01 <br/>2020-05-01T00:00:00<br/>2 days<br/>5 hours. | Optional | 
| end_date | The latest date time (UTC) a search should target (ISO 8601 format).<br/>Formats accepted: YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days<br/>N hours<br/>Example: 2020-05-01 <br/>2020-05-01T00:00:00<br/>2 days<br/>5 hours. | Optional | 
| add_fields | A comma-delimited list of optional fields to add to the default payload. Additional fields would add data in the entry context. | Optional | 
| rem_fields | A comma-delimited list of fields to remove from the default payload. Limited fields would return limited data in entry context. | Optional | 
| fields | A comma-delimited list of fields to include in the payload. Limited fields would return limited data in entry context. | Optional | 
| limit | The maximum number of items to be returned in the paged response. | Optional | 
| page_id | To page through a collection of message data. | Optional | 
| sort | A comma-delimited string that specifies the field ordering to be applied to the response. | Optional | 
| search | Search using advanced search syntax.<br/>Format: field operator operand {and/or field operator operand}<br/>Example: has_attachment=true and ip='10.0.0.0'<br/>sbrs in [3.5, 2.6]<br/>domain_reputation is not null<br/>sbrs gt 3<br/>sbrs&gt;=3 and domain_tags eq internal | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AgariPhishingDefense.Message.has_attachment | Boolean | Has attachment. | 
| AgariPhishingDefense.Message.ip | String | IP address. | 
| AgariPhishingDefense.Message.message_id | String | The Global message ID. | 
| AgariPhishingDefense.Message.ptr_name | String | PTR name. | 
| AgariPhishingDefense.Message.sbrs | String | SBRS. | 
| AgariPhishingDefense.Message.id | String | The internal message ID. | 
| AgariPhishingDefense.Message.authenticity | Number | Authenticity score. | 
| AgariPhishingDefense.Message.to | String | Message recipient. | 
| AgariPhishingDefense.Message.date | String | Date in ISO format. | 
| AgariPhishingDefense.Message.timestamp_ms | Number | Timestamp in ms since epoch. | 
| AgariPhishingDefense.Message.from | String | Sender's email. | 
| AgariPhishingDefense.Message.from_domain | String | From domain. | 
| AgariPhishingDefense.Message.subject | String | Message subject. | 
| AgariPhishingDefense.Message.domain_reputation | Number | Reputation of sender domain. | 
| AgariPhishingDefense.Message.message_trust_score | Number | Risk score. | 
| AgariPhishingDefense.Message.message_details_link | String | Link to message details. | 
| AgariPhishingDefense.Message.domain_tags | Unknown | List of domain tags. | 
| AgariPhishingDefense.Message.mail_from | String | Mail from domain. | 
| AgariPhishingDefense.Message.reply_to | String | Reply-to address. | 
| AgariPhishingDefense.Message.uris | Unknown | List of URIs. | 
| AgariPhishingDefense.Message.attachment_extensions | Unknown | List of message attachment extensions. | 
| AgariPhishingDefense.Message.attachment_filenames | Unknown | List of message attachment filenames. | 
| AgariPhishingDefense.Message.attachment_sha256 | Unknown | List of message attachment SHA256 hashes. | 
| AgariPhishingDefense.Message.attachment_types | Unknown | List of message attachment types. | 
| AgariPhishingDefense.Message.attack_types | Unknown | List of attack type classifications. | 
| AgariPhishingDefense.Message.dkim_result | String | DKIM result. | 
| AgariPhishingDefense.Message.dmarc_result | String | DMARC result. | 
| AgariPhishingDefense.Message.domain_dmarc_policy | String | DMARC policy for domain. | 
| AgariPhishingDefense.Message.enforcement_action | String | Enforcement action. | 
| AgariPhishingDefense.Message.enforcement_folder | String | Enforcement folder. | 
| AgariPhishingDefense.Message.enforcement_result | String | Enforcement result. | 
| AgariPhishingDefense.Message.expanded_from | String | Expanded from. | 
| AgariPhishingDefense.Message.forwarded_from | String | Forwarded from. | 
| AgariPhishingDefense.Message.has_malicious_attachment | Boolean | Has malicious attachment. | 
| AgariPhishingDefense.Message.message_read_status | Boolean | Message read status. | 
| AgariPhishingDefense.Message.org_domain | String | Organization domain. | 
| AgariPhishingDefense.Message.policy_ids | Unknown | List of triggered policy IDs. | 
| AgariPhishingDefense.Message.sender_approval_state | String | Sender approval state. | 
| AgariPhishingDefense.Message.sender_type | String | Sender type. | 
| AgariPhishingDefense.Message.spf_result | String | SPF result. | 


#### Command Example
```!apd-list-message-data limit=2```

#### Context Example
```json
{
    "AgariPhishingDefense": {
        "Message": [
            {
                "attack_types": [
                    "spoof (Domain spoof)"
                ],
                "authenticity": "0.085819915",
                "date": "2020-12-03T02:07:02+00:00",
                "domain_reputation": "9.0",
                "domain_tags": [
                    "partner"
                ],
                "enforcement_action": "move",
                "enforcement_result": "pending",
                "from": "Accounts@abc.com",
                "from_domain": "abc.com",
                "has_attachment": "false",
                "id": "785d91a8-34fb-11eb-bf90-f6ba445dac4f",
                "ip": "1.2.3.4",
                "message_details_link": "https://apis.com/messages/785d91a8-34fb-11eb-bf90-f6ba445dac4f",
                "message_id": "<facade2c8712345c91c755d17f1134cb@BY2PR12MB0054.abc.com>",
                "message_trust_score": "0.6",
                "policy_ids": [
                    9014,
                    9008,
                    2843446
                ],
                "subject": "Please approve and forward expense report \"December Expenses\"",
                "timestamp_ms": "1606961222000",
                "to": "acoyle@xyz.com"
            },
            {
                "attack_types": [
                    "spoof (Domain spoof)"
                ],
                "authenticity": "0.07902577",
                "date": "2020-12-03T02:07:02+00:00",
                "domain_reputation": "8.6",
                "domain_tags": [
                    "internal"
                ],
                "enforcement_action": "move",
                "enforcement_result": "pending",
                "from": "help@xyz.com",
                "from_domain": "xyz.com",
                "has_attachment": "false",
                "id": "7852dc68-34fb-11eb-bf90-f6ba445dac4f",
                "ip": "2.2.3.4",
                "message_details_link": "https://apis.com/messages/7852dc68-34fb-11eb-bf90-f6ba445dac4f",
                "message_id": "<facade2c12345f9c91c755d17f1134cb@BY2PR12MB0054.xyz.com>",
                "message_trust_score": "0.8",
                "policy_ids": [
                    9014,
                    9009,
                    2843455
                ],
                "subject": "Please approve and forward expense report \"December Expenses\"",
                "timestamp_ms": "1606961222000",
                "to": "aarmstrong@xyz.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Messages
>|ID|From|To|Subject|Message Trust Score|Domain Reputation|IP|Authenticity|Attack Types|Date|
>|---|---|---|---|---|---|---|---|---|---|
>| 785d91a8-34fb-11eb-bf90-f6ba445dac4f | Accounts@abc.com | acoyle@xyz.com | Please approve and forward expense report "December Expenses" | 0.6 | 9.0 | 1.2.3.4 | 0.085819915 | spoof (Domain spoof) | 2020-12-03T02:07:02+00:00 |
>| 7852dc68-34fb-11eb-bf90-f6ba445dac4f | help@xyz.com | aarmstrong@xyz.com | Please approve and forward expense report "December Expenses" | 0.8 | 8.6 | 2.2.3.4 | 0.07902577 | spoof (Domain spoof) | 2020-12-03T02:07:02+00:00 |


### apd-remediate-message
***
Remediate suspected message.


#### Base Command

`apd-remediate-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The primary identifier to remediate a message (UUID). To retrieve the ID execute the apd-list-message-data command. | Required | 
| operation | An operation to remediate a message. Remediation operation is either 'delete' or 'move'. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!apd-remediate-message id="0e43a684-2e0e-11eb-815a-0a8f2da72108" operation="move"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Message ID - 0e43a684-2e0e-11eb-815a-0a8f2da72108 remediated successfully with operation 'move'.
