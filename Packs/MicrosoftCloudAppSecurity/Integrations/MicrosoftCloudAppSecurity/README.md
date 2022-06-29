Microsoft Cloud App Security is a multimode Cloud Access Security Broker (CASB). It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyber threats across all your cloud services. Use the integration to view and resolve alerts, view activities, view files, and view user accounts.
This integration was integrated and tested with version 178 of MicrosoftCloudAppSecurity.

For more details about how to generate a new token, see [Microsoft Cloud App Security - Managing API tokens](https://docs.microsoft.com/en-us/defender-cloud-apps/api-tokens-legacy).

For more information about which permissions are required for the token owner in Microsoft Cloud App Security, see [Microsoft Cloud App Security - Manage admin access](https://docs.microsoft.com/en-us/cloud-app-security/manage-admins).

## Configure MicrosoftCloudAppSecurity on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MicrosoftCloudAppSecurity.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL \(e.g., https://example.net\) |  | True |
    | User's key to access the API |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident severity |  | False |
    | Maximum alerts to fetch |  | False |
    | First fetch time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | Incident resolution status |  | False |
    | Custom Filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. An example of a Custom Filter is: \{"severity":\{"eq":2\}\}. Note that for filtering by "entity.policy", you should use the ID of the policy. For example, for retrieving the policy: \{"policyType": "ANOMALY_DETECTION", "id": "1234", "label": "Impossible travel", "type": "policyRule"\}" please query on \{"entity.policy":\{"eq":1234\}\}. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-alerts#filters. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### microsoft-cas-alerts-list
***
Returns a list of alerts that match the specified filters.


#### Base Command

`microsoft-cas-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. | Optional | 
| limit | The maximum number of records to return. Default is 50. Default is 50. | Optional | 
| severity | The severity of the alert. Possible values are: "Low", "Medium", and "High". Possible values are: Low, Medium, High. | Optional | 
| resolution_status | The alert resolution status. Possible values are: "Open", "Dismissed", and "Resolved". Possible values are: Open, Dismissed, Resolved. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-alerts#filters. | Optional | 
| alert_id | The alert ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Alerts._id | String | The alert ID. | 
| MicrosoftCloudAppSecurity.Alerts.timestamp | Date | The time the alert was created. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.id | String | The ID of the rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.label | String | The label of the rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.type | String | The type of rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.policyType | String | The policy type of the rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.service.id | Number | The cloud service ID. | 
| MicrosoftCloudAppSecurity.Alerts.service.label | String | The cloud service name. | 
| MicrosoftCloudAppSecurity.Alerts.service.type | String | The cloud service type. | 
| MicrosoftCloudAppSecurity.Alerts.file.id | String | The ID of the alert file. | 
| MicrosoftCloudAppSecurity.Alerts.file.label | String | THe label of the alert file. | 
| MicrosoftCloudAppSecurity.Alerts.file.type | String | The alert file type. | 
| MicrosoftCloudAppSecurity.Alerts.user.id | String | The ID of the user who received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.user.label | String | The label of the user who received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.user.type | String | The type of the user who received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.country.id | String | The country ID where the alert originated. | 
| MicrosoftCloudAppSecurity.Alerts.country.label | String | The country label where the alert originated. | 
| MicrosoftCloudAppSecurity.Alerts.country.type | String | The country type where the alert originated. | 
| MicrosoftCloudAppSecurity.Alerts.ip.id | String | The IP address where the alert came. | 
| MicrosoftCloudAppSecurity.Alerts.ip.label | String | The IP label where the alert came. | 
| MicrosoftCloudAppSecurity.Alerts.ip.type | String | The IP type where the alert came. | 
| MicrosoftCloudAppSecurity.Alerts.ip.triggeredAlert | Boolean | Whether this IP address triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.id | String | The ID of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.label | String | The label of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.type | String | The type of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.inst | Number | The instance of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.saas | Number | The service of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.pa | String | The email of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.entityType | Number | The entity type of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.title | String | The title of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.description | String | The description of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policy.id | String | The ID of the reason \(policy\) that explains why the alert was triggered. | 
| MicrosoftCloudAppSecurity.Alerts.policy.label | String | The label of the reason \(policy\) that explains why the alert was triggered. | 
| MicrosoftCloudAppSecurity.Alerts.policy.policyType | String | The policy type of the reason \(policy\) that explains why the alert was triggered. | 
| MicrosoftCloudAppSecurity.Alerts.threatScore | Number | The threat score of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.isSystemAlert | Boolean | Whether it is a system alert. | 
| MicrosoftCloudAppSecurity.Alerts.statusValue | Number | The status value of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.severityValue | Number | The severity value of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.handledByUser | String | The user who handled the alert. | 
| MicrosoftCloudAppSecurity.Alerts.comment | String | The comment relating to the alert. | 
| MicrosoftCloudAppSecurity.Alerts.resolveTime | Date | The date/time that the alert was resolved. | 


#### Command Example
```!microsoft-cas-alerts-list custom_filter=`{"filters": {"date": {"gte_ndays":30}}, "limit": "3"}````

#### Context Example
```json
{
    "MicrosoftCloudAppSecurity": {
        "Alerts": [
            {
                "URL": "https://example.portal.cloudappsecurity.com/#/alerts/60edead2cdbeaf0b87e13377",
                "_id": "60edead2cdbeaf0b87e13377",
                "account": [
                    {
                        "entityType": 2,
                        "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "inst": 0,
                        "label": "John Example",
                        "pa": "john@example.onmicrosoft.com",
                        "saas": 11161,
                        "type": "account"
                    }
                ],
                "contextId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "country": [
                    {
                        "id": "IL",
                        "label": "IL",
                        "type": "country"
                    },
                    {
                        "id": "NL",
                        "label": "NL",
                        "type": "country"
                    }
                ],
                "description": "<p>The user John Example (john@example.onmicrosoft.com) perform failed sign in activities from remote locations that are considered an impossible travel activity.<br>The user performed failed sign in activities from 1.2.3.6 in Netherlands and 1.2.3.4 in Israel within 96 minutes.<br>If these are IP addresses that are known and safe, add them in the <a href=\"#/subnet\">IP address range page</a> to improve the accuracy of the alerts.</p>",
                "evidence": [
                    {
                        "title": {
                            "parameters": {
                                "app": "Office 365"
                            },
                            "template": "ANUBIS_ADMIN_USER_FEATURE"
                        }
                    },
                    {
                        "title": {
                            "parameters": {
                                "mitre": {
                                    "alternateLink": "https://go.microsoft.com/fwlink/?linkid=2135034",
                                    "label": "MITRE",
                                    "type": "link"
                                },
                                "tactic": "INITIAL_ACCESS"
                            },
                            "template": "ALERTS_MITRE_TACTIC"
                        }
                    }
                ],
                "idValue": 15859716,
                "intent": [
                    2
                ],
                "ip": [
                    {
                        "id": "1.2.3.4",
                        "label": "1.2.3.4",
                        "type": "ip"
                    },
                    {
                        "id": "1.2.3.5",
                        "label": "1.2.3.5",
                        "type": "ip"
                    }
                ],
                "isPreview": false,
                "isSystemAlert": false,
                "is_open": true,
                "policyRule": [
                    {
                        "id": "5e6fa96cb5172297ca756554",
                        "label": "Impossible travel",
                        "policyType": "ANOMALY_DETECTION",
                        "type": "policyRule"
                    }
                ],
                "resolutionStatusValue": 0,
                "service": [
                    {
                        "id": 20893,
                        "label": "Microsoft Exchange Online",
                        "type": "service"
                    },
                    {
                        "id": 11161,
                        "label": "Office 365",
                        "type": "service"
                    },
                    {
                        "id": 12260,
                        "label": "Microsoft Azure",
                        "type": "service"
                    }
                ],
                "severityValue": 1,
                "statusValue": 0,
                "stories": [
                    0
                ],
                "threatScore": 33,
                "threatScoreReasoning": [
                    {
                        "parameters": {
                            "usage": 1,
                            "userPercent": 12
                        },
                        "template": "UEBA_ALERTS_TENANT_USAGE_EVIDENCE"
                    }
                ],
                "timestamp": 1626193095126,
                "title": "Impossible travel activity",
                "user": [
                    {
                        "id": "john@example.onmicrosoft.com",
                        "label": "john@example.onmicrosoft.com",
                        "type": "user"
                    }
                ]
            },
            {
                "URL": "https://example.portal.cloudappsecurity.com/#/alerts/60eda688cdbeaf0b87f5a41e",
                "_id": "60eda688cdbeaf0b87f5a41e",
                "account": [
                    {
                        "em": "john@example.onmicrosoft.com",
                        "entityType": 2,
                        "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "inst": 0,
                        "label": "John Example",
                        "pa": "john@example.onmicrosoft.com",
                        "saas": 11161,
                        "type": "account"
                    }
                ],
                "contextId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "country": [
                    {
                        "id": "NL",
                        "label": "NL",
                        "type": "country"
                    }
                ],
                "description": "John Example performed a risky sign-in.<br><br>Unfamiliar sign-in properties<br>Sign-in with properties we have not seen recently for the given user",
                "evidence": [
                    {
                        "title": {
                            "parameters": {
                                "mitre": {
                                    "alternateLink": "https://go.microsoft.com/fwlink/?linkid=2135034",
                                    "label": "MITRE",
                                    "type": "link"
                                },
                                "tactic": "INITIAL_ACCESS"
                            },
                            "template": "ALERTS_MITRE_TACTIC"
                        }
                    },
                    {
                        "title": {
                            "parameters": {
                                "mitre": {
                                    "alternateLink": "https://go.microsoft.com/fwlink/?linkid=2135034",
                                    "label": "MITRE",
                                    "type": "link"
                                },
                                "tactic": "INITIAL_ACCESS"
                            },
                            "template": "ALERTS_MITRE_TACTIC"
                        }
                    }
                ],
                "idValue": 15795457,
                "intent": [
                    2
                ],
                "ip": [
                    {
                        "id": "1.2.3.6",
                        "label": "1.2.3.6",
                        "type": "ip"
                    }
                ],
                "isSystemAlert": false,
                "is_open": true,
                "policyRule": [
                    {
                        "id": "5e6fa96cb5172297ca75654a",
                        "label": "Risky sign-in",
                        "policyType": "ANOMALY_DETECTION",
                        "type": "policyRule"
                    }
                ],
                "resolutionStatusValue": 0,
                "severityValue": 2,
                "statusValue": 0,
                "stories": [
                    0
                ],
                "threatScore": 0,
                "timestamp": 1626187297290,
                "title": "Risky sign-in: Unfamiliar sign-in properties"
            },
            {
                "URL": "https://example.portal.cloudappsecurity.com/#/alerts/60eaf3cccdbeaf0b87d1a775",
                "_id": "60eaf3cccdbeaf0b87d1a775",
                "account": [
                    {
                        "entityType": 2,
                        "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "inst": 0,
                        "label": "John Example",
                        "pa": "john@example.onmicrosoft.com",
                        "saas": 11161,
                        "type": "account"
                    }
                ],
                "comment": null,
                "contextId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "description": "<p>The user \"John Example (john@example.onmicrosoft.com)\" performed more than 214 administrative activities in a single session.</p>",
                "evidence": [
                    {
                        "title": {
                            "parameters": {
                                "app": "Office 365"
                            },
                            "template": "ANUBIS_ADMIN_USER_FEATURE"
                        }
                    },
                    {
                        "title": {
                            "parameters": {
                                "days": 124,
                                "resource": "1.2.3.4"
                            },
                            "template": "ANUBIS_LAST_SEEN_FEATURE_IP_ALL_TENANT"
                        }
                    }
                ],
                "handledByUser": "john@example.onmicrosoft.com",
                "idValue": 15859721,
                "intent": [
                    4
                ],
                "ip": [
                    {
                        "id": "1.2.3.5",
                        "label": "1.2.3.5",
                        "type": "ip"
                    }
                ],
                "isPreview": false,
                "isSystemAlert": false,
                "is_open": false,
                "policyRule": [
                    {
                        "id": "5e6fa96cb5172297ca756571",
                        "label": "Unusual administrative activity (by user)",
                        "policyType": "ANOMALY_DETECTION",
                        "type": "policyRule"
                    }
                ],
                "resolutionStatusValue": 4,
                "resolveTime": "2021-07-13T18:26:58.662Z",
                "service": [
                    {
                        "id": 20595,
                        "label": "Microsoft Cloud App Security",
                        "type": "service"
                    }
                ],
                "severityValue": 1,
                "statusValue": 0,
                "stories": [
                    0
                ],
                "threatScore": 33,
                "threatScoreReasoning": [
                    {
                        "parameters": {
                            "usage": 1,
                            "userPercent": 12
                        },
                        "template": "UEBA_ALERTS_TENANT_USAGE_EVIDENCE"
                    }
                ],
                "timestamp": 1625995805942,
                "title": "Suspicious administrative activity",
                "user": [
                    {
                        "id": "john@example.onmicrosoft.com",
                        "label": "john@example.onmicrosoft.com",
                        "type": "user"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft CAS Alerts
>|alert_id|alert_date|title|description|status_value|severity_value|is_open|
>|---|---|---|---|---|---|---|
>| 60edead2cdbeaf0b87e13377 | 2021-07-13T16:18:15.126000 | Impossible travel activity | <p>The user John Example (john@example.onmicrosoft.com) perform failed sign in activities from remote locations that are considered an impossible travel activity.<br/>The user performed failed sign in activities from 1.2.3.6 in Netherlands and 1.2.3.4 in Israel within 96 minutes.<br/>If these are IP addresses that are known and safe, add them in the <a href="#/subnet">IP address range page</a> to improve the accuracy of the alerts.</p> | N/A | Medium | true |
>| 60eda688cdbeaf0b87f5a41e | 2021-07-13T14:41:37.290000 | Risky sign-in: Unfamiliar sign-in properties | John Example performed a risky sign-in.<br/><br/>Unfamiliar sign-in properties<br/>Sign-in with properties we have not seen recently for the given user | N/A | High | true |
>| 60eaf3cccdbeaf0b87d1a775 | 2021-07-11T09:30:05.942000 | Suspicious administrative activity | <p>The user "John Example (john@example.onmicrosoft.com)" performed more than 214 administrative activities in a single session.</p> | N/A | Medium | false |


### microsoft-cas-alert-close-benign
***
An alert on a suspicious but not malicious activity, such as a penetration test or other authorized suspicious action


#### Base Command

`microsoft-cas-alert-close-benign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alerts matching the specified filters.<br/>Alert_id should appear similar to - "1234567890abcdefg".<br/>Mandatory, unless you use a custom filter. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| comment | Comment describing why the alerts were dismissed. | Optional | 
| reason | The reason for closing the alerts as benign. Providing a reason helps improve the accuracy of the detection over time. Possible values include:<br/>* Actual severity is lower<br/>* Other<br/>* Confirmed with end user<br/>* Triggered by test. Possible values are: Actual severity is lower, Other, Confirmed with end user, Triggered by test. | Optional | 
| sendFeedback | Whether feedback about this alert is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| feedbackText | The text of the feedback. | Optional | 
| allowContact | Whether consent to contact the user is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| contactEmail | The email address of the user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-cas-alert-close-benign alert_ids=60eaf3cccdbeaf0b87d1a775```

#### Human Readable Output

>1 alerts were closed as benign.

### microsoft-cas-alert-close-true-positive
***
Cֹlose multiple alerts matching the specified filters as true positive (an alert on a confirmed malicious activity.


#### Base Command

`microsoft-cas-alert-close-true-positive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alerts matching the specified filters.<br/>Alert_id should appear similar to - "1234567890abcdefg".<br/>Mandatory, unless you use a custom filter. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| comment | Comment describing why the alerts were dismissed. | Optional | 
| sendFeedback | Whether feedback about this alert is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| feedbackText | The text of the feedback. | Optional | 
| allowContact | Whether consent to contact the user is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| contactEmail | The email address of the user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-cas-alert-close-true-positive alert_ids=60ced07dcdbeaf0b876fc7d3```

#### Human Readable Output

>1 alerts were closed as true-positive.

### microsoft-cas-alert-close-false-positive
***
Close multiple alerts matching the specified filters as false positive (an alert on a non-malicious activity).


#### Base Command

`microsoft-cas-alert-close-false-positive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alerts matching the specified filters.<br/>Alert_id should appear similar to - "1234567890abcdefg".<br/>Mandatory, unless you use a custom filter. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| comment | Comment describing why the alerts were dismissed. Default is None. | Optional | 
| reason | The reason for closing the alerts as false positive. Providing a reason helps improve the accuracy of the detection over time. Possible values include:<br/>* Not of interest<br/>* Too many similar alerts<br/>* Alert is not accurate<br/>* Other. Possible values are: Not of interest, Too many similar alerts, Alert is not accurate, Other. | Optional | 
| sendFeedback | Whether feedback about this alert is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| feedbackText | The text of the feedback. | Optional | 
| allowContact | Whether consent to contact the user is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| contactEmail | The email address of the user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-cas-alert-close-false-positive alert_ids=60cf6d10cdbeaf0b87acdfa9 reason="Alert is not accurate"```

#### Human Readable Output

>1 alerts were closed as false-positive.

### microsoft-cas-activities-list
***
Returns a list of activities that match the specified filters.


#### Base Command

`microsoft-cas-activities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | The number of records to skip. Default is 50. | Optional | 
| limit | Maximum number of records returned to the user. Default is 50. | Optional | 
| ip | The origin of the specified IP address. | Optional | 
| ip_category | The subnet categories. Valid values are: "Corporate", "Administrative", "Risky", "VPN", "Cloud_provider", and "Other". Possible values are: Corporate, Administrative, Risky, VPN, Cloud_provider, Other. | Optional | 
| taken_action | The actions taken on activities. Valid values are: "block", "proxy", "BypassProxy", "encrypt", "decrypt", "verified", "encryptionFailed", "protect", "verify", and "null". Possible values are: block, proxy, BypassProxy, encrypt, decrypt, verified, encryptionFailed, protect, verify. | Optional | 
| source | The source type. Valid values are: "Access_control", "Session_control", "App_connector", "App_connector_analysis", "Discovery", and "MDATP". Possible values are: Access_control, Session_control, App_connector, App_connector_analysis, Discovery, MDATP. | Optional | 
| custom_filter | A custom filter by which to filter the returned activities. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| activity_id | The ID of the activity. | Optional | 
| timeout | Timeout of the request to Microsoft CAS, in seconds. Default is 60 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| MicrosoftCloudAppSecurity.Activities._id | String | The ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.saasId | Number | The ID of the cloud service. | 
| MicrosoftCloudAppSecurity.Activities.timestamp | Date | The time the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.instantiation | Date | The instantiation of the activity. | 
| MicrosoftCloudAppSecurity.Activities.created | Date | The time the activity was created. | 
| MicrosoftCloudAppSecurity.Activities.eventTypeValue | String | The event type of the activity. | 
| MicrosoftCloudAppSecurity.Activities.device.clientIP | String | The device client IP address of the activity. | 
| MicrosoftCloudAppSecurity.Activities.device.userAgent | String | The user agent of the activity. | 
| MicrosoftCloudAppSecurity.Activities.device.countryCode | String | The country code \(name\) of the device. | 
| MicrosoftCloudAppSecurity.Activities.location.countryCode | String | The country code \(name\) of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.city | String | The city of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.region | String | The region of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.longitude | Number | The longitude of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.latitude | Number | The latitude of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.categoryValue | String | The category value of the activity. | 
| MicrosoftCloudAppSecurity.Activities.user.userName | String | The username associated with the activity. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.family | String | The family of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.name | String | The name of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.operatingSystem.name | String | The name of the operating system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.operatingSystem.family | String | The family of the operating system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.type | String | The type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.typeName | String | The name of the type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.version | String | The version of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.deviceType | String | The device type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.nativeBrowser | Boolean | The native browser type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.os | String | The operating system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.browser | String | The browser in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.instanceId | Number | The ID of the instance of the event objects. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.saasId | Number | The ID of the cloud service of the event objects. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.id | String | The ID of the event objects. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.activityResult.isSuccess | Boolean | Whether the activities were successful. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.type | String | The type of activity. | 
| MicrosoftCloudAppSecurity.Activities.confidenceLevel | Number | The confidence level of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.id | String | The user ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.saasId | String | The user cloud service ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.instanceId | String | The user instance ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.name | String | The username of the activity. | 
| MicrosoftCloudAppSecurity.Activities.eventTypeName | String | The event that triggered the activity. | 
| MicrosoftCloudAppSecurity.Activities.classifications | String | The classifications of the activity. | 
| MicrosoftCloudAppSecurity.Activities.entityData.displayName | String | The display name of entity activity. | 
| MicrosoftCloudAppSecurity.Activities.entityData.id.id | String | The ID of the entity activity. | 
| MicrosoftCloudAppSecurity.Activities.entityData.resolved | Boolean | Whether the entity was resolved. | 
| MicrosoftCloudAppSecurity.Activities.description | String | The description of the activity. | 
| MicrosoftCloudAppSecurity.Activities.genericEventType | String | The generic event type of the activity. | 
| MicrosoftCloudAppSecurity.Activities.severity | String | The severity of the activity. | 


#### Command Example
```!microsoft-cas-activities-list limit=4```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "1.2.3.6",
            "Score": 0,
            "Type": "ip",
            "Vendor": "MicrosoftCloudAppSecurity"
        },
        {
            "Indicator": "1.2.3.4",
            "Score": 0,
            "Type": "ip",
            "Vendor": "MicrosoftCloudAppSecurity"
        }
    ],
    "IP": [
        {
            "Address": "1.2.3.6",
            "Geo": {
                "Location": "52.30905:4.94019"
            }
        },
        {
            "Address": "1.2.3.4",
            "Geo": {
                "Location": "50.1109:8.6821"
            }
        }
    ],
    "MicrosoftCloudAppSecurity": {
        "Activities": [
            {
                "_id": "710e5ae7f65ad8e997e3154db373ad08c2304f63e8b49cb98347fded4652131a",
                "aadTenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "appId": 11161,
                "appName": "Office 365",
                "classifications": [
                    "access"
                ],
                "collected": {
                    "aadLogins": {
                        "MCAS_Router": false,
                        "correlationId": "a54f8379-730d-420c-a475-088d8478d894",
                        "enqueueTime": 1626197391062,
                        "routingTime": 1626197391127
                    }
                },
                "confidenceLevel": 30,
                "created": 1626197535294,
                "createdRaw": 1626197535294,
                "description": "Failed log on (Failure message: General failure)",
                "description_id": "EVENT_DESCRIPTION_FAILED_LOGIN",
                "description_metadata": {
                    "activity_result_message": "(Failure message: General failure)",
                    "colon": "",
                    "dash": "",
                    "event_category": "Failed log on"
                },
                "device": {
                    "clientIP": "1.2.3.6",
                    "countryCode": "NL",
                    "userAgent": ";Windows 10;Chrome 91.0;"
                },
                "entityData": [
                    {
                        "displayName": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                        "id": {
                            "id": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                            "inst": 0,
                            "saas": 11161
                        },
                        "resolved": false
                    }
                ],
                "eventRouting": {
                    "auditing": true,
                    "dispersed": true,
                    "lograbber": true,
                    "scubaUnpacker": false
                },
                "eventType": 2293761,
                "eventTypeName": "EVENT_CATEGORY_FAILED_LOGIN",
                "eventTypeValue": "EVENT_AAD_LOGIN_FAILED",
                "failedUserData": {
                    "userName": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com"
                },
                "genericEventType": "ENUM_ACTIVITY_GENERIC_TYPE_FAILED_LOGIN",
                "instantiation": 1626197490954,
                "instantiationRaw": 1626197490954,
                "internals": {
                    "otherIPs": [
                        "1.2.3.6"
                    ]
                },
                "location": {
                    "anonymousProxy": false,
                    "carrier": "eunetworks gmbh",
                    "category": 0,
                    "categoryValue": "NONE",
                    "city": "amsterdam",
                    "countryCode": "NL",
                    "isSatelliteProvider": false,
                    "latitude": 52.30905,
                    "longitude": 4.94019,
                    "organizationSearchable": "eunetworks",
                    "postalCode": "1101",
                    "region": "noord-holland"
                },
                "lograbberService": {
                    "scubaUnpacker": true
                },
                "mainInfo": {
                    "activityResult": {
                        "isSuccess": false,
                        "message": "General failure"
                    },
                    "eventObjects": [
                        {
                            "id": "c61faf03-1cbc-4409-94a9-ae1497de0883",
                            "name": "EWS O365",
                            "objType": 6,
                            "role": 1,
                            "tags": []
                        },
                        {
                            "id": "a25feb7c-f23c-4152-9f46-d87e2e10d800",
                            "name": "Request ID",
                            "objType": 7,
                            "role": 3,
                            "tags": []
                        },
                        {
                            "name": "Pass-through authentication",
                            "objType": 7,
                            "role": 3,
                            "tags": [],
                            "value": "false"
                        },
                        {
                            "id": "58518ac4-40e0-4dc3-a56b-565dcfe4e9d3",
                            "name": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                            "objType": 2,
                            "resolved": false,
                            "role": 2,
                            "tags": [
                                "000000200000000000000000"
                            ]
                        },
                        {
                            "governable": false,
                            "id": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                            "instanceId": 0,
                            "link": 1874981740,
                            "name": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                            "objType": 22,
                            "resolved": false,
                            "role": 5,
                            "saasId": 11161,
                            "tags": [
                                "000000200000000000000000"
                            ]
                        }
                    ],
                    "prettyOperationName": "OAuth2:Authorize",
                    "rawOperationName": "OAuth2:Authorize",
                    "type": "failedLogin"
                },
                "rawDataJson": {
                    "ApplicationId": "c61faf03-1cbc-4409-94a9-ae1497de0883",
                    "ApplicationName": "EWS O365",
                    "BrowserId": "14dc3979-59da-4b8e-b9d3-a49b716b1fe9",
                    "Call": "OAuth2:Authorize",
                    "CorrelationId": "a54f8379-730d-420c-a475-088d8478d894",
                    "DataSource": null,
                    "DeviceInfo": ";Windows 10;Chrome 91.0;",
                    "DeviceTrustType": "",
                    "EventType": "MCASLoginEvent",
                    "HomeTenantUserObjectId": "58518ac4-40e0-4dc3-a56b-565dcfe4e9d3",
                    "IpAddress": "1.2.3.6",
                    "IsDeviceCompliantAndManaged": false,
                    "IsInteractive": null,
                    "IsInteractiveComputed": true,
                    "LoginErrorCode": 16000,
                    "LoginStatus": "Failure",
                    "MfaAuthMethod": null,
                    "MfaMaskedDeviceId": null,
                    "MfaRequired": false,
                    "MfaResult": null,
                    "MfaStatusRaw": null,
                    "MsodsTenantRegionScope": "EU",
                    "RequestId": "a25feb7c-f23c-4152-9f46-d87e2e10d800",
                    "SasStatus": null,
                    "TenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                    "TimeStamp": "2021-07-13T17:26:35.1425646Z",
                    "Upn": "arunvnnk_gmail.com#EXT#@arunvnnkgmail.onmicrosoft.com",
                    "UserIsPassthru": false,
                    "UserName": "",
                    "UserPrincipalObjectID": "58518ac4-40e0-4dc3-a56b-565dcfe4e9d3",
                    "UserTenantId": null,
                    "UserTenantMsodsRegionScope": null
                },
                "resolvedActor": {
                    "governable": false,
                    "id": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                    "instanceId": "0",
                    "name": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                    "objType": "22",
                    "resolved": false,
                    "role": "2",
                    "saasId": "11161",
                    "tags": [
                        "000000200000000000000000"
                    ]
                },
                "resolvedActorAccount": {
                    "governable": false,
                    "id": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                    "instanceId": "0",
                    "name": "arunvnnk_gmail.com#ext#@arunvnnkgmail.onmicrosoft.com",
                    "resolved": false,
                    "role": "2",
                    "saasId": "11161",
                    "tags": [
                        "000000200000000000000000"
                    ]
                },
                "saasId": 11161,
                "severity": "INFO",
                "source": 2,
                "srcAppId": 11161,
                "tenantId": 97134000,
                "timestamp": 1626197195142,
                "timestampRaw": 1626197195142,
                "uid": "710e5ae7f65ad8e997e3154db373ad08c2304f63e8b49cb98347fded4652131a",
                "user": {
                    "userTags": [
                        "000000200000000000000000"
                    ]
                },
                "userAgent": {
                    "browser": "CHROME",
                    "deviceType": "DESKTOP",
                    "family": "CHROME",
                    "major": "91",
                    "minor": "0",
                    "name": "Chrome",
                    "nativeBrowser": false,
                    "operatingSystem": {
                        "family": "Windows",
                        "name": "Windows 10",
                        "version": "10"
                    },
                    "os": "windows",
                    "type": "Browser",
                    "typeName": "Browser",
                    "version": "91.0"
                }
            },
            {
                "_id": "d1b3c191a5563edfbce3f11cad83155cf31552f6f0b40184b423f38e0c39f536",
                "aadTenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "appId": 20893,
                "appName": "Microsoft Exchange Online",
                "classifications": [
                    "access"
                ],
                "collected": {
                    "aadLogins": {
                        "MCAS_Router": false,
                        "correlationId": "e04722ca-92b5-4b3f-b3db-e42941c3baba",
                        "enqueueTime": 1626197400711,
                        "routingTime": 1626197400782
                    }
                },
                "confidenceLevel": 30,
                "created": 1626197422850,
                "createdRaw": 1626197422850,
                "description": "Failed log on (Failure message: Error validating credentials due to invalid username or password.)",
                "description_id": "EVENT_DESCRIPTION_FAILED_LOGIN",
                "description_metadata": {
                    "activity_result_message": "(Failure message: Error validating credentials due to invalid username or password.)",
                    "colon": "",
                    "dash": "",
                    "event_category": "Failed log on"
                },
                "device": {
                    "clientIP": "1.2.3.4",
                    "countryCode": "DE",
                    "userAgent": ";;Python Requests 2.25;"
                },
                "entityData": [
                    {
                        "displayName": "John Example",
                        "id": {
                            "id": "john@example.onmicrosoft.com",
                            "inst": 0,
                            "saas": 11161
                        },
                        "resolved": true
                    },
                    {
                        "displayName": "John Example",
                        "id": {
                            "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "inst": 0,
                            "saas": 11161
                        },
                        "resolved": true
                    }
                ],
                "eventRouting": {
                    "auditing": true,
                    "dispersed": true,
                    "lograbber": true,
                    "scubaUnpacker": false
                },
                "eventType": 2293761,
                "eventTypeName": "EVENT_CATEGORY_FAILED_LOGIN",
                "eventTypeValue": "EVENT_AAD_LOGIN_FAILED",
                "failedUserData": {
                    "userName": "john@example.onmicrosoft.com"
                },
                "genericEventType": "ENUM_ACTIVITY_GENERIC_TYPE_FAILED_LOGIN",
                "instantiation": 1626197422679,
                "instantiationRaw": 1626197422679,
                "internals": {
                    "otherIPs": [
                        "1.2.3.4"
                    ]
                },
                "location": {
                    "anonymousProxy": false,
                    "carrier": "amazon.com%2C inc",
                    "category": 5,
                    "categoryValue": "CLOUD_PROXY_NETWORK_IP",
                    "city": "frankfurt am main",
                    "countryCode": "DE",
                    "ipTags": [
                        "000000290000000000000000"
                    ],
                    "isSatelliteProvider": false,
                    "latitude": 50.1109,
                    "longitude": 8.6821,
                    "organizationSearchable": "Amazon Web Services",
                    "postalCode": "60311",
                    "region": "hessen"
                },
                "lograbberService": {
                    "scubaUnpacker": true
                },
                "mainInfo": {
                    "activityResult": {
                        "isSuccess": false,
                        "message": "Error validating credentials due to invalid username or password."
                    },
                    "eventObjects": [
                        {
                            "id": "00000002-0000-0ff1-ce00-000000000000",
                            "name": "Office 365 Exchange Online",
                            "objType": 6,
                            "role": 1,
                            "tags": []
                        },
                        {
                            "id": "81f8ad85-b492-47a5-9138-a06543a0db00",
                            "name": "Request ID",
                            "objType": 7,
                            "role": 3,
                            "tags": []
                        },
                        {
                            "name": "Pass-through authentication",
                            "objType": 7,
                            "role": 3,
                            "tags": [],
                            "value": "false"
                        },
                        {
                            "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "name": "john@example.onmicrosoft.com",
                            "objType": 2,
                            "resolved": true,
                            "role": 2,
                            "tags": []
                        },
                        {
                            "governable": false,
                            "id": "john@example.onmicrosoft.com",
                            "instanceId": 0,
                            "link": -162371653,
                            "name": "John Example",
                            "objType": 21,
                            "resolved": true,
                            "role": 5,
                            "saasId": 11161,
                            "tags": []
                        },
                        {
                            "governable": true,
                            "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "instanceId": 0,
                            "link": -162371653,
                            "name": "John Example",
                            "objType": 23,
                            "resolved": true,
                            "role": 5,
                            "saasId": 11161,
                            "tags": [
                                "5f01dbbc68df27c17aa6ca81"
                            ]
                        }
                    ],
                    "prettyOperationName": "OAuth2:Token",
                    "rawOperationName": "OAuth2:Token",
                    "type": "failedLogin"
                },
                "rawDataJson": {
                    "ApplicationId": "00000002-0000-0ff1-ce00-000000000000",
                    "ApplicationName": "Office 365 Exchange Online",
                    "BrowserId": null,
                    "Call": "OAuth2:Token",
                    "CorrelationId": "e04722ca-92b5-4b3f-b3db-e42941c3baba",
                    "DataSource": null,
                    "DeviceInfo": ";;Python Requests 2.25;",
                    "DeviceTrustType": "",
                    "EventType": "MCASLoginEvent",
                    "HomeTenantUserObjectId": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                    "IpAddress": "1.2.3.4",
                    "IsDeviceCompliantAndManaged": false,
                    "IsInteractive": null,
                    "IsInteractiveComputed": true,
                    "LoginErrorCode": 50126,
                    "LoginStatus": "Failure",
                    "MfaAuthMethod": null,
                    "MfaMaskedDeviceId": null,
                    "MfaRequired": false,
                    "MfaResult": null,
                    "MfaStatusRaw": null,
                    "MsodsTenantRegionScope": "EU",
                    "RequestId": "81f8ad85-b492-47a5-9138-a06543a0db00",
                    "SasStatus": null,
                    "TenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                    "TimeStamp": "2021-07-13T17:26:24.4185255Z",
                    "Upn": "john@example.onmicrosoft.com",
                    "UserIsPassthru": false,
                    "UserName": "",
                    "UserPrincipalObjectID": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                    "UserTenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                    "UserTenantMsodsRegionScope": "EU"
                },
                "resolvedActor": {
                    "governable": true,
                    "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                    "instanceId": "0",
                    "name": "John Example",
                    "objType": "23",
                    "resolved": true,
                    "role": "2",
                    "saasId": "11161",
                    "tags": [
                        "5f01dbbc68df27c17aa6ca81"
                    ]
                },
                "saasId": 20893,
                "severity": "INFO",
                "source": 2,
                "srcAppId": 11161,
                "tenantId": 97134000,
                "timestamp": 1626197184418,
                "timestampRaw": 1626197184418,
                "uid": "d1b3c191a5563edfbce3f11cad83155cf31552f6f0b40184b423f38e0c39f536",
                "user": {
                    "userTags": [
                        "5f01dbbc68df27c17aa6ca81"
                    ]
                },
                "userAgent": {
                    "browser": "UNKNOWN",
                    "deviceType": "OTHER",
                    "family": "UNKNOWN",
                    "name": "Unknown",
                    "nativeBrowser": false,
                    "operatingSystem": {
                        "family": "Unknown",
                        "name": "Unknown"
                    },
                    "os": "OTHER",
                    "type": "Unknown",
                    "typeName": "Unknown"
                }
            },
            {
                "_id": "88b16c7195bd0bda2b9f4fff1f8eb22c34edc164dd16baf3d608ad4dba413fc0",
                "aadTenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "appId": 20893,
                "appName": "Microsoft Exchange Online",
                "classifications": [
                    "access"
                ],
                "collected": {
                    "aadLogins": {
                        "MCAS_Router": false,
                        "correlationId": "e2e0afa3-e52b-46d8-9550-10a78a8fbaba",
                        "enqueueTime": 1626197400711,
                        "routingTime": 1626197400782
                    }
                },
                "confidenceLevel": 30,
                "created": 1626197423060,
                "createdRaw": 1626197423060,
                "description": "Failed log on (Failure message: Error validating credentials due to invalid username or password.)",
                "description_id": "EVENT_DESCRIPTION_FAILED_LOGIN",
                "description_metadata": {
                    "activity_result_message": "(Failure message: Error validating credentials due to invalid username or password.)",
                    "colon": "",
                    "dash": "",
                    "event_category": "Failed log on"
                },
                "device": {
                    "clientIP": "1.2.3.4",
                    "countryCode": "DE",
                    "userAgent": ";;Python Requests 2.25;"
                },
                "entityData": [
                    {
                        "displayName": "John Example",
                        "id": {
                            "id": "john@example.onmicrosoft.com",
                            "inst": 0,
                            "saas": 11161
                        },
                        "resolved": true
                    },
                    {
                        "displayName": "John Example",
                        "id": {
                            "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "inst": 0,
                            "saas": 11161
                        },
                        "resolved": true
                    }
                ],
                "eventRouting": {
                    "auditing": true,
                    "dispersed": true,
                    "lograbber": true,
                    "scubaUnpacker": false
                },
                "eventType": 2293761,
                "eventTypeName": "EVENT_CATEGORY_FAILED_LOGIN",
                "eventTypeValue": "EVENT_AAD_LOGIN_FAILED",
                "failedUserData": {
                    "userName": "john@example.onmicrosoft.com"
                },
                "genericEventType": "ENUM_ACTIVITY_GENERIC_TYPE_FAILED_LOGIN",
                "instantiation": 1626197422564,
                "instantiationRaw": 1626197422564,
                "internals": {
                    "otherIPs": [
                        "1.2.3.4"
                    ]
                },
                "location": {
                    "anonymousProxy": false,
                    "carrier": "amazon.com%2C inc",
                    "category": 5,
                    "categoryValue": "CLOUD_PROXY_NETWORK_IP",
                    "city": "frankfurt am main",
                    "countryCode": "DE",
                    "ipTags": [
                        "000000290000000000000000"
                    ],
                    "isSatelliteProvider": false,
                    "latitude": 50.1109,
                    "longitude": 8.6821,
                    "organizationSearchable": "Amazon Web Services",
                    "postalCode": "60311",
                    "region": "hessen"
                },
                "lograbberService": {
                    "scubaUnpacker": true
                },
                "mainInfo": {
                    "activityResult": {
                        "isSuccess": false,
                        "message": "Error validating credentials due to invalid username or password."
                    },
                    "eventObjects": [
                        {
                            "id": "00000002-0000-0ff1-ce00-000000000000",
                            "name": "Office 365 Exchange Online",
                            "objType": 6,
                            "role": 1,
                            "tags": []
                        },
                        {
                            "id": "81f8ad85-b492-47a5-9138-a065b49fdb00",
                            "name": "Request ID",
                            "objType": 7,
                            "role": 3,
                            "tags": []
                        },
                        {
                            "name": "Pass-through authentication",
                            "objType": 7,
                            "role": 3,
                            "tags": [],
                            "value": "false"
                        },
                        {
                            "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "name": "john@example.onmicrosoft.com",
                            "objType": 2,
                            "resolved": true,
                            "role": 2,
                            "tags": []
                        },
                        {
                            "governable": false,
                            "id": "john@example.onmicrosoft.com",
                            "instanceId": 0,
                            "link": -162371653,
                            "name": "John Example",
                            "objType": 21,
                            "resolved": true,
                            "role": 5,
                            "saasId": 11161,
                            "tags": []
                        },
                        {
                            "governable": true,
                            "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "instanceId": 0,
                            "link": -162371653,
                            "name": "John Example",
                            "objType": 23,
                            "resolved": true,
                            "role": 5,
                            "saasId": 11161,
                            "tags": [
                                "5f01dbbc68df27c17aa6ca81"
                            ]
                        }
                    ],
                    "prettyOperationName": "OAuth2:Token",
                    "rawOperationName": "OAuth2:Token",
                    "type": "failedLogin"
                },
                "rawDataJson": {
                    "ApplicationId": "00000002-0000-0ff1-ce00-000000000000",
                    "ApplicationName": "Office 365 Exchange Online",
                    "BrowserId": null,
                    "Call": "OAuth2:Token",
                    "CorrelationId": "e2e0afa3-e52b-46d8-9550-10a78a8fbaba",
                    "DataSource": null,
                    "DeviceInfo": ";;Python Requests 2.25;",
                    "DeviceTrustType": "",
                    "EventType": "MCASLoginEvent",
                    "HomeTenantUserObjectId": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                    "IpAddress": "1.2.3.4",
                    "IsDeviceCompliantAndManaged": false,
                    "IsInteractive": null,
                    "IsInteractiveComputed": true,
                    "LoginErrorCode": 50126,
                    "LoginStatus": "Failure",
                    "MfaAuthMethod": null,
                    "MfaMaskedDeviceId": null,
                    "MfaRequired": false,
                    "MfaResult": null,
                    "MfaStatusRaw": null,
                    "MsodsTenantRegionScope": "EU",
                    "RequestId": "81f8ad85-b492-47a5-9138-a065b49fdb00",
                    "SasStatus": null,
                    "TenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                    "TimeStamp": "2021-07-13T17:26:18.8088432Z",
                    "Upn": "john@example.onmicrosoft.com",
                    "UserIsPassthru": false,
                    "UserName": "",
                    "UserPrincipalObjectID": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                    "UserTenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                    "UserTenantMsodsRegionScope": "EU"
                },
                "resolvedActor": {
                    "governable": true,
                    "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                    "instanceId": "0",
                    "name": "John Example",
                    "objType": "23",
                    "resolved": true,
                    "role": "2",
                    "saasId": "11161",
                    "tags": [
                        "5f01dbbc68df27c17aa6ca81"
                    ]
                },
                "saasId": 20893,
                "severity": "INFO",
                "source": 2,
                "srcAppId": 11161,
                "tenantId": 97134000,
                "timestamp": 1626197178808,
                "timestampRaw": 1626197178808,
                "uid": "88b16c7195bd0bda2b9f4fff1f8eb22c34edc164dd16baf3d608ad4dba413fc0",
                "user": {
                    "userTags": [
                        "5f01dbbc68df27c17aa6ca81"
                    ]
                },
                "userAgent": {
                    "browser": "UNKNOWN",
                    "deviceType": "OTHER",
                    "family": "UNKNOWN",
                    "name": "Unknown",
                    "nativeBrowser": false,
                    "operatingSystem": {
                        "family": "Unknown",
                        "name": "Unknown"
                    },
                    "os": "OTHER",
                    "type": "Unknown",
                    "typeName": "Unknown"
                }
            },
            {
                "_id": "4b23b9daccf2604cec7fc8654bd98480707b0114450dac11c4a9feab98ca2499",
                "aadTenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                "appId": 11161,
                "appName": "Office 365",
                "classifications": [
                    "access"
                ],
                "collected": {
                    "aadLogins": {
                        "MCAS_Router": false,
                        "correlationId": "923cb4be-cba8-4102-b9fc-1e71f3135680",
                        "enqueueTime": 1626197312908,
                        "routingTime": 1626197312965
                    }
                },
                "confidenceLevel": 30,
                "created": 1626197344376,
                "createdRaw": 1626197344376,
                "description": "Failed log on (Failure message: Session information is not sufficient for single-sign-on.)",
                "description_id": "EVENT_DESCRIPTION_FAILED_LOGIN",
                "description_metadata": {
                    "activity_result_message": "(Failure message: Session information is not sufficient for single-sign-on.)",
                    "colon": "",
                    "dash": "",
                    "event_category": "Failed log on"
                },
                "device": {
                    "clientIP": "1.2.3.6",
                    "countryCode": "NL",
                    "userAgent": ";Windows 10;Chrome 91.0;"
                },
                "entityData": [
                    {
                        "displayName": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                        "id": {
                            "id": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                            "inst": 0,
                            "saas": 11161
                        },
                        "resolved": false
                    }
                ],
                "eventRouting": {
                    "auditing": true,
                    "dispersed": true,
                    "lograbber": true,
                    "scubaUnpacker": false
                },
                "eventType": 2293761,
                "eventTypeName": "EVENT_CATEGORY_FAILED_LOGIN",
                "eventTypeValue": "EVENT_AAD_LOGIN_FAILED",
                "failedUserData": {
                    "userName": "spamphishing@arunvnnkgmail.onmicrosoft.com"
                },
                "genericEventType": "ENUM_ACTIVITY_GENERIC_TYPE_FAILED_LOGIN",
                "instantiation": 1626197343779,
                "instantiationRaw": 1626197343779,
                "internals": {
                    "otherIPs": [
                        "1.2.3.6"
                    ]
                },
                "location": {
                    "anonymousProxy": false,
                    "carrier": "eunetworks gmbh",
                    "category": 0,
                    "categoryValue": "NONE",
                    "city": "amsterdam",
                    "countryCode": "NL",
                    "isSatelliteProvider": false,
                    "latitude": 52.30905,
                    "longitude": 4.94019,
                    "organizationSearchable": "eunetworks",
                    "postalCode": "1101",
                    "region": "noord-holland"
                },
                "lograbberService": {
                    "scubaUnpacker": true
                },
                "mainInfo": {
                    "activityResult": {
                        "isSuccess": false,
                        "message": "Session information is not sufficient for single-sign-on."
                    },
                    "eventObjects": [
                        {
                            "id": "c61faf03-1cbc-4409-94a9-ae1497de0883",
                            "name": "EWS O365",
                            "objType": 6,
                            "role": 1,
                            "tags": []
                        },
                        {
                            "id": "0d0db62a-043e-447c-8ab3-1f2a184ec700",
                            "name": "Request ID",
                            "objType": 7,
                            "role": 3,
                            "tags": []
                        },
                        {
                            "name": "Pass-through authentication",
                            "objType": 7,
                            "role": 3,
                            "tags": [],
                            "value": "false"
                        },
                        {
                            "id": "76603c3a-c483-4111-8893-c69b172503ab",
                            "name": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                            "objType": 2,
                            "resolved": false,
                            "role": 2,
                            "tags": [
                                "000000200000000000000000"
                            ]
                        },
                        {
                            "governable": false,
                            "id": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                            "instanceId": 0,
                            "link": 279741149,
                            "name": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                            "objType": 22,
                            "resolved": false,
                            "role": 5,
                            "saasId": 11161,
                            "tags": [
                                "000000200000000000000000"
                            ]
                        }
                    ],
                    "prettyOperationName": "Login:reprocess",
                    "rawOperationName": "Login:reprocess",
                    "type": "failedLogin"
                },
                "rawDataJson": {
                    "ApplicationId": "c61faf03-1cbc-4409-94a9-ae1497de0883",
                    "ApplicationName": "EWS O365",
                    "BrowserId": "14dc3979-59da-4b8e-b9d3-a49b716b1fe9",
                    "Call": "Login:reprocess",
                    "CorrelationId": "923cb4be-cba8-4102-b9fc-1e71f3135680",
                    "DataSource": null,
                    "DeviceInfo": ";Windows 10;Chrome 91.0;",
                    "DeviceTrustType": "",
                    "EventType": "MCASLoginEvent",
                    "HomeTenantUserObjectId": "76603c3a-c483-4111-8893-c69b172503ab",
                    "IpAddress": "1.2.3.6",
                    "IsDeviceCompliantAndManaged": false,
                    "IsInteractive": null,
                    "IsInteractiveComputed": true,
                    "LoginErrorCode": 50058,
                    "LoginStatus": "Failure",
                    "MfaAuthMethod": null,
                    "MfaMaskedDeviceId": null,
                    "MfaRequired": false,
                    "MfaResult": null,
                    "MfaStatusRaw": null,
                    "MsodsTenantRegionScope": "EU",
                    "RequestId": "0d0db62a-043e-447c-8ab3-1f2a184ec700",
                    "SasStatus": null,
                    "TenantId": "cafe1a16-cafe-dead-beef-1337c3c1d999",
                    "TimeStamp": "2021-07-13T17:26:14.6101710Z",
                    "Upn": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                    "UserIsPassthru": false,
                    "UserName": "",
                    "UserPrincipalObjectID": "76603c3a-c483-4111-8893-c69b172503ab",
                    "UserTenantId": null,
                    "UserTenantMsodsRegionScope": null
                },
                "resolvedActor": {
                    "governable": false,
                    "id": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                    "instanceId": "0",
                    "name": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                    "objType": "22",
                    "resolved": false,
                    "role": "2",
                    "saasId": "11161",
                    "tags": [
                        "000000200000000000000000"
                    ]
                },
                "resolvedActorAccount": {
                    "governable": false,
                    "id": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                    "instanceId": "0",
                    "name": "spamphishing@arunvnnkgmail.onmicrosoft.com",
                    "resolved": false,
                    "role": "2",
                    "saasId": "11161",
                    "tags": [
                        "000000200000000000000000"
                    ]
                },
                "saasId": 11161,
                "severity": "INFO",
                "source": 2,
                "srcAppId": 11161,
                "tenantId": 97134000,
                "timestamp": 1626197174610,
                "timestampRaw": 1626197174610,
                "uid": "4b23b9daccf2604cec7fc8654bd98480707b0114450dac11c4a9feab98ca2499",
                "user": {
                    "userTags": [
                        "000000200000000000000000"
                    ]
                },
                "userAgent": {
                    "browser": "CHROME",
                    "deviceType": "DESKTOP",
                    "family": "CHROME",
                    "major": "91",
                    "minor": "0",
                    "name": "Chrome",
                    "nativeBrowser": false,
                    "operatingSystem": {
                        "family": "Windows",
                        "name": "Windows 10",
                        "version": "10"
                    },
                    "os": "windows",
                    "type": "Browser",
                    "typeName": "Browser",
                    "version": "91.0"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft CAS Activity
>|activity_id|activity_date|app_name|description|severity|
>|---|---|---|---|---|
>| 4b23b9daccf2604cec7fc8654bd98480707b0114450dac11c4a9feab98ca2499 | 2021-07-13T17:26:14.610000 | Office 365 | Failed log on (Failure message: Session information is not sufficient for single-sign-on.) | INFO |


### microsoft-cas-files-list
***
Returns a list of files that match the specified filters. Filters include file type, file share value, file extension, file quarantine status, and a custom filter. If you pass the custom_filter argument it will override the other filters in this command.


#### Base Command

`microsoft-cas-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. Default is 50. | Optional | 
| limit | Maximum number of records to return. Default is 50. | Optional | 
| file_type | The file type. Valid value are: Other, Document, Spreadsheet, Presentation, Text, Image, and Folder. Possible values are: Other, Document, Spreadsheet, Presentation, Text, Image, Folder. | Optional | 
| sharing | Filter files with the specified sharing levels. Valid values are: Private, Internal, External, Public, Public_Internet. Possible values are: Private, Internal, External, Public, Public_Internet. | Optional | 
| extension | Filter files by the specified file extension. | Optional | 
| quarantined | Filter by whether the file is quarantined. Valid values are: "True" or "False". Possible values are: True, False. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| file_id | Filter by the file ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Files._id | String | The ID of the file. | 
| MicrosoftCloudAppSecurity.Files.saasId | Number | The cloud service ID of the file. | 
| MicrosoftCloudAppSecurity.Files.instId | Number | The instance ID of the file. | 
| MicrosoftCloudAppSecurity.Files.fileSize | Number | The size of the file. | 
| MicrosoftCloudAppSecurity.Files.createdDate | Date | The date the file was created. | 
| MicrosoftCloudAppSecurity.Files.modifiedDate | Date | The date the file was last modified. | 
| MicrosoftCloudAppSecurity.Files.parentId | String | The parent ID of the file. | 
| MicrosoftCloudAppSecurity.Files.ownerName | String | The name of the file owner. | 
| MicrosoftCloudAppSecurity.Files.isFolder | Boolean | Whether the file is a folder. | 
| MicrosoftCloudAppSecurity.Files.fileType | String | The file type. | 
| MicrosoftCloudAppSecurity.Files.name | String | The name of the file. | 
| MicrosoftCloudAppSecurity.Files.isForeign | Boolean | Whether the file is foreign. | 
| MicrosoftCloudAppSecurity.Files.noGovernance | Boolean | Whether the file is no governance. | 
| MicrosoftCloudAppSecurity.Files.fileAccessLevel | String | The access level of the file. | 
| MicrosoftCloudAppSecurity.Files.ownerAddress | String | The email address of the file owner. | 
| MicrosoftCloudAppSecurity.Files.externalShares | String | The external shares of the file. | 
| MicrosoftCloudAppSecurity.Files.domains | String | The domains of the file. | 
| MicrosoftCloudAppSecurity.Files.mimeType | String | The mime type of the file. | 
| MicrosoftCloudAppSecurity.Files.ownerExternal | Boolean | Whether the owner of this file is external. | 
| MicrosoftCloudAppSecurity.Files.fileExtension | String | The file extension. | 
| MicrosoftCloudAppSecurity.Files.groupIds | String | The group IDs of the file. | 
| MicrosoftCloudAppSecurity.Files.groups | String | The group the file belongs to. | 
| MicrosoftCloudAppSecurity.Files.collaborators | String | The collaborators of the file. | 
| MicrosoftCloudAppSecurity.Files.fileStatus | String | The status of the file. | 
| MicrosoftCloudAppSecurity.Files.appName | String | The name of the app. | 
| MicrosoftCloudAppSecurity.Files.actions.task_name | String | The name of the task. | 
| MicrosoftCloudAppSecurity.Files.actions.type | String | The type of actions taken on the file. | 


#### Command Example
```!microsoft-cas-files-list file_type=Text skip=4 limit=5```

#### Context Example
```json
{
    "MicrosoftCloudAppSecurity": {
        "Files": [
            {
                "_id": "5f60838dc3b664209dab9a97",
                "_tid": 97134000,
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20200525154133.JPG.txt"
                            },
                            "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "QuarantineTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": null,
                        "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "RescanFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 0
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20200525154133.JPG.txt"
                            },
                            "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "TrashFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    }
                ],
                "alternateLink": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20200525154133.JPG.txt",
                "appId": 15600,
                "appName": "Microsoft OneDrive for Business",
                "collaborators": [],
                "createdDate": 1600160394000,
                "display_collaborators": [],
                "dlpScanResults": [],
                "domains": [
                    "example.onmicrosoft.com"
                ],
                "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                "effectiveParents": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "emails": [
                    "john@example.onmicrosoft.com"
                ],
                "enriched": true,
                "externalShares": [],
                "fTags": [],
                "facl": 0,
                "fileAccessLevel": "PRIVATE",
                "fileExtension": "txt",
                "filePath": "/personal/avishai_example_onmicrosoft_com/Documents/20200525154133.JPG.txt",
                "fileSize": 149,
                "fileStatus": "EXISTS",
                "fileType": "TEXT",
                "fstat": 0,
                "ftype": 4,
                "groupIds": [],
                "groups": [],
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|2cdab441-4e3a-4b39-9d89-144292043e3b",
                "instId": 0,
                "isFolder": false,
                "isForeign": false,
                "lastNrtTimestamp": 1600223135932,
                "mimeType": "text/plain",
                "modifiedDate": 1600160411000,
                "name": "20200525154133.JPG.txt",
                "name_l": "20200525154133.jpg.txt",
                "noGovernance": false,
                "originalId": "5f60838dc3b664209dab9a97",
                "ownerAddress": "john@example.onmicrosoft.com",
                "ownerExternal": false,
                "ownerName": "John Example",
                "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
                "parentIds": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "saasId": 15600,
                "scanVersion": 4,
                "sharepointItem": {
                    "Author": {
                        "Email": "john@example.onmicrosoft.com",
                        "LoginName": "i:0#.f|membership|john@example.onmicrosoft.com",
                        "Title": "John Example",
                        "externalUser": false,
                        "idInSiteCollection": "4",
                        "name": "John Example",
                        "oneDriveEmail": "john@example.onmicrosoft.com",
                        "sipAddress": "john@example.onmicrosoft.com",
                        "sourceBitmask": 0,
                        "trueEmail": "john@example.onmicrosoft.com"
                    },
                    "Length": 149,
                    "LinkingUrl": "",
                    "ModifiedBy": {
                        "Email": "",
                        "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@example.onmicrosoft.com",
                        "Title": "Cloud App Security Service Account for SharePoint"
                    },
                    "Name": "20200525154133.JPG.txt",
                    "ServerRelativeUrl": "/personal/avishai_example_onmicrosoft_com/Documents/20200525154133.JPG.txt",
                    "TimeCreated": "2020-09-15T08:59:54Z",
                    "TimeLastModified": "2020-09-15T09:00:11Z",
                    "UniqueId": "2cdab441-4e3a-4b39-9d89-144292043e3b",
                    "encodedAbsUrl": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20200525154133.JPG.txt",
                    "hasUniqueRoleAssignments": false,
                    "isFolder": false,
                    "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
                    "roleAssignments": [],
                    "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
                    "urlFromMetadata": null
                },
                "siteCollection": "/personal/avishai_example_onmicrosoft_com",
                "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "sitePath": "/personal/avishai_example_onmicrosoft_com",
                "snapshotLastModifiedDate": "2020-09-16T02:25:36.178Z",
                "spDomain": "https://example-my.sharepoint.com",
                "unseenScans": 0
            },
            {
                "_id": "5f39f079c3b664209de9c64c",
                "_tid": 97134000,
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt"
                            },
                            "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "QuarantineTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": null,
                        "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "RescanFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 0
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt"
                            },
                            "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "TrashFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    }
                ],
                "alternateLink": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/WhatsApp%20Image%202020-08-02%20at%2011.04.46.jpeg.txt",
                "appId": 15600,
                "appName": "Microsoft OneDrive for Business",
                "collaborators": [],
                "createdDate": 1597632377000,
                "display_collaborators": [],
                "dlpScanResults": [],
                "domains": [
                    "example.onmicrosoft.com"
                ],
                "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                "effectiveParents": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "emails": [
                    "john@example.onmicrosoft.com"
                ],
                "enriched": true,
                "externalShares": [],
                "fTags": [],
                "facl": 0,
                "fileAccessLevel": "PRIVATE",
                "fileExtension": "txt",
                "filePath": "/personal/avishai_example_onmicrosoft_com/Documents/WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt",
                "fileSize": 149,
                "fileStatus": "EXISTS",
                "fileType": "TEXT",
                "fstat": 0,
                "ftype": 4,
                "groupIds": [],
                "groups": [],
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|812d72fe-b578-4541-9767-16a546c64222",
                "instId": 0,
                "isFolder": false,
                "isForeign": false,
                "lastNrtTimestamp": 1597632633789,
                "mimeType": "text/plain",
                "modifiedDate": 1597632393000,
                "name": "WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt",
                "name_l": "whatsapp image 2020-08-02 at 11.04.46.jpeg.txt",
                "noGovernance": false,
                "originalId": "5f39f079c3b664209de9c64c",
                "ownerAddress": "john@example.onmicrosoft.com",
                "ownerExternal": false,
                "ownerName": "John Example",
                "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
                "parentIds": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "saasId": 15600,
                "scanVersion": 4,
                "sharepointItem": {
                    "Author": {
                        "Email": "john@example.onmicrosoft.com",
                        "LoginName": "i:0#.f|membership|john@example.onmicrosoft.com",
                        "Title": "John Example",
                        "externalUser": false,
                        "idInSiteCollection": "4",
                        "name": "John Example",
                        "oneDriveEmail": "john@example.onmicrosoft.com",
                        "sipAddress": "john@example.onmicrosoft.com",
                        "sourceBitmask": 0,
                        "trueEmail": "john@example.onmicrosoft.com"
                    },
                    "Length": 149,
                    "LinkingUrl": "",
                    "ModifiedBy": {
                        "Email": "",
                        "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@example.onmicrosoft.com",
                        "Title": "Cloud App Security Service Account for SharePoint"
                    },
                    "Name": "WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt",
                    "ServerRelativeUrl": "/personal/avishai_example_onmicrosoft_com/Documents/WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt",
                    "TimeCreated": "2020-08-17T02:46:17Z",
                    "TimeLastModified": "2020-08-17T02:46:33Z",
                    "UniqueId": "812d72fe-b578-4541-9767-16a546c64222",
                    "encodedAbsUrl": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/WhatsApp%20Image%202020-08-02%20at%2011.04.46.jpeg.txt",
                    "hasUniqueRoleAssignments": false,
                    "isFolder": false,
                    "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
                    "roleAssignments": [],
                    "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
                    "urlFromMetadata": null
                },
                "siteCollection": "/personal/avishai_example_onmicrosoft_com",
                "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "sitePath": "/personal/avishai_example_onmicrosoft_com",
                "snapshotLastModifiedDate": "2020-08-17T03:17:49.940Z",
                "spDomain": "https://example-my.sharepoint.com",
                "unseenScans": 0
            },
            {
                "_id": "5f306f37c3b664209d444bf2",
                "_tid": 97134000,
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20180726150700.JPG.txt"
                            },
                            "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "QuarantineTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": null,
                        "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "RescanFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 0
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20180726150700.JPG.txt"
                            },
                            "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "TrashFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    }
                ],
                "alternateLink": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20180726150700.JPG.txt",
                "appId": 15600,
                "appName": "Microsoft OneDrive for Business",
                "collaborators": [],
                "createdDate": 1597009526000,
                "display_collaborators": [],
                "dlpScanResults": [],
                "domains": [
                    "example.onmicrosoft.com"
                ],
                "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                "effectiveParents": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "emails": [
                    "john@example.onmicrosoft.com"
                ],
                "enriched": true,
                "externalShares": [],
                "fTags": [],
                "facl": 0,
                "fileAccessLevel": "PRIVATE",
                "fileExtension": "txt",
                "filePath": "/personal/avishai_example_onmicrosoft_com/Documents/20180726150700.JPG.txt",
                "fileSize": 149,
                "fileStatus": "EXISTS",
                "fileType": "TEXT",
                "fstat": 0,
                "ftype": 4,
                "groupIds": [],
                "groups": [],
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|05dc1be3-d09f-401c-b2f2-1bb8ef4461cb",
                "instId": 0,
                "isFolder": false,
                "isForeign": false,
                "lastNrtTimestamp": 1597009774796,
                "mimeType": "text/plain",
                "modifiedDate": 1597009553000,
                "name": "20180726150700.JPG.txt",
                "name_l": "20180726150700.jpg.txt",
                "noGovernance": false,
                "originalId": "5f306f37c3b664209d444bf2",
                "ownerAddress": "john@example.onmicrosoft.com",
                "ownerExternal": false,
                "ownerName": "John Example",
                "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
                "parentIds": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "saasId": 15600,
                "scanVersion": 4,
                "sharepointItem": {
                    "Author": {
                        "Email": "john@example.onmicrosoft.com",
                        "LoginName": "i:0#.f|membership|john@example.onmicrosoft.com",
                        "Title": "John Example",
                        "externalUser": false,
                        "idInSiteCollection": "4",
                        "name": "John Example",
                        "oneDriveEmail": "john@example.onmicrosoft.com",
                        "sipAddress": "john@example.onmicrosoft.com",
                        "sourceBitmask": 0,
                        "trueEmail": "john@example.onmicrosoft.com"
                    },
                    "Length": 149,
                    "LinkingUrl": "",
                    "ModifiedBy": {
                        "Email": "",
                        "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@example.onmicrosoft.com",
                        "Title": "Cloud App Security Service Account for SharePoint"
                    },
                    "Name": "20180726150700.JPG.txt",
                    "ServerRelativeUrl": "/personal/avishai_example_onmicrosoft_com/Documents/20180726150700.JPG.txt",
                    "TimeCreated": "2020-08-09T21:45:26Z",
                    "TimeLastModified": "2020-08-09T21:45:53Z",
                    "UniqueId": "05dc1be3-d09f-401c-b2f2-1bb8ef4461cb",
                    "encodedAbsUrl": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20180726150700.JPG.txt",
                    "hasUniqueRoleAssignments": false,
                    "isFolder": false,
                    "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
                    "roleAssignments": [],
                    "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
                    "urlFromMetadata": null
                },
                "siteCollection": "/personal/avishai_example_onmicrosoft_com",
                "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "sitePath": "/personal/avishai_example_onmicrosoft_com",
                "snapshotLastModifiedDate": "2020-08-09T22:01:59.075Z",
                "spDomain": "https://example-my.sharepoint.com",
                "unseenScans": 0
            },
            {
                "_id": "5f306f6ec3b664209d5013d3",
                "_tid": 97134000,
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20180802_144154.jpg.txt"
                            },
                            "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "QuarantineTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": null,
                        "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "RescanFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 0
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20180802_144154.jpg.txt"
                            },
                            "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "TrashFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    }
                ],
                "alternateLink": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20180802_144154.jpg.txt",
                "appId": 15600,
                "appName": "Microsoft OneDrive for Business",
                "collaborators": [],
                "createdDate": 1597009520000,
                "display_collaborators": [],
                "dlpScanResults": [],
                "domains": [
                    "example.onmicrosoft.com"
                ],
                "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                "effectiveParents": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "emails": [
                    "john@example.onmicrosoft.com"
                ],
                "enriched": true,
                "externalShares": [],
                "fTags": [],
                "facl": 0,
                "fileAccessLevel": "PRIVATE",
                "fileExtension": "txt",
                "filePath": "/personal/avishai_example_onmicrosoft_com/Documents/20180802_144154.jpg.txt",
                "fileSize": 149,
                "fileStatus": "EXISTS",
                "fileType": "TEXT",
                "fstat": 0,
                "ftype": 4,
                "groupIds": [],
                "groups": [],
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|2c34faf7-25c9-4fce-ba60-b1e62e706072",
                "instId": 0,
                "isFolder": false,
                "isForeign": false,
                "lastNrtTimestamp": 1597025421748,
                "mimeType": "text/plain",
                "modifiedDate": 1597009541000,
                "name": "20180802_144154.jpg.txt",
                "name_l": "20180802_144154.jpg.txt",
                "noGovernance": false,
                "originalId": "5f306f6ec3b664209d5013d3",
                "ownerAddress": "john@example.onmicrosoft.com",
                "ownerExternal": false,
                "ownerName": "John Example",
                "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
                "parentIds": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "saasId": 15600,
                "scanVersion": 4,
                "sharepointItem": {
                    "Author": {
                        "Email": "john@example.onmicrosoft.com",
                        "LoginName": "i:0#.f|membership|john@example.onmicrosoft.com",
                        "Title": "John Example",
                        "externalUser": false,
                        "idInSiteCollection": "4",
                        "name": "John Example",
                        "oneDriveEmail": "john@example.onmicrosoft.com",
                        "sipAddress": "john@example.onmicrosoft.com",
                        "sourceBitmask": 0,
                        "trueEmail": "john@example.onmicrosoft.com"
                    },
                    "Length": 149,
                    "LinkingUrl": "",
                    "ModifiedBy": {
                        "Email": "",
                        "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@example.onmicrosoft.com",
                        "Title": "Cloud App Security Service Account for SharePoint"
                    },
                    "Name": "20180802_144154.jpg.txt",
                    "ServerRelativeUrl": "/personal/avishai_example_onmicrosoft_com/Documents/20180802_144154.jpg.txt",
                    "TimeCreated": "2020-08-09T21:45:20Z",
                    "TimeLastModified": "2020-08-09T21:45:41Z",
                    "UniqueId": "2c34faf7-25c9-4fce-ba60-b1e62e706072",
                    "encodedAbsUrl": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20180802_144154.jpg.txt",
                    "hasUniqueRoleAssignments": false,
                    "isFolder": false,
                    "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
                    "roleAssignments": [],
                    "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
                    "urlFromMetadata": null
                },
                "siteCollection": "/personal/avishai_example_onmicrosoft_com",
                "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "sitePath": "/personal/avishai_example_onmicrosoft_com",
                "snapshotLastModifiedDate": "2020-08-10T02:10:24.305Z",
                "spDomain": "https://example-my.sharepoint.com",
                "unseenScans": 0
            },
            {
                "_id": "5f306ef5c3b664209d36d024",
                "_tid": 97134000,
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20170813_125133.jpg.txt"
                            },
                            "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "QuarantineTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": null,
                        "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "RescanFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 0
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
                        "bulk_support": true,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "fileName": "20170813_125133.jpg.txt"
                            },
                            "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION"
                        },
                        "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "TrashFileTask",
                        "type": "file",
                        "uiGovernanceCategory": 1
                    }
                ],
                "alternateLink": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20170813_125133.jpg.txt",
                "appId": 15600,
                "appName": "Microsoft OneDrive for Business",
                "collaborators": [],
                "createdDate": 1597009499000,
                "display_collaborators": [],
                "dlpScanResults": [],
                "domains": [
                    "example.onmicrosoft.com"
                ],
                "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                "effectiveParents": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "emails": [
                    "john@example.onmicrosoft.com"
                ],
                "enriched": true,
                "externalShares": [],
                "fTags": [],
                "facl": 0,
                "fileAccessLevel": "PRIVATE",
                "fileExtension": "txt",
                "filePath": "/personal/avishai_example_onmicrosoft_com/Documents/20170813_125133.jpg.txt",
                "fileSize": 149,
                "fileStatus": "EXISTS",
                "fileType": "TEXT",
                "fstat": 0,
                "ftype": 4,
                "groupIds": [],
                "groups": [],
                "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|518d4da4-ffd7-43bc-beaf-c9fdc078b281",
                "instId": 0,
                "isFolder": false,
                "isForeign": false,
                "lastNrtTimestamp": 1597025421725,
                "mimeType": "text/plain",
                "modifiedDate": 1597009519000,
                "name": "20170813_125133.jpg.txt",
                "name_l": "20170813_125133.jpg.txt",
                "noGovernance": false,
                "originalId": "5f306ef5c3b664209d36d024",
                "ownerAddress": "john@example.onmicrosoft.com",
                "ownerExternal": false,
                "ownerName": "John Example",
                "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b",
                "parentIds": [
                    "cac4b654-5fcf-44f0-818e-479cf8ae42ac|8f83a489-34b7-4bb6-a331-260d1291ef6b"
                ],
                "saasId": 15600,
                "scanVersion": 4,
                "sharepointItem": {
                    "Author": {
                        "Email": "john@example.onmicrosoft.com",
                        "LoginName": "i:0#.f|membership|john@example.onmicrosoft.com",
                        "Title": "John Example",
                        "externalUser": false,
                        "idInSiteCollection": "4",
                        "name": "John Example",
                        "oneDriveEmail": "john@example.onmicrosoft.com",
                        "sipAddress": "john@example.onmicrosoft.com",
                        "sourceBitmask": 0,
                        "trueEmail": "john@example.onmicrosoft.com"
                    },
                    "Length": 149,
                    "LinkingUrl": "",
                    "ModifiedBy": {
                        "Email": "",
                        "LoginName": "i:0#.f|membership|tmcassp_fa02d7a6fe55edb22020060112572594@example.onmicrosoft.com",
                        "Title": "Cloud App Security Service Account for SharePoint"
                    },
                    "Name": "20170813_125133.jpg.txt",
                    "ServerRelativeUrl": "/personal/avishai_example_onmicrosoft_com/Documents/20170813_125133.jpg.txt",
                    "TimeCreated": "2020-08-09T21:44:59Z",
                    "TimeLastModified": "2020-08-09T21:45:19Z",
                    "UniqueId": "518d4da4-ffd7-43bc-beaf-c9fdc078b281",
                    "encodedAbsUrl": "https://example-my.sharepoint.com/personal/avishai_example_onmicrosoft_com/Documents/20170813_125133.jpg.txt",
                    "hasUniqueRoleAssignments": false,
                    "isFolder": false,
                    "parentUniqueId": "8f83a489-34b7-4bb6-a331-260d1291ef6b",
                    "roleAssignments": [],
                    "scopeId": "D853886D-DDEE-4A5D-BCB9-B6F072BC1413",
                    "urlFromMetadata": null
                },
                "siteCollection": "/personal/avishai_example_onmicrosoft_com",
                "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
                "sitePath": "/personal/avishai_example_onmicrosoft_com",
                "snapshotLastModifiedDate": "2020-08-10T02:10:24.782Z",
                "spDomain": "https://example-my.sharepoint.com",
                "unseenScans": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft CAS Files
>|owner_name|file_id|file_type|file_name|file_access_level|file_status|app_name|
>|---|---|---|---|---|---|---|
>| John Example | 5f60838dc3b664209dab9a97 | TEXT | 20200525154133.JPG.txt | PRIVATE | EXISTS | Microsoft OneDrive for Business |
>| John Example | 5f39f079c3b664209de9c64c | TEXT | WhatsApp Image 2020-08-02 at 11.04.46.jpeg.txt | PRIVATE | EXISTS | Microsoft OneDrive for Business |
>| John Example | 5f306f37c3b664209d444bf2 | TEXT | 20180726150700.JPG.txt | PRIVATE | EXISTS | Microsoft OneDrive for Business |
>| John Example | 5f306f6ec3b664209d5013d3 | TEXT | 20180802_144154.jpg.txt | PRIVATE | EXISTS | Microsoft OneDrive for Business |
>| John Example | 5f306ef5c3b664209d36d024 | TEXT | 20170813_125133.jpg.txt | PRIVATE | EXISTS | Microsoft OneDrive for Business |


### microsoft-cas-users-accounts-list
***
Returns a list of user accounts that match the specified filters. Filters include user account type, group ID, external/internal, user account status, and custom filter. The accounts object schema includes information about how users and accounts use your organization's cloud apps.


#### Base Command

`microsoft-cas-users-accounts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | The number of records to skip. | Optional | 
| limit | The maximum number of records to return. Default is 50. Possible values are: . Default is 50. | Optional | 
| type | The type by which to filter the information about the user accounts. | Optional | 
| group_id | The group ID by which to filter the information about the user accounts. | Optional | 
| is_admin | Filter the user accounts that are defined as admins. | Optional | 
| is_external | The affiliation of the user accounts. Valid values are: "External", "Internal", and "No_value". Possible values are: External, Internal, No_value. | Optional | 
| status | The status by which to filter the information about the user accounts. Valid values are: "N/A", "Staged", "Active", "Suspended", and "Deleted". Possible values are: N/A, Staged, Active, Suspended, Deleted. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.UsersAccounts.displayName | String | The display name of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.id | String | The ID of the user account in the product. | 
| MicrosoftCloudAppSecurity.UsersAccounts._id | String | The ID of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.isAdmin | Boolean | Whether the user account has admin privileges. | 
| MicrosoftCloudAppSecurity.UsersAccounts.isExternal | Boolean | Whether the user account is external. | 
| MicrosoftCloudAppSecurity.UsersAccounts.email | String | The email address of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.role | String | The role of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.organization | String | The organization to which the user account belongs. | 
| MicrosoftCloudAppSecurity.UsersAccounts.lastSeen | Unknown | The date the user account was last active. | 
| MicrosoftCloudAppSecurity.UsersAccounts.domain | String | The domain of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.threatScore | Unknown | The threat score of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.idType | Number | The ID type \(number\) of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.isFake | Boolean | Whether the user account is marked as fake. | 
| MicrosoftCloudAppSecurity.UsersAccounts.username | String | The username of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.actions.task_name | String | The task name of the action of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.actions.type | String | The type of action of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts._id | String | The account ID of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.inst | Number | The number of instances of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.saas | Number | The cloud services of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.dn | String | The domain name of the cloud services of the user accounts. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.aliases | String | The user account aliases. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.isFake | Boolean | Whether the user account is marked as fake. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.em | Unknown | The email address of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.actions.task_name | String | The task name of the action. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.actions.type | String | The type of the action. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups._id | String | The ID of the user group for the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.id | String | The ID of the user group in the product. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.name | String | The name of the user group. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.usersCount | Number | The number of users in the user group. | 


#### Command Example
```!microsoft-cas-users-accounts-list status=Active limit=3```

#### Context Example
```json
{
    "MicrosoftCloudAppSecurity": {
        "UsersAccounts": [
            {
                "_id": "604771d8478257f44b3082bc",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "365 Defender Dev",
                "domain": null,
                "email": null,
                "id": "bf44d272-ec7d-40c6-bef2-79200b3f2d55",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|bf44d272-ec7d-40c6-bef2-79200b3f2d55",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 719
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 171
                    }
                ],
                "username": "{\"id\": \"bf44d272-ec7d-40c6-bef2-79200b3f2d55\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dbe4229037823e32951b",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "AAD App Management",
                "domain": null,
                "email": null,
                "id": "f0ae4899-d877-4d3c-ae25-679e38eea492",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|f0ae4899-d877-4d3c-ae25-679e38eea492",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 719
                    }
                ],
                "username": "{\"id\": \"f0ae4899-d877-4d3c-ae25-679e38eea492\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db9c229037823e2bf15c",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "AAD Request Verification Service - PROD",
                "domain": null,
                "email": null,
                "id": "c728155f-7b2a-4502-a08b-b8af9b269319",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|c728155f-7b2a-4502-a08b-b8af9b269319",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 719
                    }
                ],
                "username": "{\"id\": \"c728155f-7b2a-4502-a08b-b8af9b269319\", \"saas\": 11161, \"inst\": 0}"
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft CAS Users And Accounts
>|display_name|is_admin|is_external|
>|---|---|---|
>| 365 Defender Dev | false | true |
>| AAD App Management | false | false |
>| AAD Request Verification Service - PROD | false | false |

