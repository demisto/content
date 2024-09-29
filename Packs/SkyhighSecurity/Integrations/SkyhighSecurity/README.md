
### Additional information
Skyhigh Security is a cloud-based, multi-tenant service that enables Cloud Discovery and Risk Monitoring, Cloud Usage Analytics, Cloud Access and Control.
This integration was integrated and tested with version 1 of Skyhigh Security.

### API limitations

Do to [API](https://success.myshn.net/Skyhigh_CASB/Skyhigh_CASB_APIs/Incidents_API/02_Incidents_API_Paths#_responses_3) limitations, keep in mind that over time the integration can start to work more slowly.
The solution is to restart the last-run.

## Configure Skyhigh Security in Cortex


   | **Parameter**  | **Description** | **Required** |
   | ---- | -------- | ------------ |
   | Base URL (e.g., https://www.myshn.net)|    | True   |
   | Password | The username and password to use for the connection | True |
   | Maximum number of incidents to fetch every time. Default is 50. Maximum is 500. | False  |
   | First fetch in timestamp format (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days. |   | False   |
   | Trust any certificate (not secure) |  | False  |
   | Use system proxy settings |  | False   |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### skyhigh-security-incident-query

---

Retrieves a list of incidents in ascending time modified order.

#### Base Command

`skyhigh-security-incident-query`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                             | **Required** |
| ------- | ---------- | ------------ |
| limit   | Maximum number of items that will be returned within a single response. Maximum is 500. If the limit value exceeds the 500 maximum, it will not be flagged as an error but will also not increase results. Default is 50. | Optional |
| page   | Pagination support for use with a large “limit” value. | Optional |
| page_size | Pagination support for use with a large “limit” value. The maximum is 500. | Optional |
| start_time  | For time arguments use the ISO-8601 standard - '%Y-%m-%dT%H:%M:%SZ' or relative time (last X days). Default is 3 days. | Optional  |
| end_time  | For time arguments use the ISO-8601 standard - '%Y-%m-%dT%H:%M:%SZ' or relative time (last X days).  | Optional |
| actor_ids   | The actor IDs of the incidents to retrieve.  | Optional  |
| service_names  | The service names of the incidents to retrieve. | Optional     |
| incident_types  | The type of the incidents to retrieve. Possible values are: Alert, Threat. | Optional  |
| categories | The categories of the incidents to retrieve. When defining the categories argument the incident_types argument is ignored. Possible values are: Access, Admin, Audit, CompromisedAccount, Data, InsiderThreat, Policy, PrivilegeAccess, Vulnerability. | Optional     |

#### Context Output

| **Path**             | **Type** | **Description**          |
| ------ | ----- | ------ |
| SkyhighSecurity.Incident | Unknown  | The incident's metadata. |

#### Command example

`!skyhigh-security-incident-query limit="3" start_time="3 days"`

#### Context Example

```json
{
  "SkyhighSecurity": {
    "Incident": [
      {
        "activityNames": [],
        "actorId": "NOT AVAILABLE",
        "actorIdType": "USER",
        "incidentGroup": "Alert.Policy.CloudAccess",
        "incidentGroupId": null,
        "incidentId": "CAP-111111",
        "incidentRiskScore": 10,
        "incidentRiskSeverity": "high",
        "incidentRiskSeverityId": 2,
        "information": {
          "contentItemCreatedOn": "2022-07-01T19:13:53.075Z",
          "contentItemId": "UNKNOWN",
          "contentItemName": "/css/webfonts/office365icons.eot?",
          "contentItemType": "REQUEST",
          "device": {
            "application": {
              "type": "application",
              "user_agent": "Chrome"
            },
            "device_type": "Desktop",
            "ip": "1.1.1.1",
            "os": {
              "platform": "Windows",
              "type": "os"
            }
          },
          "eventId": "222222",
          "lastExecutedResponseLabel": "Block Access",
          "policyId": 333333,
          "policyName": "Block downloads to unmanaged devices",
          "userAttributes": {}
        },
        "instanceId": 444444,
        "instanceName": "zengel",
        "responses": ["Block Access"],
        "serviceNames": ["Microsoft Office 365 and OneDrive"],
        "significantlyUpdatedAt": "2022-07-01T19:13:57.053Z",
        "status": "new",
        "timeCreated": "2022-07-01T19:13:53.075Z",
        "timeModified": "2022-07-01T19:13:57.053Z"
      },
      {
        "activityNames": [],
        "actorId": "NOT AVAILABLE",
        "actorIdType": "USER",
        "incidentGroup": "Alert.Policy.CloudAccess",
        "incidentGroupId": null,
        "incidentId": "CAP-555555",
        "incidentRiskScore": 3,
        "incidentRiskSeverity": "low",
        "incidentRiskSeverityId": 0,
        "information": {
          "contentItemCreatedOn": "2022-07-02T02:38:16.706Z",
          "contentItemId": "UNKNOWN",
          "contentItemName": "/",
          "contentItemType": "REQUEST",
          "device": {
            "application": {
              "type": "application",
              "user_agent": "Unknown"
            },
            "device_type": "Unknown",
            "ip": "2.2.2.2",
            "os": {
              "platform": "Unknown",
              "type": "os"
            }
          },
          "eventId": "666666",
          "lastExecutedResponseLabel": "Allow Access",
          "policyId": 777777,
          "policyName": "allow successfactors",
          "userAttributes": {}
        },
        "instanceId": 888888,
        "instanceName": "ZengelBiz",
        "responses": ["Allow Access"],
        "serviceNames": ["SAP - SuccessFactors HXM Suite"],
        "significantlyUpdatedAt": "2022-07-02T02:38:18.682Z",
        "status": "new",
        "timeCreated": "2022-07-02T02:38:16.706Z",
        "timeModified": "2022-07-02T02:38:18.682Z"
      },
      {
        "activityNames": [],
        "actorId": "NOT AVAILABLE",
        "actorIdType": "USER",
        "incidentGroup": "Alert.Policy.CloudAccess",
        "incidentGroupId": null,
        "incidentId": "CAP-999999",
        "incidentRiskScore": 3,
        "incidentRiskSeverity": "low",
        "incidentRiskSeverityId": 0,
        "information": {
          "contentItemCreatedOn": "2022-07-02T02:38:16.888Z",
          "contentItemId": "UNKNOWN",
          "contentItemName": "/",
          "contentItemType": "REQUEST",
          "device": {
            "application": {
              "type": "application",
              "user_agent": "Unknown"
            },
            "device_type": "Unknown",
            "ip": "2.2.2.2",
            "os": {
              "platform": "Unknown",
              "type": "os"
            }
          },
          "eventId": "144304",
          "lastExecutedResponseLabel": "Allow Access",
          "policyId": 777777,
          "policyName": "allow successfactors",
          "userAttributes": {}
        },
        "instanceId": 888888,
        "instanceName": "ZengelBiz",
        "responses": ["Allow Access"],
        "serviceNames": ["SAP - SuccessFactors HXM Suite"],
        "significantlyUpdatedAt": "2022-07-02T02:38:19.202Z",
        "status": "new",
        "timeCreated": "2022-07-02T02:38:16.888Z",
        "timeModified": "2022-07-02T02:38:19.202Z"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Skyhigh Security Incidents
>
> | Alert Severity | Incident ID | Service Name   | Status | Time (UTC)  | User Name  |
> | ---- | ---- | ----- | ------ | ------ | ---- |
> | high   | CAP-111111  | Microsoft Office 365 and OneDrive | new  | 2022-07-01T19:13:53.075Z | NOT AVAILABLE |
> | low   | CAP-555555  | SAP - SuccessFactors HXM Suite  | new  | 2022-07-02T02:38:16.706Z | NOT AVAILABLE |
> | low   | CAP-999999  | SAP - SuccessFactors HXM Suite  | new  | 2022-07-02T02:38:16.888Z | NOT AVAILABLE |

### skyhigh-security-incident-status-update

---

Update status of single/multiple incidents.

Note!
For multiple IDs, a single status will be applied for all IDs
e.g., 123, 456, 789 >> change status to >> closed.

#### Base Command

`skyhigh-security-incident-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| ------ | ----- | ---- |
| incident_ids | The incidents IDs that should be updated. | Required  |
| status  | The new status of the incidents. Possible values are: new, opened, false positive, resolved, suppressed, archived. | Required  |

#### Context Output

There is no context output for this command.

#### Command example

`!skyhigh-security-incident-status-update incident_ids=CAP-114044 status=archived`

#### Human Readable Output

> Status updated for user

### skyhigh-security-anomaly-activity-list

---

Fetches activities for a given anomaly ID.

#### Base Command

`skyhigh-security-anomaly-activity-list`

#### Input

| **Argument Name** | **Description**  | **Required** |
| ----- | ---- | --- |
| anomaly_id  | The anomaly ID from where to retrieve the activities. Only for incidents of type anomaly (ANO-123). | Required  |

#### Context Output

| **Path** | **Type** | **Description**                                               |
| --- | ----- | --- |
| SkyhighSecurity.AnomalyActivity.timeStamp          | String   | The timestamp of the anomaly activity.   |                     |
| SkyhighSecurity.AnomalyActivity.actionName         | String  | The action name.  |
| SkyhighSecurity.AnomalyActivity.asnName            | String  | The ASN name of an activity.  |                                |
| SkyhighSecurity.AnomalyActivity.city               | String  | The city where the anomaly activity occurred.    |
| SkyhighSecurity.AnomalyActivity.collabGroup        | String  | The collaboration group for the anomaly activity.  |
| SkyhighSecurity.AnomalyActivity.count              | Number  | The number of anomalies detected.      |
| SkyhighSecurity.AnomalyActivity.country            | String   | The country of the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.deviceManaged      | Boolean   | Whether the anomaly activity is managed by the device or not. |
| SkyhighSecurity.AnomalyActivity.directory          | String   | The directory of the anomaly activity.    |
| SkyhighSecurity.AnomalyActivity.downloadBytes      | Number   | The number of bytes downloaded by the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.eventCount         | Number   | The number of anomalies detected.     |
| SkyhighSecurity.AnomalyActivity.fileFolderPath     | String   | The file folder path for the anomaly activity.    |
| SkyhighSecurity.AnomalyActivity.fileName           | String   | The file name of the anomaly activity.                        |
| SkyhighSecurity.AnomalyActivity.fileSharingEnabled | Boolean  | Whether the CASB file sharing is enabled or not.   |             |
| SkyhighSecurity.AnomalyActivity.fileSize           | Number   | The file size of the anomaly activity.  |
| SkyhighSecurity.AnomalyActivity.fileType           | String   | The file type of the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.geoOrgNameV1       | String   | The geo organization name.     |
| SkyhighSecurity.AnomalyActivity.httpMethod         | String   | The HTTP method used by the anomaly activity.     |
| SkyhighSecurity.AnomalyActivity.instanceId         | String   | The instance ID for the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.isSourceTrusted    | Boolean  | Whether the anomaly activity source is trusted or not.       |
| SkyhighSecurity.AnomalyActivity.networkType        | String   | The network type for the anomaly.    |
| SkyhighSecurity.AnomalyActivity.objectType         | String   | The object type for the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.operation          | String   | The operation type.    |
| SkyhighSecurity.AnomalyActivity.proxyDescription   | String   | The proxy description for the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.proxyType          | String   | The proxy type for the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.region             | String   | The region where the anomaly activity occurred.  |
| SkyhighSecurity.AnomalyActivity.serviceName        | String   | The name of the service.    |
| SkyhighSecurity.AnomalyActivity.siteUrl            | String   | The URL of the CASB's site.       |
| SkyhighSecurity.AnomalyActivity.sourceIP           | IP     | The IP address of the source IP.   |
| SkyhighSecurity.AnomalyActivity.sourceIdentifier   | String   | The source identifier for the anomaly activity.   |
| SkyhighSecurity.AnomalyActivity.targetId           | String   | The target ID for the anomaly activity.                       |
| SkyhighSecurity.AnomalyActivity.targetType         | String   | The anomaly activity type.   |
| SkyhighSecurity.AnomalyActivity.tenantId           | Number   | The tenant ID for the anomaly activity.     |
| SkyhighSecurity.AnomalyActivity.threatCategory     | String   | The threat category for the anomaly activity.    |
| SkyhighSecurity.AnomalyActivity.trustEntity        | String   | The trust entity for the anomaly activity.      |
| SkyhighSecurity.AnomalyActivity.trustReason        | String   | The trust reason of the anomaly activity.    |
| SkyhighSecurity.AnomalyActivity.uploadBytes        | Number   | The number of bytes uploaded.       |
| SkyhighSecurity.AnomalyActivity.url                | String   | The URL of the anomaly activity.     |
| SkyhighSecurity.AnomalyActivity.user               | String   | The user who triggered the anomaly.     |

### skyhigh-security-policy-dictionary-list

---

List existing policy dictionaries.

#### Base Command

`skyhigh-security-policy-dictionary-list`

#### Input

| **Argument Name** | **Description**                                                                           | **Required** |
| ------ | ----- | ------- |
| limit     | Maximum number of policies that will be returned within a single response. Default is 50. | Optional     |
| page   | Pagination support for use with a large “limit” value.    | Optional     |
| page_size     | Pagination support for use with a large “limit” value.   | Optional     |
| name     | The name of the policies to retrieve.    | Optional     |

#### Context Output

| **Path**                                  | **Type** | **Description**    |
|-------------------------------------------| -------- | ----------- |
| SkyhighSecurity.Dictionaries.ID           | Number   | The ID for the dictionary.   |
| SkyhighSecurity.Dictionaries.LastModified | String   | The date the dictionary was last modified. |
| SkyhighSecurity.Dictionaries.Name         | String   | The name of the dictionary.     |

#### Command example

`!skyhigh-security-policy-dictionary-list limit="3"`

#### Context Example

```json
{
  "SkyhighSecurity": {
    "dictionaries": [
      {
        "ID": 121212,
        "LastModified": "2022-07-04T14:02:03.000+0000",
        "Name": "(Default) Internal Domains"
      },
      {
        "ID": 131313,
        "LastModified": "2020-04-15T13:08:09.000+0000",
        "Name": "Access Whitelist Users"
      },
      {
        "ID": 141414,
        "LastModified": "2021-07-14T12:22:37.000+0000",
        "Name": "Allowed Geo"
      }
    ]
  }
}
```

#### Human Readable Output

> ### List of Skyhigh Security Policies
>
> | ID    | Last Modified   | Name   |
> | ------ | ----- | ------- |
> | 121212 | 2022-07-04T14:02:03.000+0000 | (Default) Internal Domains |
> | 131313 | 2020-04-15T13:08:09.000+0000 | Access Whitelist Users     |
> | 141414 | 2021-07-14T12:22:37.000+0000 | Allowed Geo    |

### skyhigh-security-policy-dictionary-update

---

Adds new content to an existing policy dictionary.

#### Base Command

`skyhigh-security-policy-dictionary-update`

#### Input

| **Argument Name** | **Description**   | **Required** |
| ---- | --- | --- |
| dictionary_id     | The dictionary where to set the policy.   | Required     |
| name    | A name for the new key-value which will be added in the dictionary.  | Required   |
| content    | The value to be set in the dictionary for the given key-name. Multiple values can be separated by commas. | Required     |

#### Context Output

There is no context output for this command.

#### Command example

`!skyhigh-security-policy-dictionary-update dictionary_id="121212" name="(Default) Internal Domains" content="gmail.com, outlook.com"`

#### Human Readable Output

> Dictionary id: 121212 was updated.