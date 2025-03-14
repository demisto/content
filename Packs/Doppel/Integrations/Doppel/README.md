# Overview
Doppel is a Modern Digital Risk Protection Solution, that detects the phishing and brand cyber attacks on the emerging channels. Doppel scans millions of channels online which includes, social media, domains, paid ads, dark web, emerging channels, etc. Doppel can identify the malicious content and cyber threats, and enables their customers to take down the digital risks proactively. The XSOAR pack for Doppel mirrors the alerts created by Doppel as XSOAR incidents. The pack also contains the commands to perform different operations on Doppel alerts.


## Configure Doppel on Cortex XSOAR

1. Navigate to **Settings & Info** > **Settings** > **Integrations** > **Instances**.
2. Search for Doppel.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Doppel Tenant URL | The tenant URL of the Doppel | True |
    | API Key | API key to use for the connection. | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Fetch incidents timeout: The time limit in seconds for fetch incidents to run. Leave this empty to cancel the timeout limit. |  | False |
    | Number of incidents for each fetch.: Due to API limitations, the maximum is 100. |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Mirror Direction | Choose the direction to mirror the incident: Incoming \(from Doppel to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Doppel\), or Incoming and Outgoing \(from/to Cortex XSOAR and Doppel\). | False |
    
4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### doppel-get-alert

***

Retrieves the alert details by ID or entity. Must include exactly one of either ID or entity.

#### Base Command

`doppel-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| id | The ID of the alert to retrieve details for. | Optional |  
| entity | The alerted entity to retrieve details for. | Optional |  

#### Context Output

| **Path** | **Type** | **Description** |  
| --- | --- | --- |  
| Doppel.Alert.id | String | The unique identifier of the alert (e.g., TET-1953421). |  
| Doppel.Alert.entity | String | The URL or profile link related to the alert. |  
| Doppel.Alert.brand | String | The brand associated with the alert. |  
| Doppel.Alert.queue_state | String | The current state of the alert in the queue. |  
| Doppel.Alert.entity_state | String | The current state of the alert entity (e.g., active, inactive). |  
| Doppel.Alert.severity | String | The severity level of the alert (e.g., low, medium, high). |  
| Doppel.Alert.product | String | The product category associated with the alert (e.g., social media). |  
| Doppel.Alert.platform | String | The platform on which the alert was generated (e.g., Bluesky). |  
| Doppel.Alert.source | String | The source from which the alert was generated (e.g., Analyst Upload). |  
| Doppel.Alert.notes | Unknown | Additional notes related to the alert, if any. |  
| Doppel.Alert.created_at | Date | The timestamp when the alert was created. |  
| Doppel.Alert.doppel_link | String | The link to the alert on the Doppel platform. |  
| Doppel.Alert.entity_content | Unknown | Additional content related to the alert entity. |  
| Doppel.Alert.audit_logs.timestamp | Date | Timestamp when the audit log entry was created. |  
| Doppel.Alert.audit_logs.type | String | The type of audit log entry (e.g., alert_create). |  
| Doppel.Alert.audit_logs.value | String | The value of the audit log entry (e.g., needs_review). |  
| Doppel.Alert.audit_logs.changed_by | String | The user who made the change, if available. |  
| Doppel.Alert.audit_logs.metadata | Unknown | Additional metadata related to the audit log. |  
| Doppel.Alert.tags | Unknown | Tags associated with the alert. |  
| Doppel.Alert.uploaded_by | String | The user or source who uploaded the alert (e.g., Doppel). |  

#### Command example

```!doppel-get-alert id="TST-31"```

#### Context Example

```json
{
  "Doppel": {
    "Alert": {
      "id": "TST-31",
      "entity": "http://dummyrul.com",
      "brand": "test_brand",
      "queue_state": "doppel_review",
      "entity_state": "active",
      "severity": "medium",
      "product": "domains",
      "platform": "domains",
      "source": "Analyst Upload",
      "notes": null,
      "created_at": "2024-11-27T06:51:50.357664",
      "doppel_link": "https://app.doppel.com/alerts/TST-31222",
      "entity_content": {
        "root_domain": {
          "domain": "dummyrul.com",
          "registrar": null,
          "ip_address": null,
          "country_code": null,
          "hosting_provider": null,
          "contact_email": null
        }
      },
      "audit_logs": [
        {
          "timestamp": "2024-11-27T06:51:50.357664",
          "type": "alert_create",
          "value": "needs_review",
          "changed_by": "currentuser@doppel.com",
          "metadata": {}
        }
      ],
      "tags": [],
      "uploaded_by": "currentuser@doppel.com"
    }
  }
}
```

#### Human Readable Output

>### Alert Details
>| ID | Entity | Brand | Queue State | Entity State | Severity | Product | Platform | Source | Created At | Doppel Link | Uploaded By |  
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |  
>| TST-31 | http://dummyrul.com | test_brand | doppel_review | active | medium | domains | domains | Analyst Upload | 2024-11-27T06:51:50.357664 | [Doppel Link](https://app.doppel.com/alerts/TST-31222) | currentuser@doppel.com |  


### doppel-create-alert

***

Creates an alert for a specified entity. This command requires the entity to be provided in the arguments.

#### Base Command

`doppel-create-alert`

#### Input

| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| entity | The entity for which the alert should be created. | Required |  

#### Context Output

| **Path** | **Type** | **Description** |  
| --- | --- | --- |  
| Doppel.CreatedAlert.id | String | The unique ID of the alert. |  
| Doppel.CreatedAlert.entity | String | The entity URL associated with the alert. |  
| Doppel.CreatedAlert.doppel_link | String | The link to view the alert in the Doppel platform. |  

#### Command example

```!doppel-create-alert entity="http://example.com"```

#### Context Example

```json
{
  "CreatedAlert": {
    "id": "TST-1001",
    "entity": "http://example.com",
    "doppel_link": "https://app.doppel.com/alerts/TST-1001"
  }
}
```

#### Human Readable Output

>### Created Alert
>| ID | Entity | Doppel Link |  
>| --- | --- | --- |  
>| TST-1001 | http://example.com | [Doppel Link](https://app.doppel.com/alerts/TST-1001) |  

### doppel-update-alert

***

Updates an alert in the Doppel platform. Either `alert_id` or `entity` must be specified.

#### Base Command

`doppel-update-alert`

#### Input

| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| alert_id | The ID of the alert to update. Only one of `alert_id` or `entity` can be specified, not both. | Optional |  
| entity | The entity of the alert to update. Only one of `alert_id` or `entity` can be specified, not both. | Optional |  
| queue_state | Status of which queue the alert is in. Possible values are: `doppel_review`, `actioned`, `needs_confirmation`, `monitoring`, `taken_down`, `archived`. | Optional |  
| entity_state | State of the alert. Possible values are: `active`, `down`, `parked`. | Optional |  
| comment | A comment to add while updating the alert. | Optional |  

#### Context Output

| **Path** | **Type** | **Description** |  
| --- | --- | --- |  
| Doppel.UpdatedAlert.id | String | Unique identifier for the alert (e.g., TET-1953421). |  
| Doppel.UpdatedAlert.entity | String | The URL or identifier associated with the alert. |  
| Doppel.UpdatedAlert.brand | String | The brand associated with the alert. |  
| Doppel.UpdatedAlert.queue_state | String | The current state of the alert in the queue. |  
| Doppel.UpdatedAlert.entity_state | String | The current state of the alert entity. |  
| Doppel.UpdatedAlert.severity | String | The severity of the alert (e.g., Low, Medium, High). |  
| Doppel.UpdatedAlert.product | String | The product category related to the alert. |  
| Doppel.UpdatedAlert.platform | String | The platform associated with the alert (e.g., Bluesky). |  
| Doppel.UpdatedAlert.source | String | The source of the alert (e.g., Analyst Upload). |  
| Doppel.UpdatedAlert.notes | Unknown | Additional notes regarding the alert. |  
| Doppel.UpdatedAlert.created_at | Date | Timestamp when the alert was created. |  
| Doppel.UpdatedAlert.doppel_link | String | URL link to the alert in Doppel Vision. |  
| Doppel.UpdatedAlert.entity_content | Unknown | Content details of the alert entity. |  
| Doppel.UpdatedAlert.audit_logs.timestamp | Date | Timestamp of the audit log entry. |  
| Doppel.UpdatedAlert.audit_logs.type | String | The type of audit log entry. |  
| Doppel.UpdatedAlert.audit_logs.value | String | The value associated with the audit log entry. |  
| Doppel.UpdatedAlert.audit_logs.changed_by | String | The user who changed the alert, or null if system-generated. |  
| Doppel.UpdatedAlert.audit_logs.metadata | Unknown | Additional metadata related to the audit log entry. |  
| Doppel.UpdatedAlert.tags | Unknown | List of tags associated with the alert. |  
| Doppel.UpdatedAlert.uploaded_by | String | The user or system that uploaded the alert (e.g., Doppel). |  

#### Command example

```!doppel-update-alert alert_id="TST-31" queue_state="actioned" entity_state="down" comment="Updated due to new findings"```

#### Context Example

```json
{
  "Doppel": {
    "UpdatedAlert": {
      "id": "TST-31",
      "entity": "http://dummyrul.com",
      "brand": "test_brand",
      "queue_state": "actioned",
      "entity_state": "down",
      "severity": "medium",
      "product": "domains",
      "platform": "domains",
      "source": "Analyst Upload",
      "notes": null,
      "created_at": "2024-11-27T06:51:50.357664",
      "doppel_link": "https://app.doppel.com/alerts/TST-31222",
      "entity_content": {
        "root_domain": {
          "domain": "dummyrul.com",
          "registrar": null,
          "ip_address": null,
          "country_code": null,
          "hosting_provider": null,
          "contact_email": null
        }
      },
      "audit_logs": [
        {
          "timestamp": "2024-11-27T06:51:50.357664",
          "type": "alert_update",
          "value": "actioned",
          "changed_by": "currentuser@doppel.com",
          "metadata": {}
        }
      ],
      "tags": [],
      "uploaded_by": "currentuser@doppel.com"
    }
  }
}
```

#### Human Readable Output

>### Updated Alert Details
>| ID | Entity | Brand | Queue State | Entity State | Severity | Product | Platform | Source | Created At | Doppel Link | Uploaded By |  
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |  
>| TST-31 | http://dummyrul.com | test_brand | actioned | down | medium | domains | domains | Analyst Upload | 2024-11-27T06:51:50.357664 | [Doppel Link](https://app.doppel.com/alerts/TST-31222) | currentuser@doppel.com |  


### doppel-create-abuse-alert

***

Create an alert for the provided value to abuse box. Will fail if the alert value is invalid or is protected.

#### Base Command

`doppel-create-abuse-alert`

#### Input

| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| entity | The entity for which the abuse alert should be created. | Required |  

#### Context Output

| **Path** | **Type** | **Description** |  
| --- | --- | --- |  
| Doppel.AbuseAlert.message | String | Message indicating the status of the submission process. |  

#### Command example

```!doppel-create-abuse-alert entity="http://malicious.com"```

#### Context Example

```json
{
  "Doppel": {
    "AbuseAlert": {
      "message": "Abuse alert created successfully"
    }
  }
}
```

#### Human Readable Output

>### Abuse Alert Submission
>| Message |  
>| --- |  
>| Abuse alert created successfully |  


### doppel-get-alerts

***

Retrieves a list of alerts. The result can be filtered by provided parameters.

#### Base Command

`doppel-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |  
| --- | --- | --- |  
| search_key | Currently only supports search by URL. | Optional |  
| queue_state | New queue status to update alert with (id required). Possible values: actioned, needs_confirmation, doppel_review, monitoring, taken_down, archived. | Optional |  
| product | Product category the report belongs to. Possible values: domains, social_media, mobile_apps, ecommerce, crypto, emails, paid_adds. | Optional |  
| created_before | Filter alerts created before a specific time. Use the ISO 8601 format, such as 2020-01-01T00:11:22Z. For durations, enter values like '12 hours' or '7 days'. | Optional |  
| created_after | Filter alerts created before a specific time. Use the ISO 8601 format, such as 2020-01-01T00:11:22Z. For durations, enter values like '12 hours' or '7 days'. | Optional |  
| sort_type | The field to sort the reports by. Defaults to date_sourced. Possible values: date_sourced, date_last_actioned. | Optional |  
| sort_order | The order to sort the reports by. Defaults to desc. Possible values: asc, desc. | Optional |  
| page | Page number for pagination; defaults to 0. | Optional |  
| tags | List of tags to filter alerts. | Optional |  

#### Context Output

| **Path** | **Type** | **Description** |  
| --- | --- | --- |  
| Doppel.GetAlerts.alerts.id | String | The unique ID of the alert. |  
| Doppel.GetAlerts.alerts.entity | String | The entity associated with the alert. |  
| Doppel.GetAlerts.alerts.brand | String | The brand related to the alert. |  
| Doppel.GetAlerts.alerts.queue_state | String | The queue state of the alert. |  
| Doppel.GetAlerts.alerts.entity_state | String | The current state of the entity (active/inactive). |  
| Doppel.GetAlerts.alerts.severity | String | The severity of the alert. |  
| Doppel.GetAlerts.alerts.product | String | The product related to the alert. |  
| Doppel.GetAlerts.alerts.platform | String | The platform associated with the alert. |  
| Doppel.GetAlerts.alerts.source | String | The source of the alert. |  
| Doppel.GetAlerts.alerts.created_at | Date | The timestamp when the alert was created. |  
| Doppel.GetAlerts.alerts.doppel_link | String | The link to the alert in the Doppel platform. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.domain | String | The domain associated with the alert. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.registrar | String | The registrar of the domain. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.ip_address | String | The IP address of the domain. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.country_code | String | The country code of the domain. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.hosting_provider | String | The hosting provider for the domain. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.contact_email | String | The contact email of the domain. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.mx_records | Unknown | The MX records associated with the domain. |  
| Doppel.GetAlerts.alerts.entity_content.root_domain.nameservers | Unknown | The nameservers associated with the domain. |  
| Doppel.GetAlerts.alerts.audit_logs.timestamp | Date | The timestamp of the audit log. |  
| Doppel.GetAlerts.alerts.audit_logs.type | String | The type of the audit log. |  
| Doppel.GetAlerts.alerts.audit_logs.value | String | The value associated with the audit log. |  
| Doppel.GetAlerts.alerts.audit_logs.changed_by | String | The user or system that changed the status. |  
| Doppel.GetAlerts.alerts.audit_logs.metadata | Unknown | Additional metadata for the audit log. |  
| Doppel.GetAlerts.alerts.tags | Unknown | The tags associated with the alert. |  
| Doppel.GetAlerts.alerts.uploaded_by | String | The source or user who uploaded the alert. |  
| Doppel.GetAlerts.metadata.count | Integer | The total count of alerts. |  
| Doppel.GetAlerts.metadata.page | Integer | The current page number in the results. |  
| Doppel.GetAlerts.metadata.total_pages | Integer | The total number of pages for the alerts. |  
| Doppel.GetAlerts.metadata.page_size | Integer | The number of alerts per page. |  

#### Command example

```!doppel-get-alerts search_key="http://example.com" sort_order="desc" page="1"```

#### Context Example

```json
{
  "Doppel": {
    "GetAlerts": {
      "alerts": [
        {
          "id": "ALERT-12345",
          "entity": "http://example.com",
          "brand": "Test Brand",
          "queue_state": "doppel_review",
          "entity_state": "active",
          "severity": "high",
          "product": "domains",
          "platform": "website",
          "source": "Analyst Upload",
          "created_at": "2024-11-27T10:20:30Z",
          "doppel_link": "https://app.doppel.com/alerts/ALERT-12345",
          "entity_content": {
            "root_domain": {
              "domain": "example.com",
              "registrar": "Example Registrar",
              "ip_address": "192.168.1.1",
              "country_code": "US",
              "hosting_provider": "Example Hosting",
              "contact_email": "contact@example.com"
            }
          },
          "audit_logs": [
            {
              "timestamp": "2024-11-27T10:21:00Z",
              "type": "alert_create",
              "value": "needs_review",
              "changed_by": "analyst@example.com",
              "metadata": {}
            }
          ],
          "tags": ["phishing", "malware"],
          "uploaded_by": "analyst@example.com"
        }
      ],
      "metadata": {
        "count": 1,
        "page": 1,
        "total_pages": 1,
        "page_size": 50
      }
    }
  }
}
```

#### Human Readable Output

>### Alert Details
>| ID | Entity | Brand | Queue State | Entity State | Severity | Product | Platform | Source | Created At | Doppel Link | Uploaded By |  
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |  
>| ALERT-12345 | http://example.com | Test Brand | doppel_review | active | high | domains | website | Analyst Upload | 2024-11-27T10:20:30Z | [Doppel Link](https://app.doppel.com/alerts/ALERT-12345) | analyst@example.com |  


### get-mapping-fields

***
Returns the list of fields for an incident type.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### update-remote-system

***
Pushes local changes to the remote system.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Get remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required | 
| lastUpdate | Retrieve entries that were created after lastUpdate. | Required | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_update | Retrieve entries that were created after lastUpdate. | Optional | 

#### Context Output

There is no context output for this command.