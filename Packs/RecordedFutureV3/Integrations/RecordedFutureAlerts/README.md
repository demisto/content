# Recorded Future Alerts

Fetch and triage **Recorded Future Classic Alerts** and **Recorded Future Playbook Alerts** directly from Cortex
XSOAR.  

The integration allows you to:

* Search and fetch alerts from the Recorded Future platform.
* Update alert status, assignee and comment/note from inside XSOAR.
* Automatically fetch screenshots that accompany the alert.

## Configure Recorded Future Alerts in Cortex

| **Parameter**                         | **Description**                                                                                                                                                                                             | **Required** |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Fetch incidents                       | Turn on **incident fetching**. When enabled, the integration will poll Recorded Future at the defined interval and create / update incidents for new or updated alerts.                                     | False        |
| Incident type                         | Incident type will be set by this field if a Classifier does not exist. If a Classifier is selected, it will take precedence. Leave empty to let the built-in classifier decide based on the alert subtype. | False        |
| Your server URL                       | Base URL for the Recorded Future XSOAR gateway API. The default value `https://api.recordedfuture.com/gw/xsoar/`.                                                                                           | True         |
| API Key                               | Recorded Future **user API token** used to authenticate the requests.                                                                                                                                       | True         |
| Source Reliability                    | How trustworthy Recorded Future should be considered when the integration sets DBot scores.                                                                                                                 | False        |
| Incidents fetch interval              | How often to poll for new alerts.                                                                                                                                                                           | False        |
| Maximum number of incidents per fetch | Hard cap on the number of alerts to pull in a single fetch cycle (maximum **50**, due to API limits).                                                                                                       | False        |
| First fetch time                      | How far back to look on the **very first** fetch run. Maximum look-back is **90 days**.                                                                                                                     | False        |
| Enable Classic Alerts                 | Toggle fetching of **Classic Alerts**. Disable if you only need Playbook Alerts.                                                                                                                            | False        |
| Classic Alerts: Rule names to fetch   | Semicolon-separated **Classic Alert rule names** to include (e.g., `Malware;Typosquat`). Leave blank to fetch alerts from *all* rules.                                                                      | False        |
| Classic Alerts: Statuses to fetch     | Classic Alert statuses to be fetched. Choose one or more of **New, InProgress, Resolved, Dismissed**.                                                                                                       | True         |
| Enable Playbook Alerts                | Toggle fetching of **Playbook Alerts**. Disable if you only need Classic Alerts.                                                                                                                            | False        |
| Playbook Alerts: Priority to fetch    | Minimum **priority** threshold. Alerts with lower priority than selected value will not be fetched. Possible values: Informational, Moderate, High.                                                         | False        |
| Playbook Alerts: Categories to fetch  | Comma-separated list of Playbook Alert **categories** to include (e.g., `domain_abuse,cyber_vulnerability`). Leave blank to fetch all categories available to your licence.                                 | False        |
| Playbook Alerts: Statuses to fetch    | Playbook Alert statuses to be fetched (choose one or more of **New, InProgress, Resolved, Dismissed**).                                                                                                     | True         |
| Trust any certificate (not secure)    | Skip TLS certificate validation. For example, enable this when using a proxy that re-signs SSL traffic or for testing with self-signed certs.                                                               | False        |
| Use system proxy settings             | Route all HTTP/S requests through the system-wide proxy settings configured in Cortex XSOAR.                                                                                                                | False        |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### rf-alerts

***
List Classic or Playbook alerts.

#### Base Command

`rf-alerts`

#### Input

| **Argument Name**         | **Description**                                                                                                                                                                                      | **Required** |
|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| include_classic_alerts    | Whether classic alerts should be included in the response. Possible values are: true, false. Default is true.                                                                                        | Optional     | 
| include_playbook_alerts   | Whether playbook alerts should be included in the response. Possible values are: true, false. Default is true.                                                                                       | Optional     | 
| classic_alert_rule_ids    | Comma-separated Classic Alert Rule IDs. Only applied to Classic Alert search.                                                                                                                        | Optional     | 
| playbook_alert_categories | Comma-separated Playbook Alert categories. Only applied to Playbook Alert search. Possible values are: domain_abuse, cyber_vulnerability, code_repo_leakage, third_party_risk, geopolitics_facility. | Optional     | 
| playbook_alert_priorities | Comma-separated Playbook Alert priorities. Only applied to Playbook Alert search. Possible values are: Informational, Moderate, High.                                                                | Optional     | 
| statuses                  | Comma-separated list of statuses to include. Possible values are: New, InProgress, Resolved, Dismissed.                                                                                              | Optional     | 
| limit                     | Maximum number of alerts to return. Maximum allowed value is 50. Default is 10.                                                                                                                      | Optional     | 
| order_by                  | Field to sort by. Possible values are: created_at, updated_at. Default value is updated_at.                                                                                                          | Optional     | 
| order_direction           | Direction to sort by. Possible values are: asc, desc. Default value is desc.                                                                                                                         | Optional     | 
| created_from              | Return only alerts created on or after this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                   | Optional     | 
| created_to                | Return only alerts created on or before this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                  | Optional     | 
| updated_from              | Return only alerts updated on or after this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                   | Optional     | 
| updated_to                | Return only alerts updated on or before this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                  | Optional     | 

#### Context Output

| **Path**                                           | **Type** | **Description**                                                                                                                   |
|----------------------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------|
| RecordedFutureAlerts.Alert.id                      | string   | Unique id of the alert in Recorded Future.                                                                                        | 
| RecordedFutureAlerts.Alert.title                   | string   | Title of the alert.                                                                                                               | 
| RecordedFutureAlerts.Alert.type                    | string   | Alert type (classic-alert / playbook-alert).                                                                                      | 
| RecordedFutureAlerts.Alert.subtype                 | string   | Alert subtype (domain_abuse / cyber_vulnerability / code_repo_leakage / third_party_risk / geopolitics_facility / classic-alert). | 
| RecordedFutureAlerts.Alert.status                  | string   | Status of the alert.                                                                                                              | 
| RecordedFutureAlerts.Alert.created                 | string   | When the alert was created as an ISO8601 string.                                                                                  | 
| RecordedFutureAlerts.Alert.updated                 | string   | When the alert was updated as an ISO8601 string.                                                                                  | 
| RecordedFutureAlerts.Alert.classic_alert_rule_name | string   | If alert is a classic alert, this is the name of the rule that triggered the alert.                                               | 
| RecordedFutureAlerts.Alert.classic_alert_rule_id   | string   | If alert is a classic alert, this is the name of the rule that triggered the alert.                                               | 
| RecordedFutureAlerts.Alert.playbook_alert_category | string   | If alert is a playbook alert, this is the category of the alert.                                                                  | 
| RecordedFutureAlerts.Alert.playbook_alert_priority | string   | If alert is a playbook alert, this is the priority of the alert.                                                                  | 

#### Command Example

```bash
!rf-alerts include_classic_alerts=false playbook_alert_categories=domain_abuse playbook_alert_priorities=High statuses=New limit=5 order_by=updated_at order_direction=desc created_from="2025-05-17T12:06:00Z"
```

#### Context Example

```json
{
  "RecordedFutureAlerts": {
    "Alert": [
      {
        "id": "task:fc34c790-293b-42bd-8f23-c1f571323f8f",
        "title": "Potential Typosquat of example.com",
        "type": "playbook-alert",
        "subtype": "domain_abuse",
        "status": "New",
        "created": "2025-05-17T16:06:00Z",
        "updated": "2025-05-17T17:14:12Z",
        "playbook_alert_category": "domain_abuse",
        "playbook_alert_priority": "High"
        "classic_alert_rule_name": null,
        "classic_alert_rule_id": null
      },
      {
        "id": "7SKZ26",
        "title": "ClassiAlert",
        "type": "classic-alert",
        "subtype": "classic-alert",
        "status": "New",
        "created": "2025-05-17T15:58:30Z",
        "updated": "2025-05-17T16:40:00Z",
        "classic_alert_rule_name": "Alert rule name 1",
        "classic_alert_rule_id": "fDasdfwea"
        "playbook_alert_category": null,
        "playbook_alert_priority": null
      }
    ]
  }
}
```

### rf-alert-update

***
Update an alert in the Recorded Future platform.

#### Base Command

`rf-alert-update`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                            | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| alert_id          | ID of alert to update.                                                                                                                                                                                                                                     | Required     | 
| status            | New status to set for the alert. Possible values are: New, InProgress, Dismissed, Resolved.                                                                                                                                                                | Optional     | 
| comment           | Add comment / Replace note.                                                                                                                                                                                                                                | Optional     | 
| reopen            | Only for Playbook Alerts. Set the reopen strategy for the alert. Reopen on significant updates or keep the alert Resolved. Can only be used with status=Resolved. Possible values are: never, significant_updates. Default: reopen on significant updates. | Optional     | 

#### Context Output

| **Path**                           | **Type** | **Description**                                             |
|------------------------------------|----------|-------------------------------------------------------------|
| RecordedFutureAlerts.Alert.id      | string   | Unique id of the alert in Recorded Future.                  | 
| RecordedFutureAlerts.Alert.type    | string   | Alert type (classic-alert / playbook-alert).                | 
| RecordedFutureAlerts.Alert.status  | string   | Status of alert in Recorded Future.                         | 
| RecordedFutureAlerts.Alert.comment | string   | Note (Classic) or comment (Playbook) that was just applied. | 

#### Command Example

```bash
!rf-alert-update alert_id=task:fc34c790-293b-42bd-8f23-c1f571323f8f status=Resolved comment="Alert resolved - false-positive." reopen=never
```

#### Context Example

```json
{
  "RecordedFutureAlerts": {
    "Alert": {
      "id": "task:fc34c790-293b-42bd-8f23-c1f571323f8f",
      "type": "playbook-alert",
      "status": "Resolved",
      "comment": "Alert resolved - false-positive."
    }
  }
}
```

### rf-alert-rules

***
Search for alert rule IDs.

#### Base Command

`rf-alert-rules`

#### Input

| **Argument Name** | **Description**                                   | **Required** |
|-------------------|---------------------------------------------------|--------------|
| rule_name         | Rule name to search. Can be a partial name.       | Optional     |
| limit             | Maximum number of rules to return. Default is 10. | Optional     |

#### Context Output

| **Path**                            | **Type** | **Description**  |
|-------------------------------------|----------|------------------|
| RecordedFutureAlerts.AlertRule.id   | string   | Alert rule ID.   | 
| RecordedFutureAlerts.AlertRule.name | string   | Alert rule name. | 

#### Command Example

```bash
!rf-alert-rules rule_name="malware" limit=3
```

#### Context Example

```json
{
  "RecordedFutureAlerts": {
    "AlertRule": [
      {
        "id": "mZbDYT",
        "name": "Malware Communication - External IP"
      },
      {
        "id": "mZbDZT",
        "name": "Malware Communication - Suspicious Domain"
      },
      {
        "id": "mxbDZT",
        "name": "Malware Communication - Command & Control"
      }
    ]
  }
}
```

### rf-alert-images

***
Fetch alert images and attach to incident in context Files.

#### Base Command

`rf-alert-images`

#### Command Example

```bash
!rf-alert-images
```

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description**                              |
|----------|----------|----------------------------------------------|
| Files    | Unknown  | New images are attached into incident Files. | 

