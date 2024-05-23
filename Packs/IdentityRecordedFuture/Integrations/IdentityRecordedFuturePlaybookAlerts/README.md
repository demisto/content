Fetch & triage | Recorded Future Identity - Playbook Alerts
This integration was integrated and tested with version 1.0.2 of IdentityRecordedFuturePlaybookAlerts

## Configure **Recorded Future Identity - Playbook Alerts** on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Recorded Future Identity - Playbook Alerts**.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                     | **Description**                                                                                                                                                             | **Required** |
    |-------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
    | API URL (e.g., https://api.recordedfuture.com/gw/xsoar-identity/) |                                                                                                                                                                             | True         |
    | API Token                                                         |                                                                                                                                                                             | True         |
    | Trust any certificate (not secure)                                |                                                                                                                                                                             | False        |
    | Use system proxy settings                                         |                                                                                                                                                                             | False        |
    | Fetch incidents                                                   |                                                                                                                                                                             | False        |
    | First Incidient Fetch: Time Range                                 | Limit incidents to include in the first fetch by time range. Input format: "NN hours" or "NN days". E.g., input "5 days" to fetch all incidents created in the last 5 days. | False        |
    | Playbook Alerts: Fetched Categories                               | Some listed Playbook alert Categories might be unavailable due to limitations in the current Recorded Future subscription                                                   | False        |
    | Maximum number of incidents per fetch                             |                                                                                                                                                                             | False        |
    | Playbook Alerts: Fetched Statuses                                 |                                                                                                                                                                             | False        |
    | Playbook Alerts: Fetched Priorities Threshold                     | Returns alerts with this selected priority or higher. High &amp;gt; Moderate &amp;gt; Informational                                                                         | False        |
    | Incident type                                                     |                                                                                                                                                                             | False        |

4. Click **Test** to validate the URLs, token, and connection.

## Pre-Process Rule

The integration pulls in Playbook alerts from Recorded Future base on its updates, this creates the need for a preprocessing rule that updates existing incidents instead of creating duplicates. Follow the guidlines below to configure the preprocessing rule.

1. Navigate to **Settings** > **Integrations** > **Pre-Process Rules**
2. Click **New Rule**
3. Enter a name for the rule
4. In the Conditions for Incoming Incident section, enter the following:
**Name** - **Includes** - **Recorded Future Identity Playbook Alert**
5. In the Action section, select: Drop and update
6. In the Update section, choose:
**Link to** - **Oldest incident** - **Created within the last** - *Your desired timeframe*
7. In the rule for update, choose:
**DbotMirrorId** - **Is identical (Incoming Incident)** - **to incoming incident**

![Pre-process Rule](../../doc_files/playbook_alerts_pre_process_rule.png)

> The configuration of the preprocessing rule is optional, but highly recommended.


## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### recordedfuture-identity-playbook-alerts-details

***
Get Playbook alert details by id.

#### Base Command

`recordedfuture-identity-playbook-alerts-details`

#### Input

| **Argument Name** | **Description**                                                                                                                                        | **Required** |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| alert_ids         | Ids of the playbook alert that should be fetched.                                                                                                      | Required     | 
| detail_sections   | What evidence sections to include in the fetch, fetches all available if not specified. Possible values are: status, action, summary, log, whois, dns. | Optional     | 

##### Command Example
```!recordedfuture-identity-playbook-alerts-details alert_ids="12312312-1231-1231-1231-123123123123" detail_sections="status,log"```

#### Context Output

| **Path**                                                                                      | **Type** | **Description**                                                           |
|-----------------------------------------------------------------------------------------------|----------|---------------------------------------------------------------------------|
| IdentityRecordedFuture.PlaybookAlerts.playbook_alert_id                                       | String   | Unique id of the playbook alert                                           | 
| IdentityRecordedFuture.PlaybookAlerts.category                                                | String   | Playbook alert category                                                   | 
| IdentityRecordedFuture.PlaybookAlerts.priority                                                | String   | Recommended Priority of the alert                                         | 
| IdentityRecordedFuture.PlaybookAlerts.status                                                  | String   | Current alert status in Recorded Future                                   | 
| IdentityRecordedFuture.PlaybookAlerts.title                                                   | String   | Title of the alert                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.updated                                                 | date     | Date of last update                                                       | 
| IdentityRecordedFuture.PlaybookAlerts.created                                                 | date     | Date of creation                                                          | 
| IdentityRecordedFuture.PlaybookAlerts.organization_id                                         | String   | Organization uhash                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.organization_name                                       | String   | Plaintext Organization name                                               | 
| IdentityRecordedFuture.PlaybookAlerts.assignee_id                                             | String   | uhash of the assigned user                                                | 
| IdentityRecordedFuture.PlaybookAlerts.assignee_name                                           | String   | name of the assigned user                                                 | 
| IdentityRecordedFuture.PlaybookAlerts.owner_id                                                | String   | uhash of the enterprise that owns the alert                               | 
| IdentityRecordedFuture.PlaybookAlerts.owner_name                                              | String   | Name of the enterprise that owns the alert                                | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.playbook_alert_id                          | String   | Unique id of the playbook alert                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.category                                   | String   | Playbook alert category                                                   | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.priority                                   | String   | Recommended Priority of the alert                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.status                                     | String   | Current alert status in Recorded Future                                   | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.title                                      | String   | Title of the alert                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.updated                                    | date     | Date of last update                                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.created                                    | date     | Date of creation                                                          | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.organization_id                            | String   | Organization uhash                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.organization_name                          | String   | Plaintext Organization name                                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.assignee_id                                | String   | uhash of the assigned user                                                | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.assignee_name                              | unknown  | name of the assigned user                                                 | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.owner_id                                   | String   | uhash of the enterprise that owns the alert                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.owner_name                                 | String   | Name of the enterprise that owns the alert                                | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.case_rule_id                               | String   | Id of the playbook alert category                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.case_rule_label                            | String   | Name of the playbook alert category                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.context_list.context                       | Array    | Context of entity connected to the Playbook alert.                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.created                                    | String   | Date marking the creation of the Playbook alert in Recorded Future        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.entity_criticality                         | String   | Criticality of the Playbook alert                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.entity_id                                  | String   | Id of the entity in Recorded Future                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.entity_name                                | String   | Name of the entity                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.risk_score                                 | String   | Risk score of the entity in Recorded Future                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.targets                                    | Array    | List of targets of the Playbook alert                                     | 
| IdentityRecordedFuture.PlaybookAlerts.panel_status.lifecycle_stage                            | String   | Indicates what lifecycle the vulerability is in                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.explanation                               | String   | Entails the explanation to the triggering of the Playbook alert           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.resolved_record_list.context_list.context | String   | Context of entity connected to the Playbook alert.                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.resolved_record_list.criticality          | String   | Level of criticality                                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.resolved_record_list.entity               | String   | ID of the entitiy in Recorded Future                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.resolved_record_list.record_type          | String   | Type of record A, CNAME or MX                                             | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.resolved_record_list.risk_score           | String   | Risk score of the entity in Recorded Future                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.screenshots.description                   | String   | Description of the image                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.screenshots.image_id                      | String   | ID of the screenshot in Recorded Future                                   | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.screenshots.tag                           | String   | Image Analisys tag                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.screenshots.created                       | String   | When the image was created                                                | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.screenshots.base64                        | String   | The image binary encoded as a base64 string                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.summary.targets.name                      | String   | Target affected by the vulnerability                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.summary.lifecycle_stage                   | String   | The current lifecycle stage of the Playbook Alert                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.summary.riskrules.rule                    | String   | Name of the rule that triggered                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.summary.riskrules.description             | String   | Short description of the trigger \(E.g 13 sightings on 1 source..\)       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.affected_products.name                    | String   | Name of of affected product                                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.insikt_notes.id                           | String   | The id of the Insikt note                                                 | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.insikt_notes.title                        | String   | The title of the Insikt note                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.insikt_notes.topic                        | String   | The topic of the Insikt note                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.insikt_notes.published                    | String   | The time at which the Insikt note was published                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_summary.insikt_notes.fragment                     | String   | A fragment of the Insikt note text                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.id                                            | String   | Log id in Recorded Future                                                 | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.actor_id                                      | String   | Id of the actor                                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.created                                       | String   | When was the log created                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.modified                                      | String   | When was the log last modified                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.action_priority                               | String   | The priority of the Playbook alert                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.message                                       | String   | Log message                                                               | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.assigne_change.old                    | String   | Previous assignee                                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.assigne_change.new                    | String   | New assignee                                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.assigne_change.type                   | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.status_change.old                     | String   | Previous status                                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.status_change.new                     | String   | New status                                                                | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.status_change.type                    | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.title_change.old                      | String   | Previous title                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.title_change.new                      | String   | New title                                                                 | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.title_change.type                     | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.priority_change.old                   | String   | Previous priority                                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.priority_change.new                   | String   | New priority                                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.priority_change.type                  | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.reopen_strategy_change.old            | String   | Previous reopen strategy                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.reopen_strategy_change.new            | String   | New reopen strategy                                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.reopen_strategy_change.type           | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.entities_change.removed               | String   | Removed entity                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.entities_change.added                 | String   | Added entity                                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.entities_change.type                  | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.related_entities_change.removed       | String   | Removed related entity                                                    | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.related_entities_change.added         | String   | Added related entity                                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.related_entities_changetype           | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.description_change.old                | String   | Previous description                                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.description_change.new                | String   | New description                                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.description_change.type               | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.external_id_change.old                | String   | Previous external ID                                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.external_id_change.new                | String   | New external ID                                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_log.changes.external_id_change.type               | String   | Type of change                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.action                                     | String   | The name of the action                                                    | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.updated                                    | String   | When was the action last updated                                          | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.assignee_name                              | String   | Full name of the assignee                                                 | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.assignee_id                                | String   | ID of the assignee                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.status                                     | String   | The status of the action                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.description                                | String   | A short description of the action                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_action.link                                       | String   | A link associated with the action                                         | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ip_list.record                                | String   | The DNS record                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ip_list.risk_score                            | String   | Risk score associated with the record                                     | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ip_list.criticality                           | String   | The level of criticality                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ip_list.record_type                           | String   | Type of record A, CNAME or MX                                             | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ip_list.context_list.context                  | String   | Labels of malicious behavior types that can be associated with an entity. | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.mx_list.record                                | String   | The DNS record                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.mx_list.risk_score                            | String   | Risk score associated with the record                                     | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.mx_list.criticality                           | String   | The level of criticality                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.mx_list.record_type                           | String   | Type of record A, CNAME or MX                                             | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.mx_list.context_list.context                  | String   | Labels of malicious behavior types that can be associated with an entity. | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ns_list.record                                | String   | The DNS record                                                            | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ns_list.risk_score                            | String   | Risk score associated with the record                                     | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ns_list.criticality                           | String   | The level of criticality                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ns_list.record_type                           | String   | Type of record A, CNAME or MX                                             | 
| IdentityRecordedFuture.PlaybookAlerts.panel_dns.ns_list.context_list.context                  | String   | Labels of malicious behavior types that can be associated with an entity. | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.added                                  | String   | When the whois information was added                                      | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.attribute                              | String   | Attribute, either whois or whoisContancts                                 | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.entity                                 | String   | Id of whois entity                                                        | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.provider                               | String   | Name of provider                                                          | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.createdDate                      | String   | When was it created                                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.nameServers                      | Array    | List of name server IDs                                                   | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.privateRegistration              | Bool     | Boolean indicating private registration                                   | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.registrarName                    | String   | Name of the registrar                                                     | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.status                           | String   | Status of registrar                                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.city                             | String   | Contact located in this city                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.country                          | String   | Contact located in this city                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.name                             | String   | Name of contact                                                           | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.organization                     | String   | Name of contact organization                                              | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.postalCode                       | String   | Postal code of contact organization                                       | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.state                            | String   | Contact located in state                                                  | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.street1                          | String   | Street name of contact                                                    | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.telephone                        | String   | Phone number of contact                                                   | 
| IdentityRecordedFuture.PlaybookAlerts.panel_whois.body.value.type                             | String   | Type of contact                                                           | 

### recordedfuture-identity-playbook-alerts-update

***
Update the status of one or multiple Playbook alerts

#### Base Command

`recordedfuture-identity-playbook-alerts-update`

#### Input

| **Argument Name** | **Description**                                                                                            | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------|--------------|
| alert_ids         | Ids of the playbook alerts that will be updated.                                                           | Required     | 
| new_status        | New status to set for all alerts in alert_ids. Possible values are: new, in-progress, dismissed, resolved. | Required     | 

##### Command Example
```!recordedfuture-identity-playbook-alerts-update alert_ids="12312312-1231-1231-1231-123123123123" new_status="New"```

#### Context Output

| **Path**                                                | **Type** | **Description**                                     |
|---------------------------------------------------------|----------|-----------------------------------------------------|
| IdentityRecordedFuture.PlaybookAlerts.playbook_alert_id | string   | Unique id of the playbook alert in Recorded Future  | 
| IdentityRecordedFuture.PlaybookAlerts.current_status    | string   | Current status of playbook alert in Recorded Future | 
| IdentityRecordedFuture.PlaybookAlerts.title             | string   | Title of the playbook alert in Recorded Future      | 
| IdentityRecordedFuture.PlaybookAlerts.status_message    | string   | Message describing the outcome of the update        | 

### recordedfuture-identity-playbook-alerts-search

***
Search playbook alerts based on filters

#### Base Command

`recordedfuture-identity-playbook-alerts-search`

#### Input

| **Argument Name**     | **Description**                                                                                                                             | **Required** |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| limit                 | Limits the number of alerts to fetch. Default: 10.                                                                                          | Optional     | 
| time_since_update     | Time between now and e.g. "2 hours" or "7 days" ago. Default: "24 hours".                                                                   | Optional     | 
| playbook_alert_status | Filter what statuses are fetched, defaults to only new status if not specified. Possible values are: new, in-progress, dismissed, resolved. | Optional     | 
| priority              | Actions pritority assigned in Recorded Future. Possible values are: high, moderate, informational.                                          | Optional     | 
| order_search_by       | Actions pritority assigned in Recorded Future. Possible values are: updated, created.                                                       | Optional     | 

##### Command Example
```!recordedfuture-identity-playbook-alerts-search```
```!recordedfuture-identity-playbook-alerts-search```
```!recordedfuture-identity-playbook-alerts-search limit=10```
```!recordedfuture-identity-playbook-alerts-search playbook_alert_status=in-progress```
```!recordedfuture-identity-playbook-alerts-search priority=high```
```!recordedfuture-identity-playbook-alerts-search order_search_by=updated```


#### Context Output

| **Path**                                                | **Type** | **Description**                             |
|---------------------------------------------------------|----------|---------------------------------------------|
| IdentityRecordedFuture.PlaybookAlerts.playbook_alert_id | String   | Unique id of the playbook alert             | 
| IdentityRecordedFuture.PlaybookAlerts.category          | String   | Playbook alert category                     | 
| IdentityRecordedFuture.PlaybookAlerts.priority          | String   | Recommended Priority of the alert           | 
| IdentityRecordedFuture.PlaybookAlerts.status            | String   | Current alert status in Recorded Future     | 
| IdentityRecordedFuture.PlaybookAlerts.title             | String   | Title of the alert                          | 
| IdentityRecordedFuture.PlaybookAlerts.updated           | date     | Date of last update                         | 
| IdentityRecordedFuture.PlaybookAlerts.created           | date     | Date of creation                            | 
| IdentityRecordedFuture.PlaybookAlerts.organization_id   | String   | Organization uhash                          | 
| IdentityRecordedFuture.PlaybookAlerts.organization_name | String   | Plaintext Organization name                 | 
| IdentityRecordedFuture.PlaybookAlerts.assignee_id       | String   | uhash of the assigned user                  | 
| IdentityRecordedFuture.PlaybookAlerts.assignee_name     | unknown  | name of the assigned user                   | 
| IdentityRecordedFuture.PlaybookAlerts.owner_id          | String   | uhash of the enterprise that owns the alert | 
| IdentityRecordedFuture.PlaybookAlerts.owner_name        | String   | Name of the enterprise that owns the alert  | 
