Use the Hoxhunt integration to send feedback to reporters of incidents, set incident sensitivity, and apply SOC classification to incidents.
This integration was integrated and tested with version August 2024 of Hoxhunt.

## Configure Hoxhunt v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | e.g. <https://api.hoxhunt.com/graphql-external> | True |
| API Key | Input your api key from Hoxhunt | True |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |
| First fetch timestamp | \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\). Defaults to 7 days. | False |
| Fetch limit | Maxium number of incidents per fetch. Cap is 100. | False |
| Only fetch escalated incidents | If enabled, only escalated incidents will be fetched. Set up escalation rules in Hoxhunt Response -&gt; Incident Rules | False |
| Only fetch open incidents | If enabled, only open incidents will be fetched. | False |
| Use system proxy settings |  | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Hoxhunt to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Hoxhunt\), or Incoming and Outgoing \(from/to Cortex XSOAR and Hoxhunt\). | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### hoxhunt-current-user-get

***
Gets the current user information from Hoxhunt.

#### Base Command

`hoxhunt-current-user-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

##### Command Example

```!hoxhunt-current-user-get```


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HoxHunt.CurrentUser | string | Current User information from Hoxhunt. | 

### hoxhunt-incident-threats-get

***
Gets threats from Hoxhunt.

#### Base Command

`hoxhunt-incident-threats-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident the threats will be from. | Required | 
| sort | Sorting strategy to use when returning threats from API. Defaults to createdAt_DESC. See Hoxhunt API documentation for more information. | Optional | 
| limit | Limit the amount of threats returned. Defaults to 50, maximum is 100. | Optional | 
| filter | Filter string to use to pick only threats of interest. See Hoxhunt API documentation for more information. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.Threats | string | Threats from Hoxhunt. | 

##### Command Example

```!hoxhunt-incident-threats-get incident_id="12345" limit=5 sort="createdAt_DESC"```

### hoxhunt-incident-note-add

***
Add Incident note.

#### Base Command

`hoxhunt-incident-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident to which the note will be added. | Required | 
| note | The text content of the note to add to the Hoxhunt incident. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.addIncidentNode | string | Add Incident note. | 

##### Command Example

```!hoxhunt-incident-note-add incident_id="12345" note="Investigated and escalated to the SOC team."```


### hoxhunt-incident-threats-remove

***
Remove all threats that belong to an incident.

#### Base Command

`hoxhunt-incident-threats-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident from which threats will be removed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.removeIncidentThreats | number | Returns number of removed threats. | 

##### Command Example

```!hoxhunt-incident-threats-remove incident_id="12345"```


### hoxhunt-incident-soc-feedback-send

***
Send feedback to reporters of incident about whether the reported email was safe, spam or malicious.

#### Base Command

`hoxhunt-incident-soc-feedback-send`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident for which SOC feedback will be sent. | Required | 
| custom_message | A custom message to include with the SOC feedback. | Required | 
| threat_feedback_reported_at_limit | Datetime limit. Accepts (&lt;number&gt; &lt;time unit&gt;), e.g "7 days", "one month" or a iso string (e.g. "2024-10-30T08:37:42.359Z") | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.sendIncidentSocFeedback | string | The reporter will be informed the incident has been resolved and that no further actions are required from them. | 

##### Command Example

```!hoxhunt-incident-soc-feedback-send incident_id="12345" custom_message="User reported a phishing email." threat_feedback_reported_at_limit="2024-09-01T00:00:00Z"```


### hoxhunt-incident-set-sensitive

***
Set incident to contain sensitive information.

#### Base Command

`hoxhunt-incident-set-sensitive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident to be marked as sensitive or not sensitive. | Required | 
| is_sensitive | True or False Boolean for whether the incident contains sensitive information. Possible values are: TRUE, FALSE. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.setIncidentSensitive | string | Incident sensitivity information. | 

##### Command Example

```!hoxhunt-incident-set-sensitive incident_id="12345" is_sensitive=true```


### hoxhunt-incident-set-soc-classification

***
Set soc classification for an incident.

#### Base Command

`hoxhunt-incident-set-soc-classification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident to classify. | Required | 
| classification | The SOC classification to apply to the incident. Possible values are: MALICIOUS, SPAM, SAFE. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.setIncidentSocClassification | string | Incident SOC classification information. | 

##### Command Example

```!hoxhunt-incident-set-soc-classification incident_id="12345" classification="Malware"```


### hoxhunt-incident-update-state

***
Updates Incident state.

#### Base Command

`hoxhunt-incident-update-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Hoxhunt incident to update. | Required | 
| state | The new state of the incident. Possible values are: OPEN, RESOLVED. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.updateIncidentState | string | Incident state information. | 

##### Command Example

```!hoxhunt-incident-update-state incident_id="12345" state="RESOLVED"```

### get-mapping-fields

***
Get mapping fields from remote incident. Please note that this method will not update the current incident. It's here for debugging purposes.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Hoxhunt v2 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Hoxhunt v2 events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Hoxhunt v2 events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Hoxhunt v2 events will be reflected in both directions. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Hoxhunt v2.
