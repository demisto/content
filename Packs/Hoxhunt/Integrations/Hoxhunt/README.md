Use the Hoxhunt integration to send feedback to reporters of incidents, set incident sensitivity, and apply SOC classification to incidents.
This integration was integrated and tested with version August 2024 of Hoxhunt.

## Configure Hoxhunt in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://api.hoxhunt.com/graphql-external) |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| API Key | Input your api key from Hoxhunt | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Query Filter | Input a query filter for incidents to be fetched | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### hoxhunt-get-current-user

***
Gets the current user information from Hoxhunt.

#### Base Command

`hoxhunt-get-current-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HoxHunt.CurrentUser | string | Current User information from Hoxhunt. | 

### hoxhunt-get-incidents

***
Gets incidents from Hoxhunt.

#### Base Command

`hoxhunt-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Input here the filter or other arguments. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.Incidents | string | Incidents from Hoxhunt. | 

### hoxhunt-get-threats

***
Gets threats from Hoxhunt.

#### Base Command

`hoxhunt-get-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Input here the filter or other arguments. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.Threats | string | Threats from Hoxhunt. | 

### hoxhunt-add-incident-note

***
Add Incident note.

#### Base Command

`hoxhunt-add-incident-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to which the note will be added. | Required | 
| note | The content of the note to add to the incident. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.addIncidentNode | string | Add Incident note. | 

### hoxhunt-remove-incident-threats

***
Remove all threats that belong to an incident.

#### Base Command

`hoxhunt-remove-incident-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from which threats will be removed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.removeIncidentThreats | number | Returns number of removed threats. | 

### hoxhunt-send-incident-soc-feedback

***
Send feedback to reporters of incident about whether the reported email was safe, spam or malicious.

#### Base Command

`hoxhunt-send-incident-soc-feedback`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident for which SOC feedback will be sent. | Required | 
| custom_message | A custom message to include with the SOC feedback. | Required | 
| threat_feedback_reported_at_limit | Datetime limit. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.sendIncidentSocFeedback | string | The reporter will be informed the incident has been resolved and that no further actions are required from them. | 

### hoxhunt-set-incident-sensitive

***
Set incident to contain sensitive information.

#### Base Command

`hoxhunt-set-incident-sensitive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to be marked as sensitive or not sensitive. | Required | 
| is_sensitive | True or False Boolean. Possible values are: TRUE, FALSE. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.setIncidentSensitive | string | Incident sensitivity information. | 

### hoxhunt-set-incident-soc-classification

***
Set soc classification for an incident.

#### Base Command

`hoxhunt-set-incident-soc-classification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to classify. | Required | 
| classification | The SOC classification to apply to the incident. Possible values are: MALICIOUS, SPAM, SAFE. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.setIncidentSocClassification | string | Incident SOC classification information. | 

### hoxhunt-update-incident-state

***
Updates Incident state.

#### Base Command

`hoxhunt-update-incident-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to update. | Required | 
| state | The new state of the incident. Possible values are: OPEN, RESOLVED. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hoxhunt.updateIncidentState | string | Incident state information. | 

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Hoxhunt corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Hoxhunt.