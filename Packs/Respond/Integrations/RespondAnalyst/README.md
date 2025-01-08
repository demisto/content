#### What is the Respond Analyst/Mandiant Defense Engine?
Disclaimer: Respond Software was recently acquired by FireEye and has rebranded from the Respond Analyst to the Mandiant Defense Engine. These terms refer to the same product. Most of this integration was written prior to rebranding, and primarily includes references to Respond. This will be updated in the future, at which point this disclaimer will be removed. 

Mandiant Defense is the cybersecurity investigation automation solution that connects the dots across disparate cybersecurity data to find real incidents fast. The Mandiant Defense engine is built to accelerate investigations for security operations teams in defense agencies, government bodies, universities, large enterprises, and leading managed service providers to get investigation power at machine speed. Mandiant Defense works with the broadest range of vendors, sensors, threat intelligence and data repositories in the industry to improve detection and response while raising security analyst productivity.

#### What does this pack do?

This pack provides a set of commands which can be executed against an instance of the Respond Analyst. The commands allow users to retrieve information from Respond and modify incidents from within XSOAR. Additionally, this integration supports bi-directional mirroring (for XSOAR v6 and above) of 
- incident closure status
- incident assignee
- incident feedback and notes
- incident title
- incident description

When fetch incidents is enabled, the pack will pull all open incidents from Respond into XSOAR. Each incident in XSOAR will follow the naming convention `<Respond Tenant Id>:<Respond Incident Id>`

It is worth noting that this pack does not pull in all of the data on each incident in Respond, rather a subset deemed to be most critical and helpful based on customer feedback. There is a link to the Respond incident provided on every corresponding XSOAR incident in case a user needs to retrieve additional information.

Use the Mandiant Automated Defense integration to fetch and update incidents from Mandiant Automated Defense. Mandiant Automated Defense fetches open incidents and updates them every minute. Changes made within XSOAR are reflected in Mandiant Automated Defense platform with bi-directional mirroring capabilities enabled.

## Configure Mandiant Automated Defense (Formerly Respond Software) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident Mirroring Direction |  | False |
| Base Url | https://&amp;lt;Respond Analyst Server&amp;gt; \(either hostname or IP address\) | True |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| API Token | steps to generate an API token here -&amp;gt; https://knowledge-base.respond-software.com/knowledge/api-token | True |
| Max Fetch |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Incidents Fetch Interval |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mad-get-incident
***
pull data for a specific incident from MAD. This command will only return an output of the incident data. it does not create a new incident


#### Base Command

`mad-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | ID of the Tenant in which the incident resides in Respond. | Optional | 
| incident_id | Respond incident ID of the incident to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mandiant.AutomatedDefense.Incident.incidentId | String | ID of incident | 
| Mandiant.AutomatedDefense.Incident.timeGenerated | Date | time incident was created | 
| Mandiant.AutomatedDefense.Incident.eventCount | Number | number of events associated with incident | 
| Mandiant.AutomatedDefense.Incident.firstEventTime | Date | time first event associated with incident occurred | 
| Mandiant.AutomatedDefense.Incident.lastEventTime | Date | time most recent event associated with incident occurred | 
| Mandiant.AutomatedDefense.Incident.URL | String | URL to incident in Mandiant Advantage platform | 
| Mandiant.AutomatedDefense.Incident.closeURL | String | URL to incident close page in Mandiant Advantage platform | 
| Mandiant.AutomatedDefense.Incident.title | String | incident title | 
| Mandiant.AutomatedDefense.Incident.description | String | incident description | 
| Mandiant.AutomatedDefense.Incident.status | String | incident status | 
| Mandiant.AutomatedDefense.Incident.severity | String | incident severity | 
| Mandiant.AutomatedDefense.Incident.probability | String | incident probability | 
| Mandiant.AutomatedDefense.Incident.attackStage | String | incident attack stage | 
| Mandiant.AutomatedDefense.Incident.attackTactic | Unknown | incident attack tactic | 
| Mandiant.AutomatedDefense.Incident.assetCriticality | String | incident asset criticiality | 
| Mandiant.AutomatedDefense.Incident.assetCount | Number | incident asset count | 
| Mandiant.AutomatedDefense.Incident.assets.hostname | String | asset hostname | 
| Mandiant.AutomatedDefense.Incident.assets.ipaddress | String | asset ip address | 
| Mandiant.AutomatedDefense.Incident.assets.isinternal | Boolean | asset is internal | 
| Mandiant.AutomatedDefense.Incident.externalsystems.hostname | String | system hostname | 
| Mandiant.AutomatedDefense.Incident.externalsystems.ipaddress | String | system ip address | 
| Mandiant.AutomatedDefense.Incident.externalsystems.isinternal | Boolean | system is internal | 
| Mandiant.AutomatedDefense.Incident.accounts.domain | Unknown | account domain | 
| Mandiant.AutomatedDefense.Incident.accounts.name | String | account name | 
| Mandiant.AutomatedDefense.Incident.hashes.hash | String | hash | 
| Mandiant.AutomatedDefense.Incident.malware.name | String | malware name | 
| Mandiant.AutomatedDefense.Incident.malware.type | String | malware type | 
| Mandiant.AutomatedDefense.Incident.malware.vendor | String | malware vendor | 
| Mandiant.AutomatedDefense.Incident.escalationreasons.label | String | escalation reason | 
| Mandiant.AutomatedDefense.Incident.assignedUsers | String | assigned users | 
| Mandiant.AutomatedDefense.Incident.tenantIdRespond | String | tenant id in mandiant | 
| Mandiant.AutomatedDefense.Incident.tenantId | String | tenant id external | 
| Mandiant.AutomatedDefense.Incident.respondRemoteId | String | remote id | 
| Mandiant.AutomatedDefense.Incident.dbotMirrorDirection | String | mirror direction | 
| Mandiant.AutomatedDefense.Incident.dbotMirrorInstance | String | mirror instance | 
| Mandiant.AutomatedDefense.Incident.owner | String | owner | 
| Mandiant.AutomatedDefense.Incident.feedback.timeUpdated | Date | time feedback updated | 
| Mandiant.AutomatedDefense.Incident.feedback.userId | String | user id | 
| Mandiant.AutomatedDefense.Incident.feedback.outcome | String | feedback outcome | 
| Mandiant.AutomatedDefense.Incident.feedback.comments | String | feedback comments | 

### mad-close-incident
***
close an incident in Respond and provide feedback on that incident. If the incident is already closed, feedback can still be updated. Additional comments and an updated closure code are viable options for updates on an incident that has already been closed (and on incidents that have not been closed yet as well)


#### Base Command

`mad-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | ID of the Tenant in which the incident resides in Respond. | Optional | 
| incident_id | Respond incident ID of the incident to retrieve. | Required | 
| incident_feedback | Outcome of the incident. Confirmed, Non-Actionable, or Inconclusive. This outcome is determined by the analyst who closes the incident. Possible values are: ConfirmedIncident, NonActionable, Inconclusive. | Optional | 
| feedback_optional_text | additional feedback information added by analysts. Any specific notes or observations. | Optional | 


#### Context Output

There is no context output for this command.
### mad-assign-user
***
assign a user to a Respond incident


#### Base Command

`mad-assign-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | respond incident id. | Required | 
| tenant_id | tenant id. | Optional | 
| username | email. | Required | 


#### Context Output

There is no context output for this command.
### mad-remove-user
***
unassign a user from a Respond incident


#### Base Command

`mad-remove-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | incident id. | Required | 
| tenant_id | tenant id. | Optional | 
| username | email. | Required | 


#### Context Output

There is no context output for this command.
### mad-get-escalations
***
Get escalation data associated with incident. In Respond, an 'escalation' is a specific event derived from a cybersecurity telemetry. Escalations are compiled together to form Incidents in Respond.


#### Base Command

`mad-get-escalations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | incident_id. | Required | 
| tenant_id | tenant id. | Optional | 


#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Mandiant Automated Defense (Formerly Respond Software) corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Mandiant Automated Defense (Formerly Respond Software) events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Mandiant Automated Defense (Formerly Respond Software) events (outgoing mirrored fields). |
    | Both |  |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Mandiant Automated Defense (Formerly Respond Software).