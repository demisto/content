This playbook is used to set shift handover meetings with all the accompanying processes such as online meeting ,notification to chatting app (for example Slack),SOC manager briefing, display of the active incidents,team members that are on call and team members that are out of the office.
By modifying the playbook inputs the user can decide if to activate the Assign Active Incidents to Next Shift or the user that out of the office will take in consideration. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Set a Shift handover meeting
* Assign Active Incidents to Next Shift_V2

### Integrations
This playbook does not use any integrations.

### Scripts
* GetUsersOOO
* SearchIncidentsV2
* SetGridField
* FindSimilarIncidents
* AssignAnalystToIncidentOOO
* Set

### Commands
* setIncident
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AssignActiveIncidentsToNextShift | Yes - If you wish that the Playbook will reassign active incidents to on-call users, the playbook will take in consideration users that are out of the office.<br/>No- If you do not wish to reassign active incidents, same incident owner will remain. <br/> | Yes | Optional |
| IncidentSearchQuery | Query for the Incidents to reassign.  Incidents need to be active for this to work, it will not reassign pending Incidents.  | status:active  -category:job  | Optional |
| AppChannelName  | The name of channel that would be created in your messaging app  for the shift handover.<br/>The should not contain upper case or special characters.   | daud | Optional |
| AppMessage  | The message that you wish to send to the handover to your messaging app channel that was created above. | Hi, please join the shift handover meeting. | Optional |
| SOCManagerEmail | In case that the Shift manager briefing section will be left empty when a new shift handover incident is opened, an Email will be send to this address to provide Shift manager briefing. | evisochek@paloaltonetworks.com | Optional |
| ShiftManagerBriefing  | The incident field that will provide the shift manager briefing for the layout. | ${incident.shiftmanagerbriefing} | Optional |
| TeamName | If using Microsoft Teams please provide your Microsoft team name. | DemistoTeam | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Shift handover](Insert the link to your image here)