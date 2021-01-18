This playbook is used to set up shift handover meetings with all the accompanying processes such as creating
- An online meeting
- A notification in an integration chat app (for example Slack)
- A SOC manager briefing
- A display of the active incidents, team members that are on-call, and team members that are out of the office.
By modifying the playbook inputs, you can decide whether to activate the Assign Active Incidents to Next Shift and whether a user who is out of the office will take in consideration. 

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
| AssignActiveIncidentsToNextShift | Yes - If you want the playbook will reassign active incidents to on-call users. The playbook will take into consideration users who are out of the office.<br/>No- If you do not want to reassign active incidents to on-call users. The current incident owner will remain. <br/> | Yes | Optional |
| IncidentSearchQuery | Query for the incidents to reassign.  Incidents need to be active. The playbook will not reassign pending incidents.  | status:active  -category:job  | Optional |
| AppChannelName  | The name of channel that will be created in your messaging app for the shift handover.<br/>The name of the channel should not contain uppercase or special characters.<br/>If you want to use an existing channel, add that name here..
Currently this input supports only two integrations: Microsoft Teams and Slack V2.
   | | Optional |
| AppMessage  | The message to send for the handover to your messaging app channel that you created. | Hi, please join the shift handover meeting. | Optional |
| SOCManagerEmail | If the Shift manager briefing section is left empty when a new shift handover incident is opened, an email will be send to this address to request a shift manager briefing.<br/>The playbook is not dependent on the SOC manager replying with an answer. The Shift manager briefing section will be updated in the  layout section whenever the answer is received.  |  | Optional |
| ShiftManagerBriefing  | The incident field that will provide the shift manager briefing for the layout. | ${incident.shiftmanagerbriefing} | Optional |
| TeamName | If using Microsoft Teams, provide your Microsoft team name.<br/>This input is mandatory for Microsoft Teams.   |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Shift handover](Insert the link to your image here)
