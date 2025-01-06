Gets the ID of an incident campaign that is linked to at least one of the given incidents.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | phishing, campaign |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| IncidentIDs | A comma-separated list of incidents ids to search an incident campaign for. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExistingCampaignID | The ID of an incident campaign that is linked to at least one of the given incidents. | String |
