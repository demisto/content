Get the incident campaign's ID for the campaign that is linked to at least one  of the given incidents.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations
](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

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
| CampaignIncidentType | The type of incident campaign to search in. |
| IncidentIDs | Comma separated list of incidents ids to search for. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExistingCampaignID | The incident campaign's ID for the campaign that is linked to at least one  of the given incidents. | String |
