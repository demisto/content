Get the incident campaign's ID for the campaign that is linked to at least one  of the given incidents.

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
