

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| SimilarityThresholdToSplitBy | The similarity value on which to split the context campaign data. |
| campaign_context_path | The context full path of the EmailCampaign. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailCampaign.incidents.id | The IDs of the incidents involved in the campaign. | Unknown |
| EmailCampaign.incidents.similarity | The textual similarity of the related emails to the current incident. | Unknown |
| EmailCampaign.incidents.emailfrom | The senders of the emails involved in the campaign. | Unknown |
| EmailCampaign.incidents.emailfromdomain | The domains of the email senders involved in the campaign. | Unknown |
| EmailCampaign.incidents.recipients | A list of email addresses of recipients involved in the campaign. The list is comprised of the following fields, "Email To", "Email CC", "Email BCC". | Unknown |
| EmailCampaign.incidents.recipientsdomain | A list of the domains of the email addresses of recipients involved in the campaign. The list is comprised of the following fields, "Email To", "Email CC", "Email BCC". | Unknown |
| EmailCampaign.LowerSimilarityIncidents.id | The IDs of the incidents involved in the campaign. | Unknown |
| EmailCampaign.LowerSimilarityIncidents.similarity | The textual similarity of the related emails to the current incident. | Unknown |
| EmailCampaign.LowerSimilarityIncidents.emailfrom | The senders of the emails involved in the campaign. | Unknown |
| EmailCampaign.LowerSimilarityIncidents.emailfromdomain | The domains of the email senders involved in the campaign. | Unknown |
| EmailCampaign.LowerSimilarityIncidents.recipients | A list of email addresses of recipients involved in the campaign. The list is comprised of the following fields, "Email To", "Email CC", "Email BCC". | Unknown |
| EmailCampaign.LowerSimilarityIncidents.recipientsdomain | A list of the domains of the email addresses of recipients involved in the campaign. The list is comprised of the following fields, "Email To", "Email CC", "Email BCC". | Unknown |
