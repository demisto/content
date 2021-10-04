Find a campaign of emails based on their textual similarity.

This script can be executed upon each new incoming Phishing incident.
The script would search among past incidents whether past incidents with high text similarity to the current one exist. The script uses NLP techniques for calculating text similarity. The text similarity is calculated based on the email body and email subject fields of the phishing incident.
If such incidents were found, the script would aggregate details regarding them, such as their senders, recipients, dates, mutual indicators, snippets from the email, etc.
This script's purpose is to provide you an immediate background for phishing incidents when similar incidents exist, and furthermore, help you to detect phishing campaigns more  easily.


## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml, phishing |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Detect & Manage Phishing Campaigns

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentTypeFieldName | The name of the incident field in which the incident type is stored. Default is "type". Change this argument only if you are using a custom field for specifying the incident type. |
| incidentTypes | A comma-separated list of incident types by which to filter. Specify "None" to search through all incident types. |
| existingIncidentsLookback | The date from which to search for similar incidents. Date format is the same as in the incidents query page. For example: "3 days ago", "2019-01-01T00:00:00 \+0200". |
| query | Additional text by which to query incidents. |
| limit | The maximum number of incidents to fetch. |
| emailSubject | The name of the field that contains the email subject. |
| emailBody | The name of the field that contains the email body. |
| emailBodyHTML | The name of the field that contains the HTML version of the email body. |
| emailFrom | The name of the field that contains the email sender. |
| statusScope | Whether to compare the new incident to closed incidents, unclosed incidents, or all incidents. |
| threshold | Threshold by which to consider incidents as similar. The range of values is 0-1. |
| maxIncidentsToReturn | The maximum number of incidents to display as part of a campaign. If a campaign includes a higher number of incidents, the results will contain only this amount of incidents. |
| minIncidentsForCampaign | Minimum number of incidents to consider as a campaign. |
| minUniqueRecipients | Minimum number of unique recipients of similar email incidents to consider as a campaign. |
| fieldsToDisplay | A comma-seperated list of fields to display. An example is "emailclassification,closereason". If a list of fields is provided, and a campaign is detected, these incidents fields will be displayed. |
| includeSelf | Include the current incident in EmailCampaign path in context. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailCampaign.isCampaignFound | Whether a campaign was found. | Boolean |
| EmailCampaign.involvedIncidentsCount | The number of incidents involved in the campaign. | Number |
| EmailCampaign.incidents.id | The IDs of the incidents involved in the campaign. | Unknown |
| EmailCampaign.incidents.similarity | The textual similarity of the related emails to the current incident. | Unknown |
| EmailCampaign.incidents.emailfrom | The senders of the emails involved in the campaign. | Unknown |
| EmailCampaign.incidents.emailfromdomain | The domains of the email senders involved in the campaign. | Unknown |
| EmailCampaign.incidents.recipients | A list of email addresses of recipients involved in the campaign. The list is comprised of the following fields, "Email To", "Email CC", "Email BCC". | Unknown |
| EmailCampaign.incidents.recipientsdomain | A list of the domains of the email addresses of recipients involved in the campaign. The list is comprised of the following fields, "Email To", "Email CC", "Email BCC". | Unknown |
| EmailCampaign.indicators.id | The IDs of the mututal indicators of the incidents involved in the campaign. | Unknown |
| EmailCampaign.indicators.value | The values of the mututal indicators of the incidents involved in the campaign. | Unknown |
| EmailCampaign.fieldsToDisplay | List of fields to display in the linked list table. | Unknown |
| EmailCampaign.firstIncidentDate | The occurrence date of the oldest incident in the campaign. | unknown |
| incident.emailcampaignsummary | Markdown table with email campaign summary. | string |
| incident.emailcampaignsnippets | Markdown table with email content summary. | string |
| incident.emailcampaignmutualindicators | Markdown table with relevant indicators. | string |
| incident.emailcampaigncanvas | Link to the campaign canvas. | string |
