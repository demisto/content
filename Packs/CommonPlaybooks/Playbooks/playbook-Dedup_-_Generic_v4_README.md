This playbook identifies duplicate incidents using the Cortex XSOAR machine learning method (script).
In this playbook, you can choose fields and/or indicators to be compared against other incidents in the Cortex XSOAR database. 

Note: To identify similar incidents you must properly define the playbook inputs. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* DBotFindSimilarIncidents
* DBotFindSimilarIncidentsByIndicators

### Commands
* linkIncidents
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| method | Choose the way you want to identify similar incidents. Possible values: Indicators,  Fields, and Fields and Indicators. | Fields and Indicators | Required |
| handleSimilar | This input defines how to handle similar incidents. <br/>Possible values: Link, Close, and Link and Close.<br/>Note: Close incidents requires you to define the **CloseSimilar** input as well.<br/>Also, the incidents found by similar indicators or fields will be closed if their similarity score is above the **CloseSimilar** value. | Link | Required |
| fieldExactMatch | Select the incident field name you want the script to query.  <br/>For example, if you select 'Type', the playbook will query against the database for all incidents with the same type as your current incident.<br/> Note: If you use comma-separated values, the operator between them will be AND. |  | Optional |
| fieldsToDisplay | A comma-separated list of additional incident fields to display in the context output. These fields can be used later on for layouts or other states if needed.<br/>(Those which will not be taken into account when computing similarity). |  | Optional |
| fromDate | The start date to filter incidents. Date format is the same as in the incidents query page, for example, 3 days ago, 1 month ago, 2019-01-01T00:00:00 +0200. | 1 month ago | Optional |
| limit | The maximum number of incidents to query and set to context data. | 200 | Optional |
| minimunIncidentSimilarity | Retain incidents with a similarity score greater than the MinimunIncidentSimilarity.<br/>Value should be between 0 to 1 (0=low similarity, 1=identical) | 0.2 | Required |
| similarTextField | A comma-separated list of incident text fields to take into account when computing similarity. For example commandline, URL |  | Required |
| CloseSimilar | Defines the threshold of similarity to close a similar incident. All similar incidents with similarity above this value will be closed.<br/>For example, if CloseSimilar is set to .8 and an incident has a similarity score of .9, the incident will be closed.<br/>The value should be between 0 and 1 \[0=low similarity , 1=identical\]. |  | Optional |
| showIncidentSimilarityForAllFields | Whether to display the similarity score for each of the incident fields that were entered in the **similarTextField**. | True | Optional |
| query | The argument for dedicated query on incidents. This helps reduce the query size.<br/> | -status:closed -category:job <br/>(Same as in the **Incident** tab). | Optional |
| closeReason | Specify the reason for closing the incident. This information will be added as a note/comment to the closed incident. | Closed by Dedup Playbook within inc ${incident.id} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotFindSimilarIncidents | Return all the results from the "DBotFindSimilarIncidents" script. | string |

## Playbook Image
---
![Dedup - Generic v4](../doc_files/Dedup_-_Generic_v4.png)
