This playbook identifies duplicate incidents using the XSOAR machine learning method (script).
In this playbook, you can choose how to find similar incidents by using fields and/or indicators to be compared against other incidents in the XSOAR DB.

Remember that the identification of similar incidents is *must* be defined properly in the playbook's inputs. 

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
| method | Choose the way you want to identify similar incidents. Choose between "Indicators" / "Fields" / "Fields and Indicators"  . | Fields and Indicators | Required |
| handleSimilar | This input defines how to handle Similar incidents. <br/>You may choose between: "Link", "Close", "Link and Close".<br/>Note: that closing incidents will require you to define "CloseSimilar" input as well.<br/>Also, note that the closer will apply on at least one of the options \(indicators or fields\) which will match the "closer percentage" criteria.<br/>Default: Link  | Link | Required |
| fieldExactMatch | Please select those incident types which you would like to be \*equal\* on queried incidents. <br/>For example - if you put &amp;lt;Type&amp;gt;, the PB will query against the DB for all the incidents with the same type as your current incident.<br/>If you are using comma-separated values - please remember that the operator between them will be \*AND\*. |  | Optional |
| fieldsToDisplay | Comma-separated list of additional incident fields to display in the context output. Those fields can be used later on for Layouts or other states if needed.<br/>\(Those which will not be taken into account when computing similarity\) |  | Optional |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example, "3 days ago", "1 months ago", "2019-01-01T00:00:00 \+0200"\). | 1 months ago | Optional |
| limit | The maximum number of incidents to query and set to context data.<br/>Default is: 200 | 200 | Optional |
| minimunIncidentSimilarity | Retain incidents with a similarity score that's higher than the MinimunIncidentSimilarity.<br/>Default: 0.2<br/>Value should be between 0 to 1 \[0=low similarity, 1=identical\] | 0.2 | Required |
| similarTextField | Comma-separated list of incident text fields to take into account when computing similarity. For example commandline, URL |  | Required |
| CloseSimilar | Define if you would like to close incidents by a similarity percentage. The percentage will be the bottom border for closing inc.<br/>This option will close also exact matches as well \( if there are\).<br/>Value should be between 0 to 1 \[0=low similarity , 1=identical\] |  | Optional |
| showIncidentSimilarityForAllFields | Whether to display the similarity score for each of the incident fields that was entered in the "similarTextField".<br/>Default: True | True | Optional |
| query | The argument for dedicated query on incidents. This helps reduce the query size.<br/>Default \(same is in the Incident tab\): "-status:closed -category:job " | -status:closed -category:job | Optional |
| closeReason | Please specify the reason for closing an incident. This information will be added as a note/comment to the closed incident. | Closed by Dedup Playbook within inc ${incident.id} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotFindSimilarIncidents | Return all the results from the "DBotFindSimilarIncidents" script | string |

## Playbook Image
---
![Dedup - Generic v4](../doc_files/Dedup_-_Generic_v4.png)