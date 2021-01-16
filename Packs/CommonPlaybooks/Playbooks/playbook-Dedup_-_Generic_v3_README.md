This playbook identifies duplicate incidents using one of the supported methods.
Select one of the following methods to identify duplicate incidents in Cortex XSOAR.
- **ml**: Machine learning model, which is trained mostly on phishing incidents.
- **rules**: Rules help identify duplicate incidents when the logic is well defined, for example, the same label or custom fields.
- **text**: Statistics algorithm that compares text, which is generally useful for phishing incidents.
For each method, the playbook will search for the oldest similar incident. when there is a match for a similar incident the playbook will close the current incident and will link it to the older incident. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* CloseInvestigationAsDuplicate
* PhishingDedupPreprocessingRule
* FindSimilarIncidentsByText
* FindSimilarIncidents

### Commands
* linkIncidents

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DuplicateMethod | Select a method for identifying duplicate incidents. Can be "ml", "rules", or "text". <br/>'rules' - define specific rules, such as similar incident fields &amp;amp; labels. This method works best if you know the exact logic to find similar incidents. <br/>'text' - text similarity, based on TF-IDF - unique word frequency in the incidents \(based on similar incident fields\) <br/>'ml' - machine learning model, which was trained on similar phishing incidents. Considers similar labels, incident fields, and indicators. |  | Required |
| exsitingIncidentsLookback | Use only with ML Method.<br/>The start date by which to search for duplicated existing incidents. The date format is the same as in the incidents query page. For example, "3 days ago", "2019-01-01T00:00:00 \+0200" | 7 days ago | Optional |
| statusScope | Use only with ML Method.<br/>Whether to compare the new incident to past closed or non-closed incidents only.   <br/>"All" - Default. Compares to all incidents.<br/>"ClosedOnly" - Compares to closed incidents.<br/>"NonClosedOnly" - Compare to open incidents. |  | Optional |
| fromPolicy | Use only with ML Method.<br/>Whether to take into account the email from field for deduplication.<br/><br/>"TextOnly" - incidents will be considered duplicated based on test similarity only, ignoring the sender's address. <br/><br/>"Exact" - incidents will be considered duplicated if their text is similar, and their sender is the same. <br/><br/>"Domain" -  Default. Incidents will be considered duplicated if their text is similar, and their senders' address has the same domain. |  | Optional |
| DuplicateThreshold | The similarity threshold by which to consider an incident as a duplicate \(0-1\), where "1" is a duplicate and "0" is not a duplicate. Use this argument in the ML or text methods. | 0.7 | Required |
| TimeFrameHours | The time frame \(in hours\) in which to check for duplicate incident candidates. | 72 | Optional |
| IgnoreCloseIncidents | Whether to ignore closed incidents. Can be "yes" or "no". | yes | Optional |
| MaxNumberOfCandidates | The maximum number of candidates to check for duplication. | 1000 | Optional |
| CloseAsDuplicate | Whether to close incidents identified as duplicates. Can be "true" or "false". | true | Optional |
| TimeField | The Time field by which to query for past incidents to check for duplicate incident candidates. Values: created, occurred, modified | created | Optional |
| similarLabelsKeys | A comma-separated list of similar label keys. Comma separated value. Also supports allowing X different words between labels, within the following way: label_name:X, where X is the number of words. X can also be '\*' for contains. For example: the value "Email/subject:\*" will consider email subject similar, if one is substring of the other. Relevant for 'Rules' method. |  | Optional |
| similarIncidentFields | Fields to compare. Can be label name, incident fields, or custom fields. Comma-separated value. Relevant for 'Text' and 'Rules' methods. | name,type,details | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| isSimilarIncidentFound | Whether a similar incident was found? Can be "true" or "false". | boolean |
| similarIncident | The similar incident. | unknown |

## Playbook Image
---
![Dedup - Generic v3](https://raw.githubusercontent.com/demisto/content/b66c9f284175ad7fa2bfc0295982234110becae1/Packs/CommonPlaybooks/doc_files/Dedup_-_Generic_v3.png)
