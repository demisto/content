Deprecated. Please use Dedup Generic v3. This playbook identifies duplicate incidents using one of the supported methods.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* FindSimilarIncidentsByText
* CloseInvestigationAsDuplicate
* FindSimilarIncidents
* GetDuplicatesMlv2

### Commands
* linkIncidents

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DuplicateMethod | Select a method for identifying duplicate incidents. Can be "ml", "rules", or "text". 'rules' - defines specific rules, such as similar incident fields &amp;amp; labels. This method works best if you know the exact logic to find similar incidents. 'text' - text similarity, based on TF-IDF - unique word frequency in the incidents \(based on similar incident fields\) 'ml' - machine learning model, which was trained on similar phishing incidents. Considers similar labels, incident fields, and indicators. |  | Required |
| DuplicateThreshold | The similarity threshold by which to consider an incident as a duplicate \(0-1\), where "1" is a duplicate and "0" is not a duplicate. Use this argument in the ML or text methods. | 0.9 | Required |
| TimeFrameHours | The time frame \(in hours\) in which to check for duplicate incident candidates. | 72 | Required |
| IgnoreCloseIncidents | Whether to ignore closed incidents. Can be "yes" or "no". | yes | Required |
| MaxNumberOfCandidates | The maximum number of candidates to check for duplication. | 1000 | Optional |
| CloseAsDuplicate | Whether to close incidents identified as duplicates. Can be "true" or "false". | true | Optional |
| TimeField | The Time field by which to query for past incidents to check for duplicate incident candidates. Values: created, occurred, modified | created | Optional |
| similarLabelsKeys | A comma-separated list of similar label keys. Comma separated value. Also supports allowing X different words between labels, within the following way: label_name:X, where X is the number of words. X can also be '\*' for contains. For example: the value "Email/subject:\*" will consider email subject similar, if one is substring of the other. Relevant for 'Rules' method. |  | Optional |
| similarIncidentFields | Fields to compare. Can be label name, incident fields or custom fields. Comma separated value. Relevant for 'Text' and 'Rules' methods. | name,type,details | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| isSimilarIncidentFound | Whether a similar incident was found? Can be "true" or "false". | boolean |
| similarIncident | The similar incident. | unknown |

## Playbook Image
---
![Dedup - Generic v2](https://github.com/demisto/content/raw/bd4b287e4642b242e8befcd6e832b66c4b03af97/Packs/CommonPlaybooks/doc_files/Dedup_-_Generic_v2.png)