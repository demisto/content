This playbook identifies duplicate incidents using one of the supported methods.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
* FindSimilarIncidentsByText
* CloseInvestigationAsDuplicate
* FindSimilarIncidents
* GetDuplicatesMlv2

### Commands
* linkIncidents

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| DuplicateMethod | Select a method for identifying duplicate incidents. Can be &quot;ml&quot;, &quot;rules&quot;, or &quot;text&quot;. &\#x27;rules&\#x27; \- defines specific rules, such as similar incident fields &amp; labels. This method works best if you know the exact logic to find similar incidents. &\#x27;text&\#x27; \- text similarity, based on TF\-IDF \- unique word frequency in the incidents \(based on similar incident fields\) &\#x27;ml&\#x27; \- machine learning model, which was trained on similar phishing incidents. Considers similar labels, incident fields, and indicators. |  |  | Required |
| DuplicateThreshold | The similarity threshold by which to consider an incident as a duplicate \(0\-1\), where &quot;1&quot; is a duplicate and &quot;0&quot; is not a duplicate. Use this argument in the ML or text methods. | 0.9 |  | Required |
| TimeFrameHours | The time frame \(in hours\) in which to check for duplicate incident candidates. | 72 |  | Required |
| IgnoreCloseIncidents | Whether to ignore closed incidents. Can be &quot;yes&quot; or &quot;no&quot;. | yes |  | Required |
| MaxNumberOfCandidates | The maximum number of candidates to check for duplication. | 1000 |  | Optional |
| CloseAsDuplicate | Whether to close incidents identified as duplicates. Can be &quot;true&quot; or &quot;false&quot;. | true |  | Optional |
| TimeField | The Time field by which to query for past incidents to check for duplicate incident candidates. Values: created, occurred, modified | created |  | Optional |
| similarLabelsKeys | A comma\-separated list of similar label keys. Comma separated value. Also supports allowing X different words between labels, within the following way: label\_name:X, where X is the number of words. X can also be &\#x27;\*&\#x27; for contains. For example: the value &quot;Email/subject:\*&quot; will consider email subject similar, if one is substring of the other. Relevant for &\#x27;Rules&\#x27; method. |  |  | Optional |
| similarIncidentFields | Fields to compare. Can be label name, incident fields or custom fields. Comma separated value. Relevant for &\#x27;Text&\#x27; and &\#x27;Rules&\#x27; methods. | name,type,details |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| isSimilarIncidentFound | Whether a similar incident was found? Can be &quot;true&quot; or &quot;false&quot;. | boolean |
| similarIncident | The similar incident. | unknown |

![Playbook Image](https://github.com/demisto/content/raw/bd4b287e4642b242e8befcd6e832b66c4b03af97/Packs/CommonPlaybooks/doc_files/Dedup_-_Generic_v2.png)