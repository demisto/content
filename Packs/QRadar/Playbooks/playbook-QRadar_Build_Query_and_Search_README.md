The Playbook creates an AQL query for the  QRadar SIEM using the QRadarCreateAQLQuery automation queries. Complex queries take into consideration several inputs and allow to include or exclude each of the values as well as perform a full or partial search. Each of the values can be searched across several fields.

The playbook supports 3 full separate conditions to be evaluated
For example in the first inputs will evaluate several user names that may or may not exist in several fields. The second input can for example evaluate for IP addresses in several fields that may or may not exist in several fields and a third value can search for an event id that may or may not exist in several fields. The results of all of the inputs will create an AQL query that covers all of the inputs combining all of the different conditions.

Each of the inputs is validated so in case the inputs are not set correctly the user can review and run again.
Also notice that populated inputs will be combined, meaning by populating the first and second values the resulting AQL query will be a combination of all of them and not 3 separate searches. In addition to that make sure to populate the inputs in order both according to the indexed fields in QRadar (indexed fields should be provided before non indexed ones).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* QRadarFullSearch
* QRadar Get Hunting Results

### Integrations
This playbook does not use any integrations.

### Scripts
* QRadarCreateAQLQuery

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| BaseValuesToSearch | The values of the first field to search. This can be a single value or a list of comma delimited values. For example admin1,admin2 |  | Optional |
| BaseFieldsToSearch | The field names of the first field to search. This can be a single value or a list of comma delimited values. For example username,user |  | Optional |
| BaseFieldState | The state of the first field to search, meaning are the values in the field should be included or excluded. Valid options are include or exclude. | include | Optional |
| BaseFieldMatch | Are the values of the first field suppose to be exact match or partial match. Valid options are exact or partial. When choosing exact the AQL query will use the = operator. When choosing partial the AQL query will ILIKE and add '%%' to the values. | exact | Optional |
| FirstAdditionalValues | The values of the second field to search. This can be a single value or a list of comma delimited values. For example admin1,admin2 |  | Optional |
| FirstAdditionalFields | The field names of the second field to search. This can be a single value or a list of comma delimited values. For example admin1,admin2 |  | Optional |
| FirstAdditionalFieldState | The state of the second field to search, meaning are the values in the field should be included or excluded. Valid options are include or exclude. | include | Optional |
| FirstAdditionalFieldMatch | Are the values of the second field suppose to be exact match or partial match. Valid options are exact or partial. | exact | Optional |
| SecondAdditionalValues | The values of the third field to search. This can be a single value or a list of comma delimited values. For example admin1,admin2 |  | Optional |
| SecondAdditionalFields | The field names of the third field to search. This can be a single value or a list of comma delimited values. For example username,user |  | Optional |
| SecondAdditionalFieldState | The state of the third field to search, meaning are the values in the field should be included or excluded. Valid options are include or exclude. | include | Optional |
| SecondAdditionalFieldMatch | Are the values of the third field suppose to be exact match or partial match. Valid options are exact or partial. When choosing exact the AQL query will use the = operator. When choosing partial the AQL query will ILIKE and add '%%' to the values. | exact | Optional |
| SelectFields | The list of fields to select within the AQL query<br/>The default fields are<br/>DATEFORMAT\(devicetime,'dd-MM-yyyy hh:mm'\),LOGSOURCENAME\(logsourceid\),CATEGORYNAME\(category\),QIDNAME\(qid\),sourceip,destinationip,username | DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username | Optional |
| TimeFrame | Time frame as used in AQL<br/>Examples can be<br/>LAST 7 DAYS<br/>START '2019-09-25 15:51' STOP '2019-09-25 17:51'<br/>For more examples review IBM's AQL documentation. | LAST 1 HOURS | Optional |
| UseHuntingResults | The QRadar Get Hunting Results playbook outputs the detected hosts, users and IP addresses detected in the QRadar search results. | false | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadar.Search.Result | The result of the search | string |
| QRadar.DetectedUsers | Users detected based on the username field in your search. | string |
| QRadar.DetectedInternalIPs | Internal IP addresses detected based on fields and inputs in your search. | string |
| QRadar.DetectedExternalIPs | External IP addresses detected based on fields and inputs in your search. | string |
| QRadar.DetectedInternalHosts | Internal host names detected based on hosts in your assets table. Note that the data accuracy depends on how the Asset mapping is configured in QRadar. | string |
| QRadar.DetectedExternalHosts | External host names detected based on hosts in your assets table. Note that the data accuracy depends on how the Asset mapping is configured in QRadar. | string |

## Playbook Image
---
![QRadar Build Query and Search](../doc_files/QRadar_Build_Query_and_Search.png