This playbook is responsible for alert data enrichment and response.
The playbook executes the following:

1.Checks if the initiator is a remote attacker and allow isolating the remote host if possible.

2.Retrieve the WildFire sandbox report and extract the indicators within it.
    * The playbook will try retrieving the report, if there is no report available, the playbook will try fetching the ransomware file for detonation.

3.Hunt for the ransomware alert indicators over the alert table and searches for endpoints that have been seen with them and allows containing the identified endpoints.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Containment Plan
* WildFire - Detonate file

### Integrations
* CortexCoreIR
* CoreIOCs

### Scripts
* SearchIncidentsV2
* isError

### Commands
* file
* wildfire-report
* core-retrieve-file-details
* ip
* url
* core-isolate-endpoint
* core-retrieve-files
* extractIndicators
* core-get-endpoints
* domain

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| isolateRemoteAttacker | Whether to isolate the remote attacker host. | true | Optional |
| isolateSimilarEndpoints | Whether to isolate endpoints which has been detected with the alert IoCs. | false | Optional |
| FileSHA256 | The ransomware file SHA256. | alert.initiatorsha256 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Ransomware Enrich and Contain](Insert the link to your image here)