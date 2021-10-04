  This playbook includes the following tasks:
  - Search for the Security Notice email sent from Codecov.
  - Collect indicators to be used in your threat hunting process.
  - Query network logs to detect related activity.
  - Search for the use of Codecov bash uploader in GitHub repositories
  - Query Panorama to search for logs with related anti-spyware signatures
    - Data Exfiltration Traffic Detection
    - Malicious Modified Shell Script Detection
    

  Note: This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.

  More information:
  [Codecov Security Notice](https://about.codecov.io/security-update/)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Splunk Indicator Hunting
* QRadar Indicator Hunting V2
* Palo Alto Networks - Hunting And Threat Detection

### Commands
* extractIndicators
* ews-search-mailbox

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| KnownRelatedIOCs | Known related IOCs to the Codecov Bash Uploader breach to hunt. | 104.248.94.23 | Optional |
| CustomIOCs | Add your own custom Codecov Bash Uploader breach IOCs to hunt. |  | Optional |
| EWSSearchQuery | The EWS query to find the Codecov security notice email | From:security@codecov.io AND Subject:Bash Uploader Security Notice AND Received:three months | Optional |
| EWSSearchQuery_Limit | The limit of results to return from the search | 50 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Codecov - Bash Uploader Unauthorized Access](https://raw.githubusercontent.com/demisto/content/73c80557e51755f8fbb2cbf123fac1e04fb3e50f/Packs/MajorBreachesInvestigationandResponse/doc_files/Codecov_breach_-_Bash_Uploader.png)