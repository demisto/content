A generic playbook for handling Xpanse issues.
The logic behind this playbook is to work with an internal exclusions list which will help the analyst to get to a decision or, if configured, close incidents automatically.
The phases of this playbook are:
  1) Check if assets (IP, Domain or Certificate) associated with the issue are excluded in the exclusions list and optionally, close the incident automatically.
  2) Optionally, enrich indicators and calculate the severity of the issue, using sub-playbooks.
  3) Optionally, allow the analyst to add associated assets (IP, Domain or Certificate) to the exclusions list.
  4) Tag associated assets.
  5) Update the status of the issue.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Extract and Enrich Expanse Indicators
* Calculate Severity - Standard
* Expanse Load-Create List

### Integrations
ExpanseV2

### Scripts
* AddKeyToList
* Set
* ExpanseRefreshIssueAssets

### Commands
* expanse-update-issue
* expanse-create-tag
* expanse-get-certificate
* expanse-assign-tags-to-asset
* closeInvestigation
* expanse-get-issue-comments

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExclusionsList | The name of an internal XSOAR list which includes all IP values or domain values in the allowed list.  If no list currently exists, the playbook will create it for you with the given name.<br/>The structure of this list should be:<br/><br/>\{<br/> "Addresses":\[<br/>    \{<br/>      "ip": "x.x.x.x",<br/>      "issueTypeID": "issueTypeIDHere",<br/>      "port": 123,<br/>      "protocol": "UDP"<br/>    \},<br/>    \{<br/>      "ip": "x.x.x.x",<br/>      "issueTypeID": "issueTypeIDHere",<br/>      "port": 456,<br/>      "protocol": "TCP"<br/>    \},<br/>    .<br/>    .<br/>    .<br/>  \],<br/>"Domains":\[<br/>   \{<br/>     "domain":"some.domain.com",<br/>     "issueTypeID": "issueTypeIDHere",<br/>     "port": 80,<br/>     "protocol": "TCP"<br/>   \}<br/>   .<br/>   .<br/>   .<br/> \] ,<br/>"Certificates":\[<br/>   \{<br/>     "sha256fingerprint":"value of sha256 fingerprin",<br/>     "issueTypeID": "issueTypeIDHere",<br/>     "subject": "certificate subject"<br/>   \}<br/>   .<br/>   .<br/>   .<br/> \]<br/>\}<br/><br/>For example:<br/><br/>\{<br/>   "Addresses":\[<br/>      \{<br/>         "ip":"10.0.0.1",<br/>         "issueTypeID":"MissingXFrameOptionsHeader",<br/>         "port":443,<br/>         "protocol": "TCP"<br/>      \},<br/>      \{<br/>         "ip":"10.0.0.2",<br/>         "issueTypeID":"WildcardCertificate",<br/>         "port":443,<br/>         "protocol": "TCP"<br/>      \}<br/>   \],<br/>   "Domains":\[<br/>	   \{<br/>	     "domain":"my.domain.com",<br/>	     "issueTypeID": "ApacheWebServer",<br/>	     "port": 443,<br/>	     "protocol": "TCP"<br/>	   \}	<br/>   \],<br/>   "Certificates":\[<br/>       \{<br/>         "sha256fingerprint":"f2ca1bb.....6fd2",<br/>     	 "issueTypeID": "ShortKeyCertificate",<br/>     	 "subject": "C=US,ST=WASHINGTON,L=.....E=John@test.com"<br/>   	\}<br/>   \]<br/>\}<br/><br/>In the above example, we will add to allow list "MissingXFrameOptionsHeader" issue type ID on 10.0.0.1:443, "WildcardCertificate" issue type ID on 10.0.0.2:443, "ApacheWebServer" issue type ID on my.domain.com:443 And "ShortKeyCertificate" on a certificate with a specific sha256 fingerprint and subject.  | XpanseExclusionsList | Required |
| EnrichIndicators | Whether to extract and enrich indicators automatically using the "Entity Enrichment - Generic V3" playbook. | True | Optional |
| CalculateSeverity | Whether to calculate the severity of the incident automatically using the "Calculate Severity - Standard" playbook. | True | Optional |
| CommonTags | A comma-separated list of common tags \(lower case letters\) which your organization uses.<br/>For example:<br/>tag1, tag2, tag3 ... |  | Optional |
| CloseWhenExcluded | True - Close the incident automatically if the current issue's certificate or domain are excluded. If an IP is excluded, close automatically only if there is no domain for the incident.<br/><br/>False - Let the analyst go over the incident manually even if the assets are excluded. |  | Optional |
| AutomaticTagValue | If the value of "CloseWhenExcluded" is "True", tag associated assets with this value in Xpanse. <br/>For example, if the value of "AutomaticTagValue" is "excluded-in-xsoar", the tag "excluded-in-xsoar" will be assigned to the assets. | excluded-in-xsoar | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Xpanse Incident Handling - Generic](https://github.com/demisto/content/raw/97883646d9289a6d020bd511c1a268ec0ad5a70a/Packs/ExpanseV2/doc_files/Xpanse_Incident_Handling_-_Generic.png)
