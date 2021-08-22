This playbook stores the SCL, BCL and PCL scores (if exists) to the associated incident fields (Phishing SCL Score, Phishing PCL Score, Phishing BCL Score).
It also does the following:
1) Sets the email classification to "spam" if the "SCL" score is equal or higher than 5.
2) Sets the incident severity according to the playbook inputs (default is: PCL/BCL - Medium, SCL - Low). The severity of the incident is set only when one (or more) of the following occurs:
- PCL (Phishing Confidence Level) score is between and including 4-8: The message content is likely to be phishing.
- BCL (Bulk complaint level) score is between and including 4-7: The message is from a bulk sender that generates a mixed number of complaints. Between and including 8-9: The message is from a bulk sender that generates a high number of complaints.
- SCL (Spam confidence level) score is between and including 5-6: Spam filtering marked the message as Spam. 9: Spam filtering marked the message as High confidence spam)

For further information on SCL/BCL/PCL, see the following Microsoft documentation:

https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/spam-confidence-levels?view=o365-worldwide

https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/bulk-complaint-level-values?view=o365-worldwide

https://docs.microsoft.com/en-us/exchange/antispam-and-antimalware/antispam-protection/antispam-stamps?view=exchserver-2019

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| BCL-Severity | Set the minimum severity of an incident with a BCL \(bulk sender\) that has a score equal to or higher than 4.<br/><br/>Available values: 0 \(Unknown\), 1 \(Low\), 2 \(Medium\), 3 \(High\), 4 \(Critical\). | 2 | Required |
| PCL-Severity | Set the minimum severity of an incident with a PCL \(phishing\) that has a score equal to or higher than 4.<br/><br/>Available values: 0 \(Unknown\), 1 \(Low\), 2 \(Medium\), 3 \(High\), 4 \(Critical\). | 2 | Required |
| SCL-Severity | Set the minimum severity of an incident with a SCL \(spam\) that has a score equal to or higher than 5.<br/><br/>Available values: 0 \(Unknown\), 1 \(Low\), 2 \(Medium\), 3 \(High\), 4 \(Critical\). | 1 | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.MicrosoftHeadersSeverityCheck | Possible Values:<br/><br/>Medium: PCL or BCL scores are equal to or higher than 4.<br/><br/>High: BCL score is equal to or higher than 8.<br/> | unknown |

## Playbook Image
---
![Process Microsoft's Anti-Spam Headers](../doc_files/Process_Microsoft's_Anti-Spam_Headers.png)