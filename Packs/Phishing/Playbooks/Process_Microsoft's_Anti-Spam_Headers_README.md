This playbook will store SCL, BCL and PCL scores (if exist) to the associated incident fields (SCL Score, PCL Score, BCL Score).
It will also do the following:
1) Set the email classification to "spam" if the "SCL" score is equal or higher than 5.
2) Set the incident severity according to the playbook inputs (default is: PCL/BCL - Medium, SCL - Low). The severity of the incident will be set only when one (or more) of these cases occurred:
- PCL (Phishing Confidence Level) score is between 4-8: The message content is likely to be phishing.
- BCL (Bulk complaint level) score is above 4 -  4-7: The message is from a bulk sender that generates a mixed number of complaints. 8-9: The message is from a bulk sender that generates a high number of complaints.
- SCL (Spam confidence level) score is above 5 - 5-6: Spam filtering marked the message as Spam. 9: Spam filtering marked the message as High confidence spam)

For further information on SCL/BCL/PCL, please review these documentations from Microsoft:

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
| BCL-Severity | What would be the minimum severity of an incident with a BCL \(bulk sender\) score equal or higher than 4.<br/><br/>Available values: 0 \(Unknown\), 1 \(Low\), 2 \(Medium\), 3 \(High\), 4 \(Critical\). | 2 | Required |
| PCL-Severity | What would be the minimum severity of an incident with a PCL \(phishing\) score equal or higher than 4.<br/><br/>Available values: 0 \(Unknown\), 1 \(Low\), 2 \(Medium\), 3 \(High\), 4 \(Critical\). | 2 | Required |
| SCL-Severity | What would be the minimum severity of an incident with a SCL \(spam\) score equal or higher than 5.<br/><br/>Available values: 0 \(Unknown\), 1 \(Low\), 2 \(Medium\), 3 \(High\), 4 \(Critical\). | 1 | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.MicrosoftHeadersSeverityCheck | Possible Values:<br/><br/>Medium: PCL or BCL scores are equal or higher than 4.<br/><br/>High: BCL score is equal or higher than 8.<br/> | unknown |

## Playbook Image
---
![Process Microsoft's Anti-Spam Headers](../doc_files/Process_Microsoft's_Anti-Spam_Headers.png)