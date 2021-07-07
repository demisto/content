This playbook will return SCL, BCL and PCL scores to the context (if exist).
It will also do the following:
1) Set the email classification to "spam" if the "SCL" score is equal or higher than 5.
2) Set a value of "Medium" to a "MicrosoftHeadersSeverityCheck" field in the context if the PCL or BCL value is higher than 4.

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
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SCL | Possible Values:<br/><br/>5 - Spam filtering marked the message as Spam or High confidence spam. | unknown |
| BCL | Possible Values:<br/><br/>4 - The message is from a bulk sender that generates a mixed number of complaints or a high number of complaints. | unknown |
| PCL | Possible Values:<br/><br/>4 - Likely to be phishing and marked as suspicious content. | unknown |
| Email.MicrosoftHeadersSeverityCheck | Possible Values:<br/><br/>Unknown - there is not enough data to determine the severity.<br/><br/>Medium - PCL or BCL scores are equal or higher than 4.<br/> | unknown |

## Playbook Image
---
![Process Microsoft's Anti-Spam Headers](Insert the link to your image here)