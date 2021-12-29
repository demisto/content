This playbook executes one sub-playbook and one automation to check the email headers:
- **Process Microsoft's Anti-Spam Headers** - This playbook stores the SCL, BCL and PCL scores if they exist to the relevant incident fields (Phishing SCL Score, Phishing PCL Score, Phishing BCL Score).
- **CheckEmailAuthenticity** - This automation checks email authenticity based on its SPF, DMARC, and DKIM.
 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Process Microsoft's Anti-Spam Headers

### Integrations
This playbook does not use any integrations.

### Scripts
CheckEmailAuthenticity

### Commands
setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AuthenticateEmail | Whether the email authenticity should be verified using SPF, DKIM and DMARC. | False | Optional |
| CheckMicrosoftHeaders | Whether to check Microsoft headers for BCL/PCL/SCL scores and set the "Severity" and "Email Classification" accordingly. | False | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email.AuthenticityCheck | Possible values:<br/>Fail / Suspicious / Undetermined / Pass | Unknown |
| Email.MicrosoftHeadersSeverityCheck | Possible values:<br/>Medium: PCL or BCL scores are equal to or higher than 4.<br/>High: BCL score is equal to or higher than 8.<br/> | Unknown |

## Playbook Image
---
![Email Headers Check - Generic](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/CommonPlaybooks/doc_files/Email_Headers_Check_-_Generic.png)
