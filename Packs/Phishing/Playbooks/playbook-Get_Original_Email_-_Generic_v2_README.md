This v2 playbook is used inside the phishing flow. The inputs in this version do not use labels and also allow the user to supply an email brand.
Note: You must have the necessary permissions in your email service to execute a global search.

To retrieve the email files directly from the email service providers, use one of the provided inputs (Agari Phishing Defense customers should also use the following):
- EWS: eDiscovery
- Gmail: Google Apps Domain-Wide Delegation of Authority
- MSGraph: As described in the [message-get API](https://docs.microsoft.com/en-us/graph/api/message-get) and the [user-list-messages API](https://docs.microsoft.com/en-us/graph/api/user-list-messages).
- EmailSecurityGateway retrieves EML files from:
    * FireEye EX
    * FireEye CM
    * Proofpoint Protection Server
    * Mimecast

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get Email From Email Gateway - Generic
* Get Original Email - EWS v2
* Get Original Email - Microsoft Graph Mail
* Get Original Email - Gmail v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MessageID | The original email message ID to retrieve. This should hold the value of the "Message-ID" header of the original email. |  | Optional |
| UserID | The email address of the user to fetch the original email for. For gmail, the authenticated user. |  | Optional |
| EmailSubject | The original email subject. |  | Optional |
| EmailBrand | If this value is provided, only the relevant playbook runs. If no value is provided, all sub-playbooks are run.<br/>Possible values:<br/><ul><li>Gmail</li><li>EWS v2</li><li>MicrosoftGraphMail</li><li>EmailSecurityGateway</li></ul>Choosing EmailSecurityGateway executes the following if enabled:<ul><li>FireEye EX (Email Security)</li><li>Proofpoint TAP</li><li>Mimecast</li></ul> |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email | The email object. | String |
| File | The original email attachments. | String |
| Email.To | The email recipient. | String |
| Email.From | The email sender. | String |
| Email.CC | The email CC address. | String |
| Email.BCC | The email BCC address. | String |
| Email.HTML | The email HTML. | String |
| Email.Body | The email text body. | String |
| Email.Headers | The email headers. | String |
| Email.Subject | The email subject. | String |
| Email.HeadersMap | The email headers map. | Unknown |
| reportedemailentryid | If the original EML was retrieved, this field holds the file's entry ID. | String |

## Playbook Image
---
![Get Original Email - Generic v2](https://raw.githubusercontent.com/demisto/content/07a19d09dad3bfef74e03552446107a973752fe2/Packs/Phishing/doc_files/Get_Original_Email_-_Generic_v2.png)
