This v2 playbook is being used inside the "Phishing" flow. It will retrieve an original mail based on the inputs.

The inputs in this version are not using any labels and also allow the user to supply an email brand.

You must have the necessary permissions in your email service to execute a global search.

Optional email brand inputs and their required permissions:

- EWS: eDiscovery
- Gmail: Google Apps Domain-Wide Delegation of Authority
- MSGraph: As described here:
    * https://docs.microsoft.com/en-us/graph/api/message-get
    * https://docs.microsoft.com/en-us/graph/api/user-list-messages
- EmailSecurityGateway: Will retrieve eml files from:
    * FireEye EX
    * FireEye CM
    * Proofpoint Protection Server
    * Agari Phishing Defense
    * Mimecast

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* 3bb02e8c-dc28-4762-8ff0-0cd5e6534b0d
* Get Original Email - Microsoft Graph Mail
* Get Original Email - Gmail v2
* Get Original Email - EWS v2

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
| MessgaeID | The original email message id to retrieve. This should hold the value of the "Message-ID" header of the original email. |  | Optional |
| UserID | The email address of the user for which to fetch the original email. the authenticated user \(gmail\). |  | Optional |
| EmailSubject | The original email subject. |  | Optional |
| EmailBrand | When this value supplied, only the relevant playbook will run.<br/>Possible values:<br/>- Gmail<br/>- EWS v2<br/>- MicrosoftGraphMail<br/>- EmailSecurityGateway<br/>      \* FireEye EX \(Email Security\)<br/>      \* Proofpoint TAP<br/>      \* Agari Phishing Defense<br/>      \* Mimecast<br/><br/>If none of the above values is supplied, all of the playbooks will run. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Email | The email object | string |
| File | Original attachments | string |
| Email.To | The recipient of the email | string |
| Email.From | The sender of the email | string |
| Email.CC | The CC address of the email | string |
| Email.BCC | The BCC address of the email | string |
| Email.HTML | The email HTML | string |
| Email.Body | The email text body | string |
| Email.Headers | The email headers | string |
| Email.Subject | The email subject | string |
| Email.HeadersMap | The headers of the email. | unknown |
| reportedemailentryid | In case the original eml was retrieved, this field will hold the File's Entry ID. | string |

## Playbook Image
---
![Get Original Email - Generic v2](Insert the link to your image here)