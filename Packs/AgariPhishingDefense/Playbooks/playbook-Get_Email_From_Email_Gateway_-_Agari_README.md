Retrieve a specified eml/msg file directly from Gmail, Mail Listener v2, EWS O365, or Microsoft Graph Mail using the Agari Phishing Defense playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* ews-search-mailbox
* gmail-get-mail
* mail-listener-get-email-as-eml
* msgraph-mail-get-email
* msgraph-mail-get-email-as-eml
* mail-listener-get-email
* gmail-get-attachments
* ews-get-items-as-eml

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MessageID | Message Id of email. |  | Optional |
| UserID | User Id of user. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EmailData | From field, Html Text of body, Headers, Text of body, Subject of email. | unknown |

## Playbook Image
---
![Get Email From Email Gateway - Agari](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/AgariPhishingDefense/doc_files/Get_Email_From_Email_Gateway_-_Agari.png)