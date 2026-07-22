This playbook retrieves email data based on the "URLDomain", "SHA256" and "IPAddress" inputs.
SHA256 - Emails with attachments matching the "SHA256" input are retrieved.
URLDomain - If the "URLDomain" value is found as a substring of URL(s) in the body of the email, the email is retrieved.
IPAddress - Emails with "SenderIPv4"/SenderIPv6" or URLs (in the body) matching the "IPAddress" input are retrieved.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Microsoft 365 Defender

### Scripts
* Set
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands
* microsoft-365-defender-advanced-hunting

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URLDomain | Domain or URL to search within emails. Can be a single domain or URL or an array of domains or URLs to search. The search looks for the exact Domain or URL. |  | Optional |
| SHA256 | The SHA256 hash file or an array of hashes to search within emails. |  | Optional |
| IPAddress | The source or destination IP address to search. Can be a single address or an array of IP addresses. |  | Optional |
| Timeout | The time limit in seconds for the HTTP request to run. Default is 60. | 60 | Optional |
| SearchTimeframe | Number of days past to search. Default is 7. | 7 | Optional |
| ResultsLimit | Number of retrieved entries. Enter -1 for unlimited query. 50 is the default. | 50 | Optional |
| ListenerMailbox | The mailbox of the listening integration. In case it is provided, the emails found in it will be ignored. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Microsoft365Defender.RetrievedEmails | Email objects containing relevant fields. | string |
| Microsoft365Defender.RetrievedEmails.InternetMessageId | Internet Message ID of the email. | string |
| Microsoft365Defender.RetrievedEmails.SenderFromDomain | Sender domain. | string |
| Microsoft365Defender.RetrievedEmails.EmailDirection | Email direction \(inbound/outbound\). | string |
| Microsoft365Defender.RetrievedEmails.DeliveryLocation | Delivery location. | string |
| Microsoft365Defender.RetrievedEmails.AuthenticationDetails | Authentication details \(SPF, DKIM, DMARC, CompAuth\). | string |
| Microsoft365Defender.RetrievedEmails.DeliveryAction | Delivery action. | string |
| Microsoft365Defender.RetrievedEmails.Subject | Email subject. | string |
| Microsoft365Defender.RetrievedEmails.AttachmentCount | Number of attachments. | string |
| Microsoft365Defender.RetrievedEmails.ThreatNames | Threat names. | string |
| Microsoft365Defender.RetrievedEmails.RecipientEmailAddress | Recipient email address. | string |
| Microsoft365Defender.RetrievedEmails.EmailAction | Email action. | string |
| Microsoft365Defender.RetrievedEmails.EmailLanguage | Email language. | string |
| Microsoft365Defender.RetrievedEmails.SenderFromAddress | Sender address. | string |
| Microsoft365Defender.RetrievedEmails.Timestamp | Timestamp. | string |
| Microsoft365Defender.RetrievedEmails.SenderDisplayName | Sender display name. | string |
| Microsoft365Defender.RetrievedEmails.SenderIPv4 | Sender IPv4. | string |
| Microsoft365Defender.RetrievedEmails.ConfidenceLevel | Confidence level. | string |
| Microsoft365Defender.RetrievedEmails.ThreatTypes | Threat types. | string |
| Microsoft365Defender.RetrievedEmails.SHA256 | SHA256 of the attachments \(if exists in the email\). | string |
| Microsoft365Defender.RetrievedEmails.Url | URLs found in the email's body. | string |
| Microsoft365Defender.RetrievedEmails.UrlCount | Number of URLs found in the email's body. | string |
| Microsoft365Defender.RetrievedEmails.SenderIPv6 | Sender IPv6. | unknown |

## Playbook Image
---
![Microsoft Defender XDR - Emails Indicators Hunt](../doc_files/Microsoft_365_Defender_-_Emails_Indicators_Hunt.png)