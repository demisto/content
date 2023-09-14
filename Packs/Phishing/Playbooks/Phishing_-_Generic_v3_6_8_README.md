This playbook investigates and remediates a potential phishing incident. It engages with the user who triggered the incident while investigating the incident itself.

Note:
- Final remediation tasks are manual by default. can be managed by "SearchAndDelete" and "BlockIndicators" inputs. 
- Do not rerun this playbook inside a phishing incident since it can produce an unexpected result. Create a new incident instead if needed.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* TIM - Indicator Relationships Analysis
* Extract Indicators From File - Generic v2
* Process Email - Generic v2
* Detonate File - Generic
* Process Microsoft's Anti-Spam Headers
* Detect & Manage Phishing Campaigns
* Email Address Enrichment - Generic v2.1
* Calculate Severity - Generic v2
* Entity Enrichment - Phishing v2
* Phishing - Indicators Hunting
* Block Indicators - Generic v3
* Spear Phishing Investigation
* Detonate URL - Generic v1.5
* Search And Delete Emails - Generic v2
* Phishing - Machine Learning Analysis

### Integrations

This playbook does not use any integrations.

### Scripts

* SetAndHandleEmpty
* CheckEmailAuthenticity
* AssignAnalystToIncident
* Set

### Commands

* closeInvestigation
* setIncident
* setIndicator
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. |  | Required |
| SearchAndDelete | Enables the Search and Delete capability.<br/>For a malicious email, the "Search and Delete" sub-playbook looks for other instances of the email and deletes them pending analyst approval. | False | Optional |
| BlockIndicators | This input manages the automated block indicators capability.<br/>Set to "True" for automatically block all malicious indicators.<br/>Set to "False" to manually choose which indicators to block, if any. | False | Optional |
| AuthenticateEmail | Determines whether the authenticity of the email should be verified using SPF, DKIM, and DMARC. | True | Optional |
| OnCall | Set to True to assign only the user that is currently on shift. | False | Optional |
| SearchAndDeleteIntegration | Determines which product and playbook is used to search and delete the phishing email from user inboxes.<br/>  - Set this to "O365" to use the "O365 - Security And Compliance - Search And Delete" playbook.<br/>  - Set this to "EWS" to use the "Search And Delete Emails - EWS" playbook.<br/>  - Set this to "Gmail" to use the "Search And Delete - Gmail" playbook. | EWS | Optional |
| O365DeleteType | Sets the method to delete emails in the "O365 - Security And Compliance - Search And Delete" playbook. Can be "Soft" \(recoverable\), or "Hard" \(unrecoverable\). Leave empty to decide manually for each email incident.<br/>This is only applicable if the SearchAndDeleteIntegration input is set to "O365". | Soft | Optional |
| O365ExchangeLocation | The exchange location. Determines from where to search and delete emails using O365 playbooks. Use the value "All" to search all mailboxes. If no input provided, it will search and delete the email only from the recipient's mailboxes. Note - Searching all mailboxes may take a significant amount of time. This input is used only when searching and deleting emails in O365 and only applies if the SearchAndDeleteIntegration input is set to O365. |  | Optional |
| O365AllowNotFoundSearchLocations | Used only when searching and deleting emails in O365. Determines whether to include mailboxes other than regular user mailboxes in the compliance search. | False | Optional |
| O365ExchangeLocationExclusion | Used only when searching and deleting emails in O365. A comma-separated list of mailboxes/distribution groups to exclude when you use the value "All" for the O365ExchangeLocation input. |  | Optional |
| CheckMicrosoftHeaders | Whether to check Microsoft headers for BCL/PCL/SCL scores and set the "Severity" and "Email Classification" accordingly. | True | Optional |
| InternalDomains | A CSV list of internal domains. The list is used to determine whether an email address is internal or external. |  | Optional |
| DetonateURL | Determines whether to use the "URL Detonation" playbook. Detonating a URL may take a few minutes. | False | Optional |
| InternalRange | This input is used in the "Entity Enrichment - Phishing v2" playbook.<br/>A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges is: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, uses the default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| PhishingModelName | Optional - the name of a pre-trained phishing model to predict phishing type using machine learning. |  | Optional |
| GetOriginalEmail | For forwarded emails. When "True", retrieves the original email in the thread.<br/><br/>You must have the necessary permissions in your email service to execute global search.<br/><br/>- For EWS: eDiscovery<br/>- For Gmail: Google Apps Domain-Wide Delegation of Authority<br/>- For MSGraph: As described in these links<br/>https://docs.microsoft.com/en-us/graph/api/message-get<br/>https://docs.microsoft.com/en-us/graph/api/user-list-messages | False | Optional |
| DBotPredictURLPhishingURLsNumber | The number of URLs to extract from the email HTML and analyze in the "DBotPredictURLPhishing" automation.<br/>This automation runs several checks to determine the score of the URLs found in the email, sets a verdict for URLs found as "Suspicious" or "Malicious", and adds these URLs as indicators. Based on the verdict, the incident severity is set \(Medium for "Suspicious" and High for "Malicious"\).<br/>Note:<br/>- You need to install the "Phishing URL" pack to use this automation.<br/>- False/True positives are possible.<br/>- This automation may take a few minutes to run.<br/>- To increase result accuracy, it is recommended to install and enable the "Whois" pack \(optional\). | 3 | Optional |
| EmailFileToExtract | Reported emails and emails retrieved during playbook execution can contain multiple nested email files. For example, an EML nested inside another EML file.<br/>If multiple level files are detected, this field determines which file represents the phishing email.<br/><br/>For example:<br/>User1 receives an email from Attacker. User1 attaches the email as an EML file and sends the email to User2.<br/>User2 also attaches that email as a file, and reports it as phishing. In this case, the phishing email would be the "inner file" \(as opposed to "outer file"\).<br/><br/>Possible values are: Inner file, Outer file, All files.<br/>Inner file: The file at the deepest level is parsed. If there is only one file, that file is parsed.<br/>Outer file: The file at the first level is parsed.<br/>All files: All files are parsed. Do not use this option in the phishing playbook, as there should only be one phishing email per playbook run. | Inner file | Optional |
| HuntEmailIndicators | Whether to enter the "Email Indicators Hunting" branch in the playbook. Under this branch, sub-playbooks would be triggered in order to hunt malicious indicators found in other emails and optionally, automatically create new incidents for each found email \(configurable through next playbook inputs\). Default is "True". | True | Optional |
| EmailHuntingCreateNewIncidents | When "True", the "Phishing - Handle Microsoft 365 Defender Results" sub-playbook will open new phishing incidents for each email that contains one of the malicious indicators. Default is "False". | False | Optional |
| ListenerMailbox | The mailbox which is being used to fetch phishing incidents. This mailbox would be excluded in the "Phishing - Indicators Hunting" playbook.<br/>In case the value of this input is empty, the value of the "Email To" incident field will be automatically used as the listener mailbox. |  | Optional |
| SendMailInstance | The name of the instance to be used when executing the "send-mail" command in the playbook. In case it will be empty, all available instances will be used \(default\). |  | Optional |
| OriginalAuthenticationHeader | This input will be used as the "original_authentication_header" argument in the "CheckEmailAuthenticity" script under the "Authenticate email" task.<br/>The header that holds the original Authentication-Results header value. This can be used when an intermediate server changes the original email and holds the original header value in a different header. Note - Use this only if you trust the server creating this header. |  | Optional |
| UserEngagement | Specify whether to engage with the user via email for investigation updates.<br/>Set the value to 'True' to allow user engagement, or 'False' to avoid user engagement. | True | Optional |
| TakeManualActions | Specify whether to stop the playbook to take additional action before closing the incident.<br/>Set the value to 'True' to stop the playbook before closing the incidents, or "False" to close the incident once the playbook flow is done. | False | Optional |
| KeyWordsToSearch | A comma-separated list of keywords to search in the email body.<br/>For example: name of the organization finance app that the attacker might impersonate.<br/>This input is used in the "Spear Phishing Investigation" sub-playbook. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Phishing - Generic v3](../doc_files/Phishing_-_Generic_v3.png)
