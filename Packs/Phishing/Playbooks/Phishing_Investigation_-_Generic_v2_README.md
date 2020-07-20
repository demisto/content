## Usage

Use this playbook to investigate and remediate a potential phishing incident. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

##### Triggers
The investigation is triggered by an email sent or forwarded to a designated "phishing inbox". A mail listener integration that listens to that mailbox, will use every received email to create a phishing incident in Cortex XSOAR.
A mail listener can be one of the following integrations:
- EWS v2
- Gmail
- Mail Listener (does not support retrieval of original emails when the suspected emails are not attached)

##### Configuration
- Create an email inbox that should be used for phishing reports. Make sure the user in control of that inbox has the permissions required by your integration (EWS v2 or Gmail).
- Configure the `Phishing` incident type to run the `Phishing Investigation - Generic v2` playbook.
- Configure the inputs of the main `Phishing Investigation - Generic v2` playbook.
- Optional - configure the Active Directory critical asset names under the inputs of the `Calculate Severity - Generic v2` inputs or leave them empty.
- Optional - Should you want to perform domain-squatting checks - configure the `InternalDomains` input of the `Email Address Enrichment - Generic v2.1` playbook. We recommend to configure this so we can provide better insight into phishing emails.
- Optional - Configure the `InternalRange` and `ResolveIP` inputs of the `IP Enrichment - External - Generic v2` playbook.
- Optional - Configure the `Rasterize` and `VerifyURL` inputs of the `URL Enrichment - Generic v2` playbook.
- Optional - Personalize the user engagement messages sent throughout the investigation in the `Phishing Investigation - Generic v2` playbook. 
These task have the following names:
  - Acknowledge incident was received (task #13)
  - Update the user that the reported email is safe (task #16)
  - Update the user that the reported email is malicious (task #17
  
##### Best Practices & Suggestions
- The email received in the designated phishing inbox should be an email **containing** the potential phishing email as a file attachment, so that the headers of the original suspected email are retained.
- Using Gmail or EWS v2 work best with the use case.
- If phishing emails are forwarded instead of attached as files, Auto extract should not be turned off so that all indicators are properly extracted and analyzed.
- Configuring the optional configurations can greatly enhance the investigation.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

#### Sub-playbooks
* Extract Indicators From File - Generic v2
* Domain Enrichment - Generic v2
* URL Enrichment - Generic v2
* Block Indicators - Generic v2
* Search And Delete Emails - Generic
* Calculate Severity - Generic v2
* Process Email - Generic
* File Enrichment - Generic v2
* Detonate File - Generic
* IP Enrichment - External - Generic v2
* Email Address Enrichment - Generic v2.1

#### Integrations
* Builtin

#### Scripts
* DBotPredictPhishingWords
* AssignAnalystToIncident
* CheckEmailAuthenticity
* Set

#### Commands
* setIncident
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator |  | Required |
| SearchAndDelete | Enable the &quot;Search and Delete&quot; capability \(can be either &quot;True&quot; or &quot;False&quot;\).
In case of a malicious email, the &quot;Search and Delete&quot; sub\-playbook will look for other instances of the email and delete them pending analyst approval. | False |  | Optional |
| BlockIndicators | Enable the &quot;Block Indicators&quot; capability \(can be either &quot;True&quot; or &quot;False&quot;\).
In case of a malicious email, the &quot;Block Indicators&quot; sub\-playbook will block all malicious indicators in the relevant integrations. | False |  | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | False |  | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | false |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.


## Playbook Image
---
![Phishing_Investigation_Generic_v2](https://github.com/demisto/content/raw/4000f5d617a0929a78095a6bb3aa90279b9ee527/Packs/Phishing/doc_files/Phishing_Investigation_Generic_v2.png)
