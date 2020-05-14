# Pack Documentation
A pack used for the complete investigation of potential phishing incidents. It can retrieve emails from user inboxes, extract and analyze attachments, authenticate the email using SPF, DKIM and DMARC checks, provide reputation for links and email adresses involved, and contain and remediate the incident by blocking malicious indicators found in the process with analyst approval.



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


##### Main Playbook Stages and Capabilities
- Performs a triage of a phishing incident, dissecting attached emails (EML or MSG files) or retrieving the original email from the user's inbox.
- Extracts and enriches all indicators from the suspected email and from its attachments. Analyzes files and provides reputation using sandbox and threat intelligence integrations.
- Provides a rendered image of HTML formatted emails, and screenshots for URLs that were found anywhere (email subject, body, attachments, etc.)
- Verifies SSL certificates for URLs and checks email addresses for known breaches and leaks and for domain-squatting.
- Calculates severity for the incident based on initial severity provided, indicator reputations, email authenticity check, and critical assets if any were involved.
- Allows remediation of the incident by blocking malicious indicators, searching and deleting malicious emails and allowing an analyst to manually take remediation steps. All potentially harmful actions require analyst approval.
- Engages with the user throughout the investigation - updating them when their email is received and starts to be investigated, and whether it is found to be malicious or benign.


##### Best Practices & Suggestions
- The email received in the designated phishing inbox should be an email **containing** the potential phishing email as a file attachment, so that the headers of the original suspected email are retained.
- Using Gmail or EWS v2 work best with the use case.
- If phishing emails are forwarded instead of attached as files, Auto extract should not be turned off so that all indicators are properly extracted and analyzed.
- Configuring the optional configurations can greatly enhance the investigation.

##### Visualization
![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/7a20daa4d3560df3be0d2f3f41c00d43ac1a1e23/Packs/Phishing/doc_files/Phishing_Investigation_Generic_v2.png)
