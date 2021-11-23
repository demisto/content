Email Security Gateways produce a high amount of phishing alerts. An analyst who addresses these alerts will need to adjust his response procedures by the type, severity, or content. It is vital to respond to these alerts to identify campaigns, analyze their IoCs, and protect the organization from any malicious payload that was delivered within them.
These content items enable you to retrieve, process and analyze email files, and manage phishing alerts incidents. The out-of-the-box items are robust enough to get you started, but are easily customizable to fit your specific requirements


##### What does this pack do?
- Retrieve emails from user inboxes or email security gateways.
- Create a Phishing Alerts incident within Cortex XSOAR associated with the alert.
- Extract and enrich all indicators from email attachments. Analyze files and provide reputation using your sandbox and threat intelligence integrations.
- Generate screenshot of the email and embedded links, and calculate reputation for all indicators involved.
- Run checks for SSL certificates of URLs, email address breach involvement, domain-squatting and email authenticity using SPF, DKIM and DMARC checks.
- Identify similar phishing incidents belonging to the same campaign, provide visibility and manual or automatic actions to respond to such incidents.
- Calculate severity for the incident based on initial severity provided, indicator reputations, email authenticity check, critical assets if any are involved and alert action.
- Remediate the incident by blocking malicious indicators, searching and deleting malicious emails upon analyst approval.
- Engage with the end user regarding the incident such as notifying them of receipt of email and providing further instructions if email is found to be malicious.

As part of this pack, you will also get out-of-the-box phishing incident views, a full layout and automation scripts. All of these are easily customizable to suit the needs of your organization.


![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/PhishingAlerts/doc_files/Phishing_Alerts_Investigation.png)
