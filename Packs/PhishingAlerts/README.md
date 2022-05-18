`Note`: For the Phishing use case, see the [Phishing Investigation - Generic v3 playbook](https://xsoar.pan.dev/docs/reference/playbooks/phishing---generic-v3).


Email security gateways produce a high volume of phishing alerts. To protect an organization from malicious emails, analysts investigating phishing alerts need to adjust their response procedures by email type, severity, or content to identify campaigns and inspect IoCs.
This content pack enables analysts to retrieve, process, and analyze email files to manage phishing alert incidents. 
The out-of-the-box items are robust enough to get you started, but are easily customizable to fit your specific requirements.


##### What Does This Pack Do?
- Retrieves emails from user inboxes or email security gateways.
- Creates a Phishing Alerts incident in Cortex XSOAR associated with the alert.
- Extracts and enriches all indicators from email attachments. 
- Analyzes files and provides reputation using your sandbox and threat intelligence integrations.
- Generates a screenshot of the email and embedded links, and calculates reputation for all indicators involved.
- Runs checks for URL SSL certificates, email address breach involvement, domain squatting and email authenticity using SPF, DKIM and DMARC checks.
- Identifies similar phishing incidents belonging to the same campaign and provides visibility and manual or automatic actions to respond to such incidents.
- Calculates severity for an incident based on initial severity, indicator reputations, email authenticity check, critical assets if any are involved, and alert action.
- Remediates the incident by blocking malicious indicators, searching for and deleting malicious emails upon analyst approval.
- Engages with the end user regarding the incident such as notifying them of receipt of email and providing further instructions if an email is found to be malicious.

This content pack also includes out-of-the-box phishing incident views, a full layout, and automation scripts. All of these are easily customizable to suit the needs of your organization.


![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/5153dd815b5288877b560e3fdcc3d9ab28cda57e/Packs/PhishingAlerts/doc_files/Phishing_Alerts_Investigation.png)
