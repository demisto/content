Phishing emails are one of the most frequent, easily executable, and harmful security attacks that organizations – regardless of size – face today. High-volume, persistent phishing alerts are a time sink to manage, with incident response requiring coordination between multiple security products and communications with end users. 
This Phishing content pack includes playbooks that automate phishing alert response and custom phishing incident fields, views and layouts to facilitate analyst investigation. The phishing playbooks orchestrate across multiple products to extract and enrich IOCs, determine severity by cross-referencing against your external threat databases, send communications to your end users, identify and delete all instances of malicious emails to avoid further damage.
The pack also leverages machine learning to intelligently identify phishing campaigns targeting multiple users in the organization, linking them together and allowing full interaction and control over the campaign from within the incident layout.
With this content pack, you can significantly reduce the time your security analysts spend on phishing alerts and standardize the way you manage phishing incidents.


##### What does this pack do?
- Retrieve emails from user inboxes or ingest them using mail listeners.
- Create a phishing incident within Cortex XSOAR associated with the email.
- Extract and enrich all indicators from email attachments. Analyze files and provide reputation using your sandbox and threat intelligence integrations.
- Generate screenshot of the email and embedded links, and calculate reputation for all indicators involved.
- Run checks for SSL certificates of URLs, email address breach involvement, domain-squatting and email authenticity using SPF, DKIM and DMARC checks.
- Identify similar phishing incidents belonging to the same campaign, provide visibility and manual or automatic actions to respond to such incidents.
- Calculate severity for the incident based on initial severity provided, indicator reputations, email authenticity check and critical assets if any are involved.
- Remediate the incident by blocking malicious indicators, searching and deleting malicious emails upon analyst approval
- Engage with the end user regarding the incident such as notifying them of receipt of email and providing further instructions if email is found to be malicious.

As part of this pack, you will also get out-of-the-box phishing incident views, a full layout and automation scripts. All of these are easily customizable to suit the needs of your organization.

_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/playbooks/phishing-investigation---generic-v2)._

_If you're new to our Phishing Content Pack, check out our [Setting Up a Phishing Incident in Cortex XSOAR](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-tutorials/tutorials/phishing-use-case.html) tutorial._

![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/952153821f8de373a5d527df653bfa845d32f77e/Packs/Phishing/doc_files/Phishing_Investigation_-_Generic_v2_-_6_0.png)
