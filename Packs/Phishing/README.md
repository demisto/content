`Note`: For the Phishing Alerts use case, see the [Phishing Alerts Investigation pack](https://xsoar.pan.dev/docs/reference/packs/Phishing-Alerts).

Phishing emails are one of the most frequent, easily executable, and harmful security attacks that organizations – regardless of size – face today. High-volume, persistent phishing alerts are a time sink to manage, with incident response requiring coordination between multiple security products and communications with end users. 
With the Phishing content pack, you can significantly reduce the time your security analysts spend on phishing alerts and standardize the way you manage phishing incidents.
This content pack includes playbooks that:
- Facilitate analyst investigation by automating phishing alert response and custom phishing incident fields, views, and layouts. 
- Orchestrate across multiple products, including cross-referencing against your external threat databases.
The pack also leverages machine learning to intelligently identify phishing campaigns targeting multiple users in the organization, linking them together and allowing full interaction and control over the campaign from within the incident layout.


##### What does this pack do?
- Retrieves emails from user inboxes or ingests them using mail listeners.
- Creates a phishing incident within Cortex XSOAR associated with the email.
- Extracts and enriches all indicators from email attachments. 
- Analyzes files and provides reputation using your sandbox and threat intelligence integrations.
- Generates a screenshot of the email and embedded links, and calculates reputation for all indicators involved.
- Runs checks for SSL certificates of URLs, email address breach involvement, domain-squatting and email authenticity using SPF, DKIM and DMARC checks.
- Identifies similar phishing incidents belonging to the same campaign, providing visibility and manual or automatic actions to respond to such incidents.
- Calculates severity for the incident based on the provided initial severity, indicator reputations, email authenticity check, and critical assets if any are involved.
- Remediates the incident by blocking malicious indicators, searching for and deleting malicious emails upon analyst approval.
- Engages with the end user regarding the incident such as notifying them of receipt of email and providing further instructions if an email is found to be malicious.

As part of this pack, you will also get out-of-the-box phishing incident views, a full layout and automation scripts. All of these are easily customizable to suit the needs of your organization.

_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/playbooks/phishing---generic-v3)._

_If you're new to our Phishing Content Pack, check out our [Setting Up a Phishing Incident in Cortex XSOAR](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-tutorials/tutorials/phishing-use-case.html) tutorial._

![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/13bc88b052c5039775cd0f569259e7fd0e1b7dea/Packs/Phishing/doc_files/Phishing_-_Generic_v3.png)
