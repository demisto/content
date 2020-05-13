# Metadata
##### Pack Name
Phishing

##### Pack Description
A pack used for the complete investigation of potential phishing incidents. It can retrieve emails from user inboxes, extract and analyze attachments, authenticate the email using SPF, DKIM and DMARC checks, provide reputation for links and email adresses involved, and contain and remediate the incident by blocking malicious indicators found in the process with analyst approval.

---
# Documentation
##### Triggers
The investigation is triggered by an email sent or forwarded to a designated "phishing inbox". A mail listener integration that listens to that mailbox, will use every received email to create a phishing incident in Cortex XSOAR.
It is best practice that the email received in that inbox is an email **containing** the potential phishing email as a file attachment.

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

##### Source Integrations
WOP

# Main Playbook Stages and Capabilities
WOP

---


# Visualization

