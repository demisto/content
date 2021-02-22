When an exfiltration incident is detected, for example by your endpoint protection service, this pack can help you investigate and remediate the incident by retrieving data about the source and destination of the exfiltration alert, assessing the severity of the incident and allowing remediation of the incident with host isolation, breach notification and blocking of malicious destination indicators.

## What does this pack do?

- Extracts indicators from the alert data.
- Retrieves the suspected exfiltration malware.
- Calculates the incident severity and determines whether the behavior is malicious or not.
- Isolates the offensive host, and blocks the exfiltration destination and the exfiltration malware.
- If an active instance of one of the email communication integrations exists, notifies the user manager of the breach.
- Guides the user to create a new breach incident according to the breach type: GDPR/HIPAA/US/Organization-specific breach notification.

The pack includes an out-of-the-box playbook and an incident layout that displays all of the information gathered during the investigation and the actions executed by the playbook.  

## How does this pack work?

An active instance of the integration you plan to use for fetching and ingesting exfiltration incidents, for example, Palo Alto Networks Cortex XDR, is required.

The **Data Exfiltration - Generic** playbook runs several sub-playbooks for each of its main functions: data gathering, incident remediation, and email communication. 
Each sub-playbook may have it's own prerequisites. If the prerequisites of a sub-playbook aren't met, the sub-playbook will not run. The **Data Exfiltration - Generic** playbook run will continue and complete regardless of the sub-playbooks.  

### Data Gathering
These sub-playbooks are used to retrieve the exfiltration malware, detonate it, and set the incident severity.
- Retrieve File from Endpoint - Generic V2: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/retrieve-file-from-endpoint---generic-v2)
- Code42 File Download: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/code42-file-download)
- Cortex XDR - Retrieve File Playbook: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/cortex-xdr---retrieve-file-playbook)
- Detonate File - Generic: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/detonate-file---generic)
- Entity Enrichment - Generic v3: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/entity-enrichment---generic-v3)
- Calculate Severity - Generic v2: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/calculate-severity---generic-v2)

### Incident Remediation
These sub-playbooks are used to isolate the offensive host, and block the exfiltration destination and the exfiltration malware.
- Isolate Endpoint - Generic: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/isolate-endpoint---generic)
- Block Indicators - Generic v2: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/block-indicators---generic-v2)
- Block File - Generic v2: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/block-file---generic-v2)

### Email Communication
A sub-playbook is used to get the email address of the offending user's manager:
- Active Directory - Get User Manager Details: [(see the documentation)](https://xsoar.pan.dev/docs/reference/playbooks/active-directory---get-user-manager-details)

The following integrations are used to send the notification email to the offending user's manager.
- EWS Mail Sender - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/ews-mail-sender)
- Mail Sender (New) - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/mail-sender-new)
- Gmail - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/gmail)
- Gmail Single User (Beta) - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/gmail-single-user)
- Microsoft Graph Mail - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail)
- Microsoft Graph Mail Single User - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail-single-user)

![Playbook Image](https://raw.githubusercontent.com/demisto/content/f028abf0392df5d6eecd2926ddc56fc233aee4e9/Packs/Exfiltration/doc_files/Data_Exfiltration_-_Generic.png)
