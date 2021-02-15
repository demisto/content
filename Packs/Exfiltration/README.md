When an exfiltration incident is detected, for example by your endpoint protection service, this pack can help you investigate and remediate the incident by retrieving data about the source and destination of the exfiltration alert, 
assessing the severity of the incident and allowing remediation of the incident with host isolation, breach notification and blocking of malicious destination indicators.

## What does this pack do?

The main features of the **Data Exfiltration - Generic** playbook included in the pack are:
- Extracts indicators from the alert data.
- Retrieves the suspected exfiltration malware.
- Calculates the incident severity and determines whether the behavior is malicious or not.
- Isolates the offensive host, and blocks the exfiltration destination and the exfiltration malware.
- If the relevant integrations exist, notifies the user manager of the breach.
- Creates a new breach incident according to the breach type: GDPR/HIPAA/US/Organization-specific breach notification.

As part of this pack, you will get out-of-the-box playbook, incident fields that are added to all incident types, and a layout to display all of the information gathered and actions executed by the playbook.  

## Integrations
The **Data Exfiltration - Generic** playbook attempts to use the following integrations, however they are optional:

- Fetch incidents integration: the integration you are using to fetch and ingest exfiltration incidents, for example, Palo Alto Networks Cortex XDR.
- Gmail - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/gmail)
- Active Directory Query V2 - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/active-directory-query-v2)
- Gmail Single User (Beta) - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/gmail-single-user)
- Microsoft Graph Mail - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail)
- EWS Mail Sender - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/ews-mail-sender)
- Mail Sender (New) - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/mail-sender-new)
- EWS v2 - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/ews-v2)
- Microsoft Graph Mail Single User - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail-single-user)
- Code42 - [(see the documentation)](https://xsoar.pan.dev/docs/reference/integrations/code42)

![Playbook Image](https://raw.githubusercontent.com/demisto/content/f028abf0392df5d6eecd2926ddc56fc233aee4e9/Packs/Exfiltration/doc_files/Data_Exfiltration_-_Generic.png)
