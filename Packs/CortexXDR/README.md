Cortex XDR is a detection and response app that natively integrates network, endpoint and cloud data to stop sophisticated attacks.
Responding and managing these attacks requires security teams to reconcile data from multiple sources. Valuable time is lost shuttling between screens and executing repeatable tasks while an attack continues to manifest.
This Cortex XDR content pack contains the ‘Palo Alto Networks Cortex XDR - Investigation and Response’ integration, that enable direct execution of Cortex XDR actions within Cortex XSOAR, ‘Cortex XDR Incident Handling v2` playbook, that enables bidirectional incident updates between Cortex XDR and Cortex XSOAR, and the Cortex XDR - Malware Investigation’ and ‘Cortex XDR - Port Scan - Adjusted’ sub-playbooks. The pack also contains the corresponding custom Cortex XDR incident fields, views and layouts to facilitate analyst investigation.  

##### What does this pack do?
The playbooks included in this pack help you save time and keep your incidents in sync. They also help automate repetitive tasks associated with Cortex XDR incidents:
- Syncs and updates Cortex XDR incidents
- Trigger a sub-playbook to handle each alert by type
- Extract and enrich all relevant indicators from the source alert.
- Hunt for related IOCs
- Calculate the severity of the incident
- Interact with the analyst to choose a remediation path or close the incident as a false positive based on the gathered information and incident severity
- Remediate the incident by blocking malicious indicators and isolating infected endpoints

As part of this pack, you will also get out-of-the-box Cortex XDR incident type views,  with incident fields and a full layout. All of these are easily customizable to suit the needs of your organization.

_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/playbooks/cortex-xdr-incident-handling-v2)_

![Cortex XDR incident handling v2](https://github.com/demisto/content/raw/3fadebe9e16eb7c9fc28ce3bb600319ec875e3b5/Packs/CortexXDR/doc_files/Cortex_XDR_incident_handling_v2.png)