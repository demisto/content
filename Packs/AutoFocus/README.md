Use AutoFocus to export threat intelligence data produced by AutoFocus and connected services to provide actionable data for the Palo Alto Networks firewall as well as third party TIP and SIEM solutions. In addition to using the data for investigative purposes though AutoFocus, this content pack allows you to use it for detection and prevention to better safeguard your network from malicious activity.



## What does this pack do?
- Query samples / sessions.
- Get sample analysis.
- Get session details.
- Get tag details.
- Get top tags.



This content pack includes:
- Integrations:
   - **AutoFocus Daily Feed**: Fetch new, daily additions to the list created by the AutoFocus feed.
   - **AutoFocus Feed**: Fetch a list from AutoFocus which includes IP addresses, domains, URLs, and hash indicators 
   - **Palo Alto AutoFocus**: (Deprecated)
Use the Palo Alto Networks AutoFocus v2 integration instead. 
   - **Palo Alto Networks AutoFocus v2**:
Distinguish the most important threats from everyday commodity attacks.

- Playbooks:
  - **Autofocus Query Samples, Sessions and Tags**
Query the PANW threat intelligence Autofocus system. The playbook accepts indicators such as IPs, hashes, domains to run basic queries or mode advanced queries that can leverage several query parameters. 
  - **AutoFocusPolling**: A sub-playbook to query PANW Autofocus Threat intelligence system. This sub-playbook is the same as the generic polling sub-playbook except that it provides outputs in the playbook. 

For information about AutoFocus feeds, see https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html
