## VirusTotal - Premium API - V3
Analyze retro hunts, read live hunt notification,s and download files from VirusTotal.
The premium API is a component of VirusTotal's [advanced services for professionals](https://www.virustotal.com/gui/services-overview).

## Authorization:
Your API key can be found in your VirusTotal account user menu.
Your API key carries all your privileges, so keep it secure and don't share it with anyone.

### Cortex XSOAR version 6.0.0 and below:
Fill anything in the "Username" fill box. Use you API key in the password fill box.

## Fetch Incidents:
The generated incidents are notifications from vt-private-livehunt-notifications-list.
Use "Tag" to filter which notification tag to get. 
For example, using the "malicious_executables" will fetch only notifications caught by malicious_executables ruleset.
The scope of the rule-set should be narrowed to catch only indicators that you want to analyze by a playbook.
Defining a broad rule-set will cause the integration to create multiple redundant incidents.  