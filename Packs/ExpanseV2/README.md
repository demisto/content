The Expanse Content Pack for Cortex XSOAR provides full coverage of the Expander and Behavior product capabilities from Expanse to allow SOCs to automate the defense of their Company's attack surface. The Integrations included in the Pack enable fetching and mirroring of Expanse Issues into Cortex XSOAR Incidents, and ingestion of Indicators (IPs, Domains and Certificates) referring to the corporate Network Perimeter as discovered by Expanse.

Through a powerful set of Playbooks, analysts can correlate the discovered information with data provided from internal security systems (such as Palo Alto Networks Cortex Data Lake, Prisma Cloud and Panorama, Active Directory, Splunk SIEM) to help pinpoint the right owners of assets and automate remediation

##### What does this pack do?
- Provides an integration named **ExpanseV2** (for Expanse Expander and Behavior) that allows XSOAR to collect Expanse Issues and bi-directionally mirror them. Several commands are available to search, tag, update Issues and Assets in Expanse.
- Provides a feed integration named **FeedExpanse** compatible with the Cortex XSOAR Threat Intel Management functionality to retrieve and store discovered assets (IPs, IP Ranges, Domains, Certificates) in Cortex XSOAR for analysis and correlation.
- Provides an **Expanse Issue** Incident Type with dedicated fields and layouts.
- Provides a rich set of Playbooks to Handle the investigation and resolution of Expanse Issues.
- Provides Dashboards about the Network perimeter as discovered by Expanse and the status of Expanse Issues.

![Handle Expanse Incident](https://raw.githubusercontent.com/demisto/content/e5ff1d909722f845d1326b7cdb3748a58b2d5c4c/Packs/ExpanseV2/Playbooks/playbook-Handle_Expanse_Incident.png)