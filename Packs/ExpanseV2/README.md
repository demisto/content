The Expanse Content Pack for Cortex XSOAR provides full coverage of the Expander and Behavior product capabilities from Expanse to allow SOCs to automate the defense of their Company's attack surface. The Integrations included in the Pack enable fetching and mirroring of Expanse Issues into Cortex XSOAR Incidents, and ingestion of Indicators (IPs, Domains and Certificates) referring to the corporate Network Perimeter as discovered by Expanse.

Through a powerful set of Playbooks, analysts can correlate the discovered information with data provided from internal security systems (such as Palo Alto Networks Cortex Data Lake, Prisma Cloud and Panorama, Active Directory, Splunk SIEM) to help pinpoint the right owners of assets and automate remediation

some additional clarifications:
- my understanding is that Behavior is a feed of malicious/suspicious connections detected from/to customer network. It's not the classical Threat Intelligence feed that provides lists of suspicious IPs/URLs/domain. I think Behavior can be considered more as a consumer of Threat Intelligence than a producer (and it would be interesting to have an integration with XSOAR TIM where TIM can feed indicators into Behavior for detection).
- Andrew already integrated the Behavior API in the first version of Expanse XSOAR Pack and Francesco reimplemented a variation of the same pattern in the new Content Pack where Behavior flows are used to enrich Expander Incidents on XSOAR.
- The new Expanse Content Pack contains 2 integrations and one of them is a feed integration, that is used to stream the assets detected by Expander into XSOAR TIM for charting and enrichment. The Content Pack contains the indicator fields to expose all the details detected by Expander in the indicator layouts:
##### What does this pack do?
- Provides an integration named **ExpanseV2** (for Expanse Expander and Behavior) that allows XSOAR to collect Expanse Issues and bi-directionally mirror them. Several commands are available to search, tag, update Issues and Assets in Expanse.
- Provides a feed integration named **FeedExpanse** compatible with the Cortex XSOAR Threat Intel Management functionality to retrieve and store discovered assets (IPs, IP Ranges, Domains, Certificates) in Cortex XSOAR for analysis and correlation.
- Provides an **Expanse Issue** Incident Type with dedicated fields and layouts.
- Provides a rich set of Playbooks to Handle the investigation and resolution of Expanse Issues.
- Provides Dashboards about the Network perimeter as discovered by Expanse and the status of Expanse Issues.

![Handle Expanse Incident](https://raw.githubusercontent.com/demisto/content/e5ff1d909722f845d1326b7cdb3748a58b2d5c4c/Packs/ExpanseV2/Playbooks/playbook-Handle_Expanse_Incident.png)