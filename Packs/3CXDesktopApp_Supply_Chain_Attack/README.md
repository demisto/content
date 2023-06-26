This pack is part of the [Rapid Breach Response](https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/) pack.

#### Executive Summary 
On March 29, 2023, CrowdStrike [released a blog](https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/) discussing a supply chain attack involving a software-based phone application called [3CXDesktopApp](https://www.3cx.com/). 

As of March 30, the 3CXDesktopApp installer hosted on the developer’s website will install the application with two malicious libraries included. The malicious libraries will ultimately run shellcode to load a backdoor on the system that allows actors to install additional malware on the victim machine.

Between March 9-30, 2023, we observed activity at 127 Cortex XDR customers that involved the 3CXDesktopApp process attempting to run shellcode, which was blocked by the XDR Agent’s In-process Shellcode Protection Module. Due to blocking the shellcode, we were unable to obtain the secondary payload used in this attack, so we cannot determine its capabilities or any post-exploitation activities carried out by the threat actor.

#### Pack Content

The pack contains a playbook named **3CXDesktopApp Supply Chain Attack** which handles 3CXDesktopApp Supply Chain Attack investigation and response.

#### Playbook Flow

**The playbook includes the following tasks:**

**Hunting:**
- Cortex XDR
    - XQL hunting queries
- Advanced SIEM queries
    - Splunk
    - QRadar
    - Elasticsearch
    - Azure Log Analytics
- Indicators hunting

**References:**

[Threat Brief: 3CXDesktopApp Supply Chain Attack](https://unit42.paloaltonetworks.com/3cxdesktopapp-supply-chain-attack/)

[CrowdStrike Falcon Platform Detects and Prevents Active Intrusion Campaign Targeting 3CXDesktopApp Customers](https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/)
