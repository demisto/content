This playbook should be run as a job. The playbook runs on domain indicators and performs various checks to decide if they should be sinkholed.

If a domain is related to a campaign or a threat actor, or if it resolves to a malicious IP or has malware-related tags, the playbook will add a new tag to it in order to sinkhole that domain.
The playbook assumes that the user is exporting indicators with the sinkhole tag to an EDL (External Dynamic List) using the Export Generic Indicators Service integration in XSOAR. That EDL should be connected to PAN-OS.

The playbook then ensures a DNS sinkhole is configured in PAN-OS so that communication with those domains will get blocked, and Traffic logs for the systems creating the malicious traffic will be generated, allowing the user to then query the logs in other playbooks using the PAN-OS - Extract IPs From Traffic Logs To Sinkhole playbook.

Note: this playbook has inputs for both the "From context data" tab and for the "From indicators" tab.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* PAN-OS - Configure DNS Sinkhole

### Integrations

This playbook does not use any integrations.

### Scripts

* SearchIndicatorRelationships
* Set
* SetAndHandleEmpty
* GetIndicatorDBotScoreFromCache

### Commands

* enrichIndicators
* appendIndicatorField

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | All domain indicators. In the playbook, the domains will be filtered by those used for malicious communication, and tagged to be sinkholed. | type:Domain | Optional |
| SinkholeTagForEDL | The tag that should be applied to the domain so that it will be exported to the EDL using the Generic Export Indicators Service integration in XSOAR. | to_sinkhole | Required |
| EnrichUnknownDomains | Whether to enrich unknown domains. Enriching domains can be useful to gain additional information regarding reputation for domains from your feed which will help identify domains used in C2 communication, but may consume more API quota from your threat intelligence integrations.<br/>Can be True or False. | False | Optional |
| EnrichSuspiciousDomains | Whether to enrich suspicious domains. Enriching domains can be useful to gain additional information regarding reputation for domains from your feed which will help identify domains used in C2 communication, but may consume more API quota from your threat intelligence integrations.<br/>Can be True or False. | False | Optional |
| EDLName | Used when configuring the DNS sinkhole for the first time - the name of the External Dynamic List exported from XSOAR and configured in PAN-OS. The EDL should contain the domains to sinkhole. It is used by the security profile to check if traffic for any of these domains is being sent through the firewall.<br/><br/>Note: using External Dynamic Lists \(EDLs\) in PAN-OS requires a "DNS Security" subscription. |  | Optional |
| PrimaryInternalDNSServerIP | Required in order to configure the DNS sinkhole in PAN OS. The IP of the primary internal DNS server. Used to find a policy that matches the malicious DNS queries that go out from the internal DNS server to the firewall. The idea is to find a policy that allows DNS traffic in order to sinkhole that traffic when used for resolving malicious domains found in our signature source. |  | Optional |
| SecondaryInternalDNSServerIP | Optional. If there is a secondary DNS server configured in the network, this input will be required for the DNS sinkhole configuration in PAN-OS.<br/>The IP of the secondary internal DNS server. Used to find a policy that matches the malicious DNS queries that go out from the internal DNS server to the firewall. The idea is to find a policy that allows DNS traffic in order to sinkhole that traffic when used for resolving malicious domains found in our signature source. |  | Optional |
| PublicDNSServerIP | Required in order to configure the DNS sinkhole in PAN OS. The IP of the public DNS server that the organization is using to resolve external domains. This is needed to find the rule that allows DNS requests so that malicious ones can be sinkholed by attaching a security profile to that rule.<br/><br/>If there is currently no rule to allow DNS traffic from the internal DNS server to the internet, the user will be prompted to approve the creation of a new rule that allows DNS traffic from the internal DNS server/s to the IP specified in this input's value. | 8.8.8.8 | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![PAN-OS - Job - Add Malicious Domains To Sinkhole](../doc_files/PAN-OS_-_Job_-_Add_Malicious_Domains_To_Sinkhole.png)
