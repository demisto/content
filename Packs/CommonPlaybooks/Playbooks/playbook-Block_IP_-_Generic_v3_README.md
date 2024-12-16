This playbook blocks malicious IP addresses using all integrations that are enabled. The direction of the traffic that will be blocked is determined by the XSOAR user (and set by default to outgoing)
Note the following:
-  some of those integrations require specific parameters to run, which are based on the playbook inputs. Also, certain integrations use FW rules or appended network objects.
- Note that the appended network objects should be specified in blocking rules inside the system later on. 


Supported integrations for this playbook [Network security products such as FW/WAF/IPs/etc.]: 

* Check Point Firewall
* Palo Alto Networks PAN-OS
* Zscaler
* FortiGate
* Aria Packet Intelligence
* Cisco Firepower 
* Cisco Secure Cloud Analytics
* Cisco ASA
* Akamai WAF
* F5 SilverLine
* ThreatX
* Signal Sciences WAF
* Sophos Firewall



## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Prisma SASE - Block IP
* Cisco FirePower- Append network group object
* PAN-OS - Block IP - Static Address Group
* Checkpoint - Block IP - Custom Block Rule
* PAN-OS - Block IP - Custom Block Rule
* Sophos Firewall - Block IP
* PAN-OS DAG Configuration

### Integrations

* F5Silverline
* Zscaler

### Scripts

* IsIntegrationAvailable
* IsIPInRanges
* SetAndHandleEmpty

### Commands

* zscaler-blacklist-ip
* aria-block-dest-subnet
* akamai-add-elements-to-network-list
* threatx-block-ip
* threatx-blacklist-ip
* fortigate-ban-ip
* sigsci-blacklist-add-ip
* sw-block-domain-or-ip
* appendIndicatorField
* enrichIndicators
* createNewIndicator
* f5-silverline-ip-object-add
* cisco-asa-create-rule

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | An array of malicious IPs to block. Enter a comma-separated list of IPs \(i.e.: 1.1.1.1,2.2.2.2\). |  | Optional |
| CustomBlockRule | This input determines whether Palo Alto Networks Panorama or Firewall Custom Block Rules are used.<br/>Specify "True" to create new Custom Block Rules \(2 FW rules inside the PAN-OS device\). <br/>For "False" - no rules will be created. | True | Optional |
| LogForwarding | Panorama log forwarding object name. Indicate what type of Log Forwarding setting will be specified in the PAN-OS custom rules. |  | Optional |
| AutoCommit | This input determines whether to commit the configuration automatically on PAN-OS devices and other FWs. <br/>Yes - Commit automatically.<br/>No - Commit manually. | No | Optional |
| StaticAddressGroup | This input determines whether Palo Alto Networks Panorama or Firewall Static Address Groups are used.<br/>Specify the Static Address Group name for IPs list handling. |  | Optional |
| Tag | Insert a tag name with which indicators will get tagged. This tag can be used later in the External Dynamic Lists integration by using the tag for filtering IPs in the indicator query. |  | Optional |
| DAG | This input determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used.<br/>Determine the Dynamic Address Group tag for IPs list handling. |  | Optional |
| UserVerification | Possible values: True/False.  Default: True.<br/>Whether to provide user verification for blocking those IPs. <br/><br/>False - No prompt will be displayed to the user.<br/>True - The server will ask the user for blocking verification and will display the blocking list. | True | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The comma-separated list should be provided in CIDR notation. For example, a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). | lists.PrivateIPs | Optional |
| SiteName | Signal Sciences WAF - Enter the site name for the integration to be applied. The site name can be found in your instance console. |  | Optional |
| AkamaiNetworkListID | Akamai's WAF network list ID, which is mandatory to be mentioned for the integration. The chosen IPs will be added to this ID. |  | Optional |
| InputEnrichment | Possible values: True/False . Default: False<br/>Enrich the input IP address/es with reputation commands. | False | Optional |
| RuleName | The rule name/description that will be presented on the created rule in certain integrations \(if there is a need\).<br/>The supported integrations: PAN-OS, CheckPoint.<br/><br/>Default input- "XSOAR - Block IP playbook - $\{incident.id\}" | XSOAR - Block IP playbook - ${incident.id} | Optional |
| RuleDirection | Determine if a newly created rule should be with the network direction of outbound or inbound blocked traffic.<br/>Possible values: inbound or outbound<br/>Default: outbound | outbound | Optional |
| DAGName | This input determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used.<br/>Determine the Dynamic Address Group name for IPs list handling. |  | Optional |
| Folder | For prisma SASE usage - Specify the scope for a newly created security rule to be applied.<br/>Remember, this input will only be used when there is no input to the CategoryName.<br/>Default: Shared | Shared | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Aria.BlockDestSubnet.Rule | The rule name/ID which was created in the system for this playbook. | unknown |
| Aria.BlockDestSubnet.Status | The status of the command that created the rule above. | unknown |
| Stealthwatch.IP.id | The ID of the object created in Cisco Secure Cloud Analytics. | unknown |
| Stealthwatch.IP.identifier | The value of the object created in Cisco Secure Cloud Analytics. | unknown |
| CiscoASA.Rules.ID | The rule ID that was created in Cisco ASA for this playbook. | unknown |
| CiscoASA.Rules.Source | The rule's source object that was set in the associated rule. | unknown |
| CiscoASA.Rules.Dest | The rule's destination object that was set in the associated rule. | unknown |
| CiscoASA.Rules.IsActive | The rule's state that was set in the associated rule. | unknown |
| SigSciences.Corp.Site.Blacklist.ID | Signal Sciences created rule ID. | unknown |
| SigSciences.Corp.Site.Blacklist.Source | Signal Sciences blocked address in a dedicated rule. | unknown |
| SigSciences.Corp.Site.Blacklist.CreatedBy | Signal Sciences - the blocking rule's creator name. | unknown |
| PrismaSase | The root context key for Prisma SASE integration output. | unknown |
| PrismaSase.AddressGroup | The Prisma Access Address group object. | unknown |
| PrismaSase.SecurityRule | Created security rule. | unknown |
| PrismaSase.SecurityRule.profile_setting | The Security rule group object in the rule. | unknown |
| PrismaSase.CandidateConfig | Configuration job object. | unknown |
| PrismaSase.Address | Created address object. | unknown |

## Playbook Image

---

![Block IP - Generic v3](../doc_files/Block_IP_-_Generic_v3.png)
