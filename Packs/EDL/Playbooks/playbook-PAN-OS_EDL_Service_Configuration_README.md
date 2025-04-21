This single-run playbook enables Cortex XSOAR built-in External Dynamic List (EDL) as a service for the system indicators, and configures PAN-OS EDL objects and the respective firewall policy rules.
The EDLs will continuously update for each indicator that matches the query syntax inputted in the playbook
(in order to validate to which indicators the query applies, you need to enter the query syntax from the indicator tab at the top of the playbook inputs window as well).
If both the IP and URL indicator types exist in the query, it sorts the indicators into two EDLs, IP and URL. If only one indicator type exists in the query, only one EDL is created.
The playbook then creates EDL objects directed to the indicator lists and firewall policy rules in PAN-OS.
- It is recommended to configure a dedicated EDL Service instance for the usage of this playbook.
- In case it is needed to edit or update the EDL query after this playbook runs, use the ***panorama-edit-edl*** command and panorama integration to update the URL containing the indicator query syntax.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS - Create Or Edit EDL Rule
* PAN-OS Commit Configuration

### Integrations
* Palo Alto Networks PAN-OS
* Palo Alto Networks PAN-OS EDL Service
### Scripts
* AreValuesEqual

### Commands
* panorama-list-rules
* panorama-get-edl
* panorama-create-edl

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ip-edl-object-name | Set a name for the EDL object that will be configured on pan\-os. This value is used to set the rule name as well. | Demisto Remediation - IP EDL | Optional |
| url-edl-object-name | Set a name for the EDL object that will be configured on pan\-os. This value is used to set the rule name as well. | Demisto Remediation - URL EDL | Optional |
| EDLServiceURL | The EDL service provides serval access methods to the EDL instance. By default, it uses a unique port, configured in the EDL Service integration, and an HTTP session. It is possible to either configure a certificate for the default option or to access the EDL by instance name, which is HTTPS by default.<br/>Please refer to the EDL Service integration tip for more information. | EDLServiceURL input examples:<br/>- if not configured with a certificate \-  http://cortex\-xsoar\_address<br/>- if configured with a certificate \- https://cortex\-xsoar\_address<br/>\* Depending on the access method to the EDL, the full URL of the EDL is constructed from this input, and by InstanceName OR by InstancePort and IndicatorQuery. The playbook identifies which access method is used from the playbook inputs and crafts the correct URL address.<br/>Full constructed URL examples:<br/>- by port - $\{EDLServiceURL\}:$\{InstancePort\}/$\{IndicatorQuery\}<br/>- By Instance Name - $\{EDLServiceURL\}:$\{InstanceName\}/$\{IndicatorQuery\} | Optional |
| InstanceName | Name of the instance as configured in EDL Service integration. Only needed when accessing EDL Service by instance name. Refer to the EDL Service integration tip for more information. | | Optional |
| InstancePort | Instance name port as configured in EDL Service integration. Only needed when accessing EDL Service by URL and Port. Refer to the EDL Service integration tip for more information. | | Optional |
| IndicatorQuery | The query to run to create the EDL. When no query is entered, EDLs will contain all IP and URL indicators. The query should be inserted in the indicators tab\(top of this input window\) so the playbook can query and validate the indicator types and create only the relevant EDL objects and rules. | | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically.<br/>Yes \- Commit automatically.<br/>No \- Commit manually. | No | Optional |
| RulePosition | The position of the rule in the ruleset. Valid values are:<br/> \* top<br/>  \* bottom<br/>  \* before<br/>  \* after<br/>The default position is 'top'. | top | Optional |
| ActionType | The action that will be defined in the rule: allow/deny/drop | drop | Optional |
| inbound-or-outbound-rule | Determines if the rule is inbound or outbound. | outbound | Optional |
| pre-post-rulebase | Either pre\-rulebase or post\-rulebase, according to the rule structure. | pre-rulebase | Optional |
| DeviceGroup | The device group to work on. Exists only in panorama\! |  | Optional |
| LogForwarding | Log Forwarding object name. |  | Optional |
| relative-rule-name | If the rule\-position that is chosen is before or after, specify the rule name to which it is related. |  | Optional |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.EDL.Name | Name of theEDL. | unknown |

## Playbook Image
---
![PAN-OS EDL Service Configuration](../doc_files/PAN-OS_EDL_Service_Configuration.png)
