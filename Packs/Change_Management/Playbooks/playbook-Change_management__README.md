If you are using Pan-os/panorama firewall and Jira as a ticketing system this playbook will be a perfect match for your change management for FW process.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* ServiceNow Change Management
* Jira Change Management

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TicketSummary | Provide a summery for your firewall change request. | incident.details | Optional |
| SecurityTeamEmail | The email of the security team that approves the FW requests. |  | Optional |
| log_type | Log type to query. Can be: traffic, threat, wildfire, url or data-filtering. | traffic | Optional |
| query | The query string by which to match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs. |  | Optional |
| Query_logs | By providing the value "Yes" to this input the playbook "Panorama Query Logs" will be activated. | Yes | Optional |
| addr-src | The source address for the change request. | incident.sourceips | Optional |
| addr-dst | The destination address for the change request. | incident.destinationips | Optional |
| port-dst | The destination ports for the change request. | incident.dstports | Optional |
| zone-src | The relevant firewall source zone for the change request. | incident.sourcenetworks | Optional |
| zone-dst | The relevant firewall destination zone for the change request. | incident.destinationnetworks | Optional |
| Action | The action for the change request \(such as: allow, drop, deny\) | incident.policyactions | Optional |
| Protocol | The relevant IP protocol for the change request. | incident.protocol | Optional |
| Log_forwarding | Log forwarding profile. |  | Optional |
| Profile_setting | A profile setting group. |  | Optional |
| Service | A comma-separated list of service object names for the rule. | incident.protocolnames | Optional |
| Application | A comma-separated list of application object names for the rule to create. |  | Optional |
| Target | Target number of the firewall. Use only on a Panorama instance. |  | Optional |
| Vsys | Target vsys of the firewall. Use only on a Panorama instance. |  | Optional |
| Rulename | Name of the rule to create. |  | Optional |
| Rule_position | Pre rule or Post rule \(Panorama instances\).<br/>Possible options:<br/>- post-rulebase<br/>- pre-rulebase |  | Optional |
| Description | Set the description of the ticket. |  | Optional |
| Time_generated | The time the log was generated from the timestamp and prior to it. For example: "2019/08/11 01:10:44". |  | Optional |
| TestConfigurations | By providing YES to this input the requested FW rule will be tested in your test environment.  |  | Optional |
| TestInstance | The instance name of the FW in DEV environment for testing the new rule. |  | Optional |
| Closing_status_approved | The closing status in Jira is changing by the  project templates, please provide the relevant closing status if the issue was approved. |  | Optional |
| Closing_status_rejected | The closing status in Jira is changing by the  project templates, please provide the relevant closing status if the issue was rejected. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Change management](../doc_files/Change_management.png)