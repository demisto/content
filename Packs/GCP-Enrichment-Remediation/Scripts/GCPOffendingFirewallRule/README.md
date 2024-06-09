Determine potential offending firewall rules in GCP based on port, protocol and possibly target tags (network tags).

Considerations:

- At this time this automation only find potential offending rules and not necessarily the rule that is matching traffic.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Used In

---
This script is used in the following playbooks and scripts.

- GCP - Enrichment - EXPANDR-3608
- GCP - Enrichment

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| project_id | The project to look up firewall rules in.  The project ID instead of the project number.  No need to supply \`projects/\` before the ID \(i.e., use \`project-name\` instead of \`projects/project-name\` or \`projects/111111111111\`\). |
| network_url | The url of the network objects to lookup firewall rules in.  This will be the url of the network and not just the name \(i.e. https://www.googleapis.com/compute/v1/projects/&lt;project_name&gt;/global/networks/&lt;network_name&gt;\). |
| port | Port to match traffic on for firewall rules. |
| protocol | Protocol to match traffic on for firewall rules. |
| network_tags | Network tags on GCP VM instance to match rules based on target tag \(optional\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GCPOffendingFirewallRule | One or more potential offending firewall rules in GCP based on port, protocol and possibly target tags \(network tags\). | Unknown |
