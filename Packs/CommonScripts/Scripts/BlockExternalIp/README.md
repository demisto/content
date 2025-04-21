The scrip blocks a list of IPs in supported integrations.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ip_list | List of IPs to block. |
| rule_name | The name of the rule which will be created in the relevant products. |
| log_forwarding_name | Panorama log forwarding object name. Indicate what type of Log Forwarding setting will be specified in the PAN-OS custom rules. |
| address_group | This input determines whether PANW Panorama or Firewall or Prisma SASE Address Groups are used. Specify the Address Group name for IPs list handling. |
| auto_commit | Whether to commit the new rule. |
| tag | The designated tag name for the IP. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select provide a comma-separated list. For example: "Palo Alto Networks - Prisma SASE,Panorama,CheckPointFirewall_v2". |
| verbose | Whether to retrieve human readable entry for every command or only the final result. True means to retrieve human readable entry for every command. False means to human readable only for the final result. |


## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BlockExternalIPResults.Message | A message concerning the result of the action. | String |
| BlockExternalIPResults.Result | The result of the action Success or Failed. | String |
| BlockExternalIPResults.Source | The name of the brand that was executed. | String |
| BlockExternalIPResults.created_rule_name | The name of the created rule. | String |
| BlockExternalIPResults.address_group | The address group. | String |
