The script blocks a list of IP addresses in supported integrations.

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
| verbose | Whether to retrieve a human-readable entry for every command or only the final result. True retrieves a human-readable entry for every command. False retrieves a human-readable entry only for the final result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BlockExternalIPResults.Message | A message concerning the result of the action. | String |
| BlockExternalIPResults.Result | The result of the action Success or Failed. | String |
| BlockExternalIPResults.Brand | The name of the brand that was executed. | String |
| BlockExternalIPResults.IP | The IP that was blocked. | String |

## Using commands

| **Brand** | **Command** |
| --- | --- |
| Zscaler | !zscaler-blacklist-ip |
| Cisco ASA | !cisco-asa-create-rule |
| F5Silverline | !f5-silverline-ip-object-add |
| FortiGate | !fortigate-ban-ip |
| Palo Alto Networks - Prisma SASE | prisma-sase-address-object-list |
| Palo Alto Networks - Prisma SASE | prisma-sase-address-object-create |
| Palo Alto Networks - Prisma SASE | prisma-sase-address-group-list |
| Palo Alto Networks - Prisma SASE | prisma-sase-address-group-create |
| Palo Alto Networks - Prisma SASE | prisma-sase-address-group-update |
| Palo Alto Networks - Prisma SASE | prisma-sase-candidate-config-push |
| Palo Alto Networks - Prisma SASE | prisma-sase-security-rule-list |
| Palo Alto Networks - Prisma SASE | prisma-sase-security-rule-create |
| Palo Alto Networks - Prisma SASE | prisma-sase-security-rule-update |
| Palo Alto Networks PAN-OS | pan-os-register-ip-tag |
| Palo Alto Networks PAN-OS | pan-os-edit-address-group |
| Palo Alto Networks PAN-OS | pan-os-create-address-group |
| Palo Alto Networks PAN-OS | pan-os-edit-rule |
| Palo Alto Networks PAN-OS | pan-os-create-rule |
| Palo Alto Networks PAN-OS | pan-os-move-rule |
| Palo Alto Networks PAN-OS | pan-os-list-address-groups |
| Palo Alto Networks PAN-OS | pan-os-list-rules |
| Palo Alto Networks PAN-OS | pan-os-push-to-device-group |
| Palo Alto Networks PAN-OS | pan-os-push-status |
| Palo Alto Networks PAN-OS | pan-os-commit |
| Palo Alto Networks PAN-OS | pan-os-commit-status |
