The script blocks a list of domain FQDNs in supported integrations. Safe to re-run: domains that are already blocked are reported as `Unchanged`.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domain_list | List of domain FQDNs to block. Wildcard entries \(e.g. \*.evil.com\) are not supported and are skipped. |
| rule_name | The name of the rule which will be created in the relevant products. Default: `Cortex - Block Domain`. |
| log_forwarding_name | Panorama log forwarding object name. Indicate what type of Log Forwarding setting will be specified in the PAN-OS custom rules. |
| address_group | Address Group name used to hold the blocked domain objects. Default: `Blocked Domains - Cortex`. |
| auto_commit | Whether to commit the new rule and push to the device group at the end of the run. Default: `true`. |
| tag | The designated tag name for the domain FQDN object. Applied to every object the script creates. Default: `cortex-blocked-domains`. |
| brands | Which integration brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select provide a comma-separated list. Default: `Panorama`. |
| verbose | Whether to retrieve a human-readable entry for every command or only the final result. True retrieves a human-readable entry for every command. False retrieves a human-readable entry only for the final result. Default: `false`. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BlockDomainResults.Domain | The domain FQDN that was processed. | String |
| BlockDomainResults.Brand | The brand \(integration\) used to block the domain. | String |
| BlockDomainResults.Instance | The integration instance used to block the domain. | String |
| BlockDomainResults.Status | The lifecycle status of the action. One of Done, Pending, Skipped, Failed. | String |
| BlockDomainResults.Result | The result of the action. Success or Failed. | String |
| BlockDomainResults.Action | The effect the run had on the target object. One of Created, Modified, Unchanged. | String |
| BlockDomainResults.RuleName | The name of the rule used for this integration. Empty if no rule was used. | String |
| BlockDomainResults.Message | A message concerning the result of the action. | String |
