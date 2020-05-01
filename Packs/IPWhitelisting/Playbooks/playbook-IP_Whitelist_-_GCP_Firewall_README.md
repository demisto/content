Set a list of IP addresses in GCP firewall.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin
* Google Cloud Compute

### Scripts
* CompareLists

### Commands
* closeInvestigation
* gcp-compute-patch-firewall
* gcp-compute-get-firewall
* setIndicator
* removeIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
|  | Indicators to trigger the playbook |  |  | Optional |
| IP | IP addresses to whitelist in GCP Firewall |  |  | Required |
| GCPFirewallName | Name of the GCP Firewall where the playbook should set the IPs |  |  | Required |
| IndicatorTagName | Name of the Indicator Tag to apply to any IPs whitelisted by this playbook. | GCP_IP_Whitelist |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

![Playbook Image](https://raw.githubusercontent.com/demisto/content/c20427ed8dde64841a1249b5d7c44e8773df2b72/Packs/IPWhitelisting/doc_files/IP_Whitelist_-_GCP_Firewall.png)
