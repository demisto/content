Initiates a Signature Search in Palo Alto Networks threat Vault.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Threat_Vault

### Scripts
This playbook does not use any scripts.

### Commands
* threatvault-antivirus-signature-search
* threatvault-dns-signature-search
* threatvault-antispyware-signature-search
* threatvault-signature-search-results

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| signature_name | Signature name to search. |  | Optional |
| domain_name | Domain name to search. |  | Optional |
| vendor | Vendor name to search. |  | Optional |
| cve | CVE name to search. |  | Optional |
| from | From which signature to return results\(used for paging\). Default is 0. | 0 | Optional |
| to | To which signature to return results. Default is from plus 10. | 10 | Optional |
| search_type | Search type. ips for antispyware, dns for DNS and panav for antivirus. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ThreatVault.Search.search_request_id | Search request ID. | String |
| ThreatVault.Search.status | Search status. | String |
| ThreatVault.Search.page_count | How many results returned in this specific search. | Number |
| ThreatVault.Search.total_count | How many results are available for this specific search. | Number |
| ThreatVault.Search.search_type | Search type. can be wither ips, dns or panav. | String |
| ThreatVault.Search.signatures | A list of all the found signatures for this specific search. | Unknown |
