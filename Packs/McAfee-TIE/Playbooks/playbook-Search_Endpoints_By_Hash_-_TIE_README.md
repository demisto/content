Hunts for sightings of MD5 hash, SHA1  hash and/or SHA256 hashes on endpoints, using McAfee TIE (requires ePO as well).

Input:
* Hash (default, takes all deferent hashes from context)

Output:
* All agents that files with "Hash" has been executed on (TIE)
* Enrich Agents info from ePO

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* McAfee Threat Intelligence Exchange
* McAfee ePO v2

### Scripts
* EPOFindSystem

### Commands
* tie-file-references
* epo-find-system

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| Hash | The hash to hunt. Can be, "MD5", "SHA1", or "SHA256". The default is set to all hashes. | ${.=val.File.map(function(f) {return [f.MD5, f.SHA1, f.SHA256];}).reduce(function(a, b){return a.concat(b);}, []).filter(function (val1) {return val1;})} |Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname | The hostname. | string |
| Endpoint | The endpoint. | unknown |

## Playbook Image
---
![Search_Endpoints_By_Hash_TIE](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Search_Endpoints_By_Hash_TIE.png)
