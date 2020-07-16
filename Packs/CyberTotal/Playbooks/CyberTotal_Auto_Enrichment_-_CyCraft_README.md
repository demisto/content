This playbook automatically enriches indicators (including IPs, URLs, domains; MD5, SHA-1, and SHA-256 file hashes). Playbook input: the indicators you want to enrich.  Playbook output: detection engine results, positive detections, detection ratios; as well as severity, confidence, and threat scores.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CyberTotal

### Scripts
* Exists

### Commands
* domain
* url
* ip
* file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The input domain will be searched automatically on CyberTotal to retrieve reputation data. | Domain.Name | Optional |
| IP | The input IP will be searched automatically on CyberTotal and to retrieve reputation data. | IP.Address | Optional |
| URL | The input URL will be searched automatically on CyberTotal to retrieve reputation data. | URL.Data | Optional |
| MD5 | The input MD5 will be searched automatically on CyberTotal to retrieve reputation data. | File.MD5 | Optional |
| SHA1 | The input SHA1 will be searched automatically on CyberTotal to retrieve reputation data. | File.SHA1 | Optional |
| SHA256 | The input SHA256 will be searched automatically on CyberTotal to retrieve reputation data. | File.SHA256 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CyberTotal Auto Enrichment - CyCraft](https://github.com/demisto/content/raw/CyberTotal/Packs/CyberTotal/doc_files/CyberTotalAutoEnrichment.png)
