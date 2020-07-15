This playbook is used to automatically enrich indicators(ip, url, domain, md5, sha1, sha256). These indicators should be set as input of this playbook. The output of this playbook includes detection engines, positive detections, detection ratio, severity, confidence and threat.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CyberTotal

### Scripts
* Exists

### Commands
* url
* file
* domain
* ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The input domain will be searched automatically on CyberTotal and get reputation. | Domain.Name | Optional |
| IP | The input IP will be searched automatically on CyberTotal and get reputation. | IP.Address | Optional |
| URL | The input URL will be searched automatically on CyberTotal and get reputation. | URL.Data | Optional |
| MD5 | The input MD5 will be searched automatically on CyberTotal and get reputation. | File.MD5 | Optional |
| SHA1 | The input SHA1 will be searched automatically on CyberTotal and get reputation. | File.SHA1 | Optional |
| SHA256 | The input SHA256 will be searched automatically on CyberTotal and get reputation. | File.SHA256 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CyberTotal Auto Enrichment - CyCraft](https://github.com/demisto/content/raw/CyberTotal/Packs/CyberTotal/doc_files/CyberTotalAutoEnrichment.png)
