Enrich indicators by providing intelligence and more associated indicators based on confirmed reporting in Digital Shadows SearchLight.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Digital Shadows - CVE_IoC Assessment & Enrichment
* Digital Shadows - URL_IoC Assessment & Enrichment
* Digital Shadows - SHA1_IoC Assessment & Enrichment
* Digital Shadows - MD5_IoC Assessment & Enrichment
* Digital Shadows - IP_IoC Assessment & Enrichment
* Digital Shadows - SHA256_IoC Assessment & Enrichment
* Digital Shadows - Domain_IoC Assessment & Enrichment

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
| IoC_IP | An IP address for assessment and enrichment | IP.Address | Optional |
| IoC_CVE | A CVE for assessment and enrichment | CVE.ID | Optional |
| IoC_Domain | A domain for assessment and enrichment | Domain.Name | Optional |
| IoC_URL | A URL for assessment and enrichment | URL.Data | Optional |
| IoC_MD5 | A MD5 hash for assessment and enrichment | File.MD5 | Optional |
| IoC_SHA256 | A SHA256 hash for assessment and enrichment | File.SHA256 | Optional |
| IoC_SHA1 | A SHA1 hash for assessment and enrichment | File.SHA1 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | Indicator Value | string |
| DBotScore.Type | Indicator Type | string |