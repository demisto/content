Enriches URLs using one or more integrations.

URL enrichment includes:
* SSL verification for URLs
* Threat information
* Providing of URL screenshots

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Rasterize

### Scripts
* URLSSLVerification
* Exists

### Commands
* vt-private-get-url-report
* rasterize

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| URL | The URLs to enrich. | Data | URL | Optional |
| Rasterize | Whether the system should take safe screenshots of input URLs. | True | - | Optional |
| VerifyURL | Whether the system should perform SSL certificate verification on the URLs. | False | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | The URL object. | uknown |
| URL.Data | The enriched URL. | string |
| DBotScore | The DBotScore object. | unknown |
| URL.Malicious | Whether the detected URL was malicious. | unknown |
| URL.Vendor | The vendor that labeled the URL as malicious. | string |
| URL.Description | The additional information for the URL. | string |

## Playbook Image
---
![URL_Enrichment_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/URL_Enrichment_Generic_v2.png)
