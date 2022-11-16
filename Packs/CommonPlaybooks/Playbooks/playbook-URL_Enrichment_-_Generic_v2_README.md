Enrich URLs using one or more integrations.

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
* rasterize

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URLs to enrich. | URL.Data | Optional |
| Rasterize | Should the system take safe screenshots of input URLs? | True | Optional |
| VerifyURL | Should the system perform SSL certificate verification on the URLs? | False | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | The URL object. | uknown |
| URL.Data | The enriched URL. | string |
| DBotScore | The DBotScore object. | unknown |
| URL.Malicious | Whether the detected URL was malicious. | unknown |
| URL.Vendor | Vendor that labeled the URL as malicious. | string |
| URL.Description | Additional information for the URL. | string |

## Playbook Image
---
![URL Enrichment - Generic v2](../doc_files/URL_Enrichment_-_Generic_v2.png)