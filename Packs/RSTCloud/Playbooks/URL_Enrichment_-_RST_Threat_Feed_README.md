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
* RST Cloud - Threat Feed API
* Rasterize

### Scripts
* URLSSLVerification
* Exists

### Commands
* url
* rasterize

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URLs to enrich. | URL.Data | Required |
| Rasterize | Should the system take safe screenshots of input URLs? | True | Optional |
| VerifyURL | Should the system perform SSL certificate verification on the URLs? | False | Optional |
| threshold | Defines the minimum score to set indicators as malicious | inputs.threshold | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | The URL object. | string |
| URL.Data | The enriched URL. | string |
| DBotScore | The DBotScore object. | unknown |
| URL.Malicious | Whether the detected URL was malicious. | unknown |
| URL.Vendor | Vendor that labeled the URL as malicious. | string |
| URL.Description | Additional information for the URL. | string |

