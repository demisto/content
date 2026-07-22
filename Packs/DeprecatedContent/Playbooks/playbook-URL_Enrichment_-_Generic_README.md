DEPRECATED. Use "URL Enrichment - Generic v2" playbook instead. Enriches a URL using one or more integrations.

URL enrichment includes:
* Verify URL SSL
* Threat information
* URL reputaiton
* Take URL screenshot

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* VirusTotal - Private API
* Rasterize

### Scripts
* URLSSLVerification
* URLReputation
* Exists

### Commands
* vt-private-get-url-report
* rasterize

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| url | The URL to enrich. | Data | URL | Optional |
| Rasterize | Whether the system should take safe screenshots of input URLs. | False | - | Optional |
| VerifyURL | Whether the system should verify the input URLs. | False | - | Optional |
| GetReputation | Whether the playbook should get the reputation for the URL. | True | - | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | The URL's object. | uknown |
| URL.Data | The enriched URL. | string |
| DBotScore | The DBotScore. | unknown |
| URL.Malicious | Whether the URL was detected as malicious. | unknown |
| URL.Vendor | The name of vendor who labeled the URL as malicious. | string |
| URL.Description | The additional info on the URL. | string |

## Playbook Image
---
![URL_Enrichment_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/URL_Enrichment_Generic.png)
