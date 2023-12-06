Enrich URLs using one or more integrations.

URL enrichment includes:
* SSL verification for URLs.
* Threat information.
* Providing of URL screenshots.
* URL Reputation using !url.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Rasterize

### Scripts

* Exists
* URLSSLVerification

### Commands

* rasterize
* url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The URLs to enrich. | URL.Data | Optional |
| Rasterize | Define if you would like the system take safe screenshots of input URLs.<br/>Possible values: True / False.<br/>The default value is true. | True | Optional |
| VerifyURL | Define if you would like the system perform SSL certificate verification on the URLs.<br/>Possible values: True / False.<br/>The default value is false. | False | Optional |
| UseReputationCommand | Define if you would like to use the \!url command.<br/>Note: This input should be used whenever there is no auto-extract enabled in the investigation flow.<br/>Possible values: True / False.<br/>The default value is false. | False | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | The URL object. | uknown |
| URL.Data | The enriched URL. | string |
| DBotScore | The DBotScore object. | unknown |
| URL.Malicious | Whether the detected URL was malicious. | unknown |
| URL.Malicious.Vendor | For malicious URLs, the vendor that made the decision. | unknown |
| URL.Malicious.Description | For malicious URLs, the reason that the vendor made the decision. | unknown |
| DBotScore.Indicator | The indicator | string |
| DBotScore.Type | The indicator's type | string |
| DBotScore.Vendor | The reputation vendor | string |
| DBotScore.Score | The reputation score | number |
| DBotScore.Reliability | Reliability of the source providing the intelligence data. | unknown |
| URL.Relationships.EntityA | The source of the relationship. | unknown |
| URL.Relationships.EntityB | The destination of the relationship. | unknown |
| URL.Relationships.Relationship | The name of the relationship. | unknown |
| URL.Relationships.EntityAType | The type of the source of the relationship. | unknown |
| URL.Relationships.EntityBType | The type of the destination of the relationship. | unknown |
| InfoFile.EntryID | The EntryID of the image/pdf file. | unknown |
| InfoFile.Extension | The extension of the image/pdf file. | unknown |
| InfoFile.Name | The name of the image/pdf file. | unknown |
| InfoFile.Info | The info of the image/pdf file. | unknown |
| InfoFile.Size | The size of the image/pdf file. | unknown |
| InfoFile.Type | The type of the image/pdf file. | unknown |

## Playbook Image

---

![URL Enrichment - Generic v2](../doc_files/URL_Enrichment_-_Generic_v2.png)
