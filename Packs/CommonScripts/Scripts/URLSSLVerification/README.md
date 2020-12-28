Verifies the URL's SSL certificate.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | url, Enrichment |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | Comma separated list of URLs to verify. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | The URL object. | Unknown |
| URL.Data | The URL address. | string |
| URL.Malicious | The malicious description. | Unknown |
| DBotScore | The DBotScore object. | Unknown |
| DBotScore.Indicator | The indicator. | string |
| DBotScore.Type | The indicator's type. | string |
| DBotScore.Vendor | The reputation vendor. | string |
| DBotScore.Score | The reputation score. | number |
