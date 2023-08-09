Checks if the supplied URLs are in the specified domains.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* PCAP Parsing And Indicator Enrichment

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domains | A comma-separated list of domains. |
| urls | A comma-separated list of URLs. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsUrlPartOfDomain.URL | The path of the URLs. | String |
| IsUrlPartOfDomain.Domain | The domain checked with the URL. | String |
| IsUrlPartOfDomain.IsInternal | Whether the URL is in the domain. | Boolean |
