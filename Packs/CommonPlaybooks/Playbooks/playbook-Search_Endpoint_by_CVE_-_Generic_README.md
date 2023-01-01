Hunt for assets with a given CVE using available tools

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Threat Hunting - Set Indicators
* CVE Exposure - RiskSense

### Integrations
* Rapid7 Nexpose

### Scripts
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands
* kenna-search-vulnerabilities
* kenna-search-assets
* nexpose-search-assets

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| CVE_ID | Hunt for assets with a given CVE using available tools.<br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Kenna.Assets | Compromised Assets retrieved from Kenna. | unknown |
| Nexpose.Asset | Compromised Assets retrieved from Nexpose. | unknown |
| Endpoint | Global compromised Assets | unknown |
| RiskSense.Host | Compromised Assets retrieved from RiskSense. | unknown |

## Playbook Image
---
![Search Endpoint by CVE - Generic](../doc_files/Search_Endpoint_by_CVE_-_Generic.png)