Detonates a URL using the Phish.AI integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* phish-ai-check-status
* phish-ai-scan-url

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| URL | The URL to detonate. | Data | URL | Optional |
| Interval | The polling frequency. How often the polling command should run (in minutes). | 1 | - | Optional |
| Timeout | How much time to wait before a timeout occurs (in minutes). | 15 | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PhishAI.ScanID | The Phish.AI scan ID. | string |
| PhishAI.Status | The scan status. | string |
| PhishAI.URL | The URL address. | string |
| URL.Malicious.Vendor | The vendor that made the decision that the URL is malicious. | string |
| URL.Malicious.Description | The reason for the vendor to make the decision that the URL is malicious. | string |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The type of the indicator. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| IP.Address | The IP address of the URL. | string |
| IP.Geo.Country | The geo location of the URL. | string |
| URL.Status | THe URL's status. | string |
| URL.Data | The URL's address. | string |

## Playbook Image
---
![Detonate_URL_PhishAI](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_URL_Phish.AI.png)
