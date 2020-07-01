Performs CVE enrichment using the following integrations:
- VulnDB
- CVE Search
- IBM X-Force Exchange

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* CVE Search
* XFE
* VulnDB

## Scripts
This playbook does not use any scripts.

## Commands
* cve-search
* vulndb-get-vuln-by-cve-id

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| cve_id | The CVE ID to enrich. | ID | CVE | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CVE | The CVE object. | unknown |
| CVE.ID | The ID of the CVE. | string |
| CVE.CVSS | The CVSS score of the CVE. | number |
| CVE.Published | The date this was published. | date |
| CVE.Modified | The last time the CVE was modified. | date |
| CVE.Description | The CVE description. | string |
| VulnDB.Vulnerability.ID | The vulnerability ID. | unknown |
| VulnDB.Vulnerability.Title | The vulnerability title (human readable). | unknown |
| VulnDB.Vulnerability.Description | The vulnerability description (human readable). | unknown |
| VulnDB.Vulnerability.Solution | The vulnerability solution (human readable). | unknown |
| VulnDB.CvssMetrics.Id | The CVSS reference value. | unknown |
| VulnDB.CvssMetrics.ConfidentialityImpact | The CVSS confidentiality impact. | unknown |
| VulnDB.CvssMetrics.AvailabilityImpact | The CVSS availability impact. | unknown |
| VulnDB.CvssMetrics.Score | The CVSS score. | unknown |
| VulnDB.cvssMetrics.integrity_impact | The CVSS integrity impact. | unknown |
| VulnDB.Vendors.Id | The vendor ID. | unknown |
| VulnDB.Products.Id | The product IDs. | unknown |

## Playbook Image
---
![CVE_Enrichment_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/CVE_Enrichment_Generic_v2.png)
