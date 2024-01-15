Sets average risk score to context for pivot result.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DomainTools |
| Cortex XSOAR Version | 6.9.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* DomainTools Auto Pivots

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domaintools_data | DomainTools Iris Enrich result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AddDomainRiskScoreToContext.HighRiskPivotedDomains.Name | The domain name | Unknown |
| AddDomainRiskScoreToContext.HighRiskPivotedDomains.OverallRiskScore | The overall risk score of the domain | Unknown |
