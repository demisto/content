Sets Data for a Domain in the Indicator Table.

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

* DomainTools_Check_Domain_Risk_Score_By_Iris_Tags
* DomainTools Check New Domains by Iris Hash

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domaintools_data | DomainTools context data for a domain. |
| proximity_score_threshold | Proximity score given based on closeness to other risky domains. |
| age_threshold | Threshold for domain age as younger domains are riskier. |
| threat_profile_score_threshold | Threshold for threat profile score based on many evidence based findings. |

## Outputs

---
There are no outputs for this script.
