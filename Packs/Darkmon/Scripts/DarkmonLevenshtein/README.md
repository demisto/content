Computes the minimum Levenshtein edit distance between a domain's root label
and a list of brand names. Used by Darkmon - Brand-Targeted NRD Watch to
flag typosquatting candidates.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | darkmon, transformer |
| Cortex XSOAR Version | 6.5.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* DarkmonScoreNRDs

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domain | The domain to compare \(only the root label is used\). |
| brands | Comma-separated brand names to compare against. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Darkmon.Levenshtein.domain | The input domain \(lowercased\). | String |
| Darkmon.Levenshtein.brand | The brand with the smallest distance to the domain root. | String |
| Darkmon.Levenshtein.distance | The minimum Levenshtein distance found. | Number |
