This script calculates the CVSS Base Score, Temporal Score, and Environmental Score using either the CVSS 3.0 or CVSS 3.1 calculator according to https://www.first.org/cvss/ calculation documentation.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| version | The CVSS version to use for scoring. Can be "3.1" or "3.0". Default is "3.1". |
| AV | Attack Vector. Can be "N", "A", "L", or "P". |
| AC | Attack Complexity. Can be "L" or "H". |
| PR | Privileges Required. Can be "N", "L", or "H". |
| UI | User Interaction. Can be "N" or "R". |
| S | Scope. Can be "U" or "C". |
| C | Confidentiality. Can be "H", "L", or "N". |
| I | Integrity. Can be "H", "L", or "N". |
| A | Availability. Can be "H", "L", or "N". |
| E | Exploit Code Maturity. Can be "X", "H", "F", "P", or "U". Default is "X". |
| RL | Remediation Level. Can be "X", "U", "W", "T", or "O". Default is "X". |
| RC | Report Confidence. Can be "X", "C", "R", or "U". Default is "X". |
| CR | Confidentiality Requirement. Can be "X", "H", "M", or "L". Default is "X". |
| IR | Integrity Requirement. Can be "X", "H", "M", or "L". Default is "X". |
| AR | Availability Requirement. Can be "X", "H", "M", or "L". Default is "X". |
| MAV | Modified Attack Vector. Can be "X", "N", "A", "L", or "P". Default is "X". |
| MAC | Modified Attack Complexity. Can be "X", "L", or "N". Default is "X". |
| MPR | Modified Privileges Required. Can be "X", "N", "L", or "H". Default is "X". |
| MUI | Modified User Interaction. Can be "X", "N", or "R". Default is "X". |
| MS | Modified Scope. Can be "X", "U", or "C". Default is "X". |
| MC | Modified Confidentiality. Can be "X", "N", "L", or "H". Default is "X". |
| MI | Modified Integrity. Can be "X", "N", "L", or "H". Default is "X". |
| MA | Modified Availability. Can be "X", "N", "L", or "H". Default is "X". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CVSS.VectorString | Text notation of the score. | string |
| CVSS.ImpactSubScore | Impact sub-score. | number |
| CVSS.Impact | Impact Score. | number |
| CVSS.Exploitability | Exploitability score. | number |
| CVSS.BaseScore | Base score. | number |
| CVSS.TemporalScore | Temporal score. | number |
| CVSS.ModifiedImpactSubScore | Modified impact sub-score. | number |
| CVSS.ModifiedImpact | Modified impact. | number |
| CVSS.ModifiedExploitability | Modified exploitability score. | number |
| CVSS.EnvironmentalScore | Environmental score. | number |
| CVSS.Version | Version of CVSS used in the calculation. | number |
