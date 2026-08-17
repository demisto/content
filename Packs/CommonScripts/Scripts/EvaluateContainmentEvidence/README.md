# EvaluateContainmentEvidence

Evaluates whether detection evidence is sufficient for a calling playbook to consider automatic containment. The script does not perform containment or override the caller's policy.

ML-only and unknown evidence require user verification. A corroborated disposition requires independent ML and signature evidence. Explicit ML-only evidence, including generator ID 411, takes precedence over classification text that may remain on the same event.

## Inputs

| Name | Description |
|---|---|
| detection_basis | Optional authoritative basis: `ml_only`, `signature`, `corroborated`, or `unknown`. |
| analytic_type | Analytic type such as Learning, ML, Rule, or Signature. |
| generator_id | Detection generator ID. Generator ID 411 is ML-only evidence. |
| signature_id | Identifier of an independently matched signature or rule. |
| classification | Detection classification text. |
| is_corroborated | Whether independent ML and signature evidence was explicitly corroborated. |
| incident_context | Additional incident text for conservative inference. |

## Outputs

| Context path | Description |
|---|---|
| ContainmentEvidence.disposition | `ml_only`, `signature`, `corroborated`, or `unknown`. |
| ContainmentEvidence.allow_auto_contain | Whether the evidence is sufficient for a caller to consider automatic containment. |
| ContainmentEvidence.require_user_verification | Whether verification is required before containment. |
| ContainmentEvidence.reason_codes | Deterministic reason codes for the decision. |
| ContainmentEvidence.evidence_summary | Concise decision summary for the investigation record. |
