Widget script to view information about the relationship information the Cyren Threat InDepth
feeds offer. For instance, you can see and navigate to a malicious SHA256 that was hosted by
a malicious URL.

The script provides base functionality for other scripts that are supposed to be used similar
to the **Feed Related Indicators**.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | cyren |
| XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | JSON representation of the indicator holding the relationship data. |
| columns | *Optional* Comma-separated column list (for instance `Value,Indicator Type`). If not provided, the full list of supported columns is assumed. |

## Outputs
---
There are no outputs for this script.

## Human Readable Output
---

| Indicator Type | Value | Reputation | Relationship Type | Entity Category | Timestamp UTC |
|---|---|---|---|---|---|
| IP | 172.217.6.65 | None (0) | resolves to | malware | 2021-01-07, 09:02:21 |
| SHA-256 | 6ea626950a759c259a182b628f79816843af379af87dbbe13923bf72d6047770 | Bad (3) | serves | malware | 2021-01-07, 09:02:21 |
