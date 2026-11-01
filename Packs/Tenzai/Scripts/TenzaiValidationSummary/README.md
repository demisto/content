Renders the Tenzai validation summary panel for the Validate tab: a TENZAI wordmark + status line, a verdict hero (exploitable / not exploitable), a monospace telemetry grid (verdict, exploit, finding count, credit usage, reference link), a per-severity meter, and a per-finding overview (a color-coded severity chip + the finding title + a one-line summary). Reads the persisted Tenzai result fields on the issue. The overview is a summary — each finding's full detail renders in the Tenzai Findings grid directly below.

This script is a dynamic-section widget used by the **Tenzai Issue Layout** and is not intended to be run directly.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---
There are no inputs for this script.

## Outputs

---
There are no outputs for this script.
