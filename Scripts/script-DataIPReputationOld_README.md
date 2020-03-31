Evaluates the reputation of an IP and return a score between 0 and 3. Where, 0 - unknown, 1 - known good, 2 - suspicious, 3 - known bad. If the indicator reputation was manually set, the manual value will be returned.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | reputation |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | The IP address to look up. |
| forceCalc | Whether to calculate a reputation even if was set manually. Can be, "yes" or "no". |

## Outputs
---
There are no outputs for this script.
