Evaluates the reputation of a URL and Domain and returns a score between 0 and 3. Where, 0 - unknown, 1 - known good, 2 - suspicious, 3 - known bad. If the indicator reputation was manually set, the manual value will be returned.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | reputation |
| Cortex XSOAR Version | 3.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | The URL to look up. |
| cacheExpiration | The time that cache should be valid for (in minutes). |
| forceCalc | Whether to calculate a reputation, even if it was set manually. Must be, "yes" or "no". |

## Outputs
---
There are no outputs for this script.
