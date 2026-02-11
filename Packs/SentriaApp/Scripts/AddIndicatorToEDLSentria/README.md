Add indicators to one of the three configured EDLs (Domain, IP, File and URL) based on the indicator type.

If the indicator does not exist, it creates it in the Threat Intel database only if they are not registered. When using the script with many indicators, or when the Threat Intel Management database is highly populated, this script may have low performance issue.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | SENTRIA |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| customer | Select customer to identify EDL to be modified. |
| indicator_type |  The indicator type of the indicators. |
| indicator_value | A comma-separated list of indicators values. For example, for IP indicators, "1.1.1.1,2.2.2.2" |

## Outputs

---
There are no outputs for this script.
