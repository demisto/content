Gets the list of processes that have connections to IP addresses with a bad reputation.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | memory, forensics, volatility, server |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| memdump | The path to memory dump the file on the system being used. |
| system | The system with Volatility installed to be used for the analysis. |
| profile | The Volatility profile to use. |
| repthreshold | The reputation threshold. Any IP addresses up to and including this score are considered malicious. |
| repscript | The reputation script to use to check IP addresses. |

## Outputs
---
There are no outputs for this script.
