Checks the sender of the email via a `Pipl` search. Use this script for phishing incidents.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | server, phishing |


## Dependencies
---
This script uses the following commands and scripts.
* pipl-search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email address to look up. If omitted, the script will instead extract with regular expression from the fullmail argument, where the phishing email should be provided. |
| fullmail | The raw email text to regex the sender from. |

## Outputs
---
There are no outputs for this script.
