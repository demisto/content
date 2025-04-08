Add, remove, or modify logos for the URL Phishing model to compare to suspicious websites.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| logoImageId | "Entry ID" of the uploaded logo in Cortex XSOAR. |
| logoName | Name of the logo. The name is the unique identifier for the logo. |
| associatedDomains | Comma-separated list of domains that are associated to the logo defined in the logoName argument. It will only be used if the action argument is AddLogo or ModifiedDomainForLogo. |
| action | Action to execute on the model. |

## Outputs
---
There are no outputs for this script.
