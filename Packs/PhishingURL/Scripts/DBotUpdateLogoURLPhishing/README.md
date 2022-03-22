Add, remove, or modify logos from the URL Phishing model.

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
| logoimageId | "Entry ID" in XSOAR |
| logoName | Name of the logo. The name is the unique identifier for the logo. |
| debug | Whether to enter debug mode. |
| associatedDomains | Comma-separated list of domains that are associated to the logo defined in the logoName argument. It will only be used if the action argument is AddLogo or ModifiedDomainForLogo. |
| action | Action to execute on the model. Will be ignored if displayLogos is set to True. |

## Outputs
---
There are no outputs for this script.
