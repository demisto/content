For a given alert and remediation path rules that are defined for that alert's attack surface rule, this takes each remediation path rule and looks at the rule criteria too see if the rule matches for the given alert. If multiple rules match, it will return the most recently created rule. This assumes that the rules passed in are filtered to correlate with the alert's attack surface rule.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| severity | Alert's Severity |
| ip | Alert's Remote IP |
| development_environment | Is this in a development environment? |
| cloud_managed | Is this Cloud Managed? |
| service_owner_identified | Has a Service Owner been Identified? |
| tags | Includes Cloud and Xpanse tags |
| providers | Externally Detected Providers |
| remediation_path_rules | List of Remediation Path Rules for the Alert's Attack Surface Rule |

## Outputs
---
There are no outputs for this script.
