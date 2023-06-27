For a given alert and remediation path rules that are defined for that alert's attack surface rule, this script takes each remediation path rule and looks at the rule criteria to see if the rule matches for the given alert. If multiple rules match, it will return the most recently created rule. This assumes that the rules passed in are filtered to correlate with the alert's attack surface rule.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| severity | Alert's Severity. |
| ip | Alert's Remote IP. |
| development_environment | Is this in a development environment? |
| cloud_managed | Is this cloud managed? |
| service_owner_identified | Has a service owner been identified? |
| tags | Includes Cloud and Xpanse tags |
| providers | Externally Detected Providers |
| remediation_path_rules | List of remediation path rules for the alert's attack surface rule. |

## Outputs
---
There are no outputs for this script.
