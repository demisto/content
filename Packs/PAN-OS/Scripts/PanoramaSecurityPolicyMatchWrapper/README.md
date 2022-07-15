A wrapper script for the ***panorama-security-policy-match*** command that receives multiple values for the source, destination, and destination port arguments and performs the policy match for each combination of the inputs.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.1.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| application | The application name. |
| category | The category name. |
| destination | A comma-separated list of destination IP addresses. |
| from | The from zone. |
| to | The to zone. |
| protocol | The IP protocol value. |
| source | A comma-separated list of source IP addresses. |
| target | Target number of the firewall. Use only on a Panorama instance. |
| vsys | Target vsys of the firewall. Use only on a Panorama instance. |
| source_user | The source user. |
| destination_port | A comma-separated list of destination ports. |
| limit | Maximum number of API calls that script sends. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.SecurityPolicyMatch.Rules.Name | The matching rule name. | String |
| Panorama.SecurityPolicyMatch.Rules.Action | The matching rule action. | String |
| Panorama.SecurityPolicyMatch.Rules.Category | The matching rule category. | String |
| Panorama.SecurityPolicyMatch.Rules.Destination | The matching rule destination. | String |
| Panorama.SecurityPolicyMatch.Rules.From | The matching rule from zone. | String |
| Panorama.SecurityPolicyMatch.Rules.Source | The matching rule source. | String |
| Panorama.SecurityPolicyMatch.Rules.To | The matching rule to zone. | String |


## Script Examples
### Example command
```!PanoramaSecurityPolicyMatchWrapper destination=2.2.2.2 source=1.1.1.1,8.8.8.8 protocol=1```
### Context Example
```json
{
    "Panorama": {
        "SecurityPolicyMatch": {
            "Rules": {
                "Action": "deny",
                "Category": "any",
                "Destination": "2.2.2.2",
                "From": "any",
                "Name": "test rule",
                "Source": "1.1.1.1",
                "To": "any"
            }
        }
    }
}
```

### Human Readable Output

>### Matching Security Policies:
>|Action|Category|Destination|From|Name|Source|To|
>|---|---|---|---|---|---|---|
>| deny | any | 2.2.2.2 | any | test rule | 1.1.1.1 | any |
>
> The query for source: 8.8.8.8, destination: 2.2.2.2 did not match a Security policy.
