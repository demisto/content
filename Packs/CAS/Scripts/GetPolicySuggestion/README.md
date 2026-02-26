# GetPolicySuggestion

## Overview
Retrieves AI-powered prevention policy recommendations from the Cortex AppSec guardrails suggestions API. This script helps security teams discover and implement policies that can improve their prevention rate by analyzing their current security posture and identifying gaps.

## Use Case
This script is designed to support the "Suggest new guardrails to improve my prevention rate" feature. It:
- Calls the `/api/cas/v1/policies/guardrails/suggestions` endpoint to get AI-generated policy recommendations
- Filters suggestions by scope criteria (repository attributes, application name, business criticality)
- Returns complete policy objects ready to be applied directly via the `core-create-appsec-policy` command

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities, AppSec, AI |
| Cortex XSOAR Version | 8.13.0+ |

## Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| business_application_name | Filter suggestions by business application name (e.g., "terragoat_GitHub"). | Optional |
| application_business_criticality | Filter suggestions by application business criticality level. Options: CRITICAL, HIGH, MEDIUM, LOW. | Optional |
| is_public_repository | Filter suggestions that apply to public repositories. Options: true, false. | Optional |
| has_internet_exposed | Filter suggestions that apply to internet-exposed assets. Options: true, false. | Optional |
| has_deployed_assets | Filter suggestions that apply to repositories with deployed assets. Options: true, false. | Optional |
| has_access_sensitive_data | Filter suggestions that apply to assets that access sensitive data. Options: true, false. | Optional |
| has_leverage_privileged_capabilities | Filter suggestions that apply to assets that leverage privileged capabilities. Options: true, false. | Optional |
| repository_name | Filter suggestions by a specific repository name. | Optional |
| limit | Maximum number of policy suggestions to return. Default: 3. | Optional |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.PolicySuggestion.id | Unique identifier for the policy suggestion | String |
| Core.PolicySuggestion.name | Human-readable policy name (e.g., "Block critical vulnerabilities") | String |
| Core.PolicySuggestion.type | Policy type (e.g., "VULNERABILITY", "SECRET", "MISCONFIGURATION") | String |
| Core.PolicySuggestion.description | Explanation of what the policy does and why it's recommended | String |
| Core.PolicySuggestion.conditions | AND/OR conditions defining what findings the policy matches | Unknown |
| Core.PolicySuggestion.scope | AND/OR conditions defining which assets/applications the policy applies to | Unknown |
| Core.PolicySuggestion.triggers | Configuration for CI/CD, PR, and periodic triggers with actions | Unknown |
| Core.PolicySuggestion.evidence | Evidence supporting the recommendation (e.g., cleanScope indicates no existing issues) | Unknown |

## Filtering Behavior

### OR Logic
When multiple scope filters are provided, the script uses **OR logic** — suggestions matching **any** of the provided criteria are returned.

### Value Matching vs Presence Matching
- **Value-match fields** (business_application_names, repository_name, application_business_criticality): Both the field name AND value must match
- **Boolean fields** (is_public_repository, has_deployed_assets, etc.): Only field presence is checked (the API always stores these with value=true)

## Example Usage

### Get top 3 suggestions for a specific application
```
!CASGetPolicySuggestion business_application_name="terragoat_GitHub"
```

### Get suggestions for public repositories with deployed assets
```
!CASGetPolicySuggestion is_public_repository=true has_deployed_assets=true limit=5
```

### Get suggestions for critical applications
```
!CASGetPolicySuggestion application_business_criticality=CRITICAL
```

## Integration with Policy Creation
The returned policy suggestions contain all the data needed to create policies directly using the `core-create-appsec-policy` command. Simply pass the suggestion's `id`, `name`, `description`, `conditions`, `scope`, and `triggers` to create the policy.
