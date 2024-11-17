This script clears user sessions from multiple integrations for specified usernames and returns an Account entity with consolidated information to the context.


## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user_name | List of names of the users to retrieve. |
| brands | List of integration brands to clear sessions from. If not provided, the script will attempt to clear sessions from all available integrations.<br/>For multiple brands, provide a comma-separated list. For example: "Okta v2,Microsoft Graph User".|
| verbose | Whether to retrieve human readable entry for every command or only the final result. True means to retrieve human readable entry for every command. False means to human readable only for the final result. |

## Outputs

---
