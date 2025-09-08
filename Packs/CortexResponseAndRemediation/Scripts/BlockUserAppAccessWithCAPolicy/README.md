Checks if a CA policy exists. If yes, adds the user if needed. If no, creates a new CA policy to block access to a specific app for a user.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Azure, Conditional Access, Access Control |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* MicrosoftGraphIdentityandAccess
* msgraph-identity-ca-policies-list

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| policy_name | The display name of the Conditional Access policy to check or create. |
| username | The UPN of the user to block. |
| app_name | The name of the app to block access to. |

## Outputs

---
There are no outputs for this script.
