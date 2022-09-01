Generates a password and allows various parameters to customize the properties of the password depending on the use case. For example, "password complexity requirements".  The default behavior is to generate a password of  *random length* including all four character classes, upper, lower, digits, and symbols, with at least five and at most ten characters per class. 

The `min_* values` all default to 0. 

This means that if the command is executed in this way:
`!GeneratePassword max_lcase=10`
It is possible that a password of length zero could be generated. It is therefore recommended to always include a `min_* parameter` that matches. 

The debug parameter will print certain properties of the command into the War Room for easy diagnostics.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| min_lcase | The minimum number of lower case characters to include in password. |
| max_lcase | The maximum number of lower case characters to include in password. |
| min_ucase | The minimum number of upper case characters to include in password. |
| max_ucase | The maximum number of upper case characters to include in password. |
| min_digits | The minimum number of digits to include in password. |
| max_digits | The maximum number of digits to include in password. |
| min_symbols | The minimum number of symbols to include in password. |
| max_symbols | The maximum number of symbols to include in password. |
| debug | Sees various values as they pass through the function if enabled. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NEW_PASSWORD | The new password generated for the user. | Unknown |
