Checks if the email address is part of the internal domain.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | email |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email address to check. |
| domain | The list of internal domains to check. (comma-separated) |
| include_subdomains | Whether to include the subdomains of the domain list. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Email.Address | The email accounts full address. | string |
| Account.Email.Username | The email accounts username. | string |
| Account.Email.Domain | The email accounts domain. | string |
| Account.Email.NetworkType | The eil account NetworkType. Can be, "Internal" or "External". | string |
