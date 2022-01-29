Gets the string distance for the sender from our domain.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | server, phishing, Condition |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| domain | The domain to be measured against the domain in the sender's email address. Usually the domain used by the company for email. For example, "acme.com", when users are assigned jane@acme.com (could be multiple domains with a comma-separator). |
| sender | The sender's email address. |
| distance | The distance that is considered close. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| LevenshteinDistance | The proximity of the sender domain to our configured domains. | Unknown |
