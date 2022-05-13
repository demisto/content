Gets all sites from Incapsula.
Each site will be returned through a ssh server (which should not be on the allow list), to ensure that the site is compliant and that the allow list is being enforced. If the site is not compliant , a warning mail will be sent to the domain owner. 
 
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Incapsula |


## Dependencies
---
This script uses the following commands and scripts.
* RemoteExec
* incap-list-sites
* SendEmail
* incap-get-domain-approver-email

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| SSHValidationServer | The name of the non-allow list SSH server instance. |

## Outputs
---
There are no outputs for this script.
