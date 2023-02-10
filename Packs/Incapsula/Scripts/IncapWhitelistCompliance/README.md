Get all sites from Incapsula.
For each site, the script, through a ssh server (one that should NOT be in the allow list), make sure the site is compliant ( allow list is being enforced ).
 If not, a warning mail will be sent to the domain owner. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Incapsula |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* incap-list-sites
* RemoteExec
* SendEmail
* incap-get-domain-approver-email

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| SSHValidationServer | Name of the non-allow list SSH server instance |

## Outputs
---
There are no outputs for this script.
