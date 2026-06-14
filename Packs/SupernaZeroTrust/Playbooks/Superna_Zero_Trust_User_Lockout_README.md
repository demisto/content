# Superna Zero Trust User Lockout

## Overview

You can run this playbook for any Superna Zero Trust created alerts, as this playbook depends on the customer userID field to exist in the incident. If lockout mode in Superna Security Edition is not enabled, this allows SecOps to decide when a user lockout should occur. This moves the responsibility of data protection decisions to the SecOps team versus the storage team.

## Playbook Tasks

1. **Start** - Initiates the playbook
2. **Print inputs to API task** - Displays the API URL and username for verification
3. **Superna Zero Trust Lockout User** - Locks out the specified user from NAS storage access using the SupernaZeroTrust integration
4. **Done** - Completes the playbook

## Inputs

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Source username from the incident (incident.sourceusername). This field is populated by Superna Zero Trust webhook integration. | No |

## Outputs

The playbook stores the lockout operation result in the context path:

- SupernaZeroTrust.Lockout.Result

## Use Cases

- Automated response to Superna Zero Trust alerts
- User access revocation during active security incidents
- Immediate containment of compromised user accounts
- Zero Trust enforcement for NAS storage

## Dependencies

- SupernaZeroTrust integration must be configured
- The incident must contain a sourceusername field populated by Superna Zero Trust webhook
