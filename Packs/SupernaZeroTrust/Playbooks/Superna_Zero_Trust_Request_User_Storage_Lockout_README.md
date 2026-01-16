# Superna Zero Trust Request User Storage Lockout

## Overview

Offers an input question to accept the userID that should be locked out of storage. This playbook can be run by any SecOps workflow where the threat to data is increased and a proactive step to ensure no data can be destroyed, or it can be used as a step in a workflow when employees are leaving the company or have been terminated.

## Playbook Tasks

1. **Start** - Initiates the playbook
2. **Prompt for userid** - Displays a form to collect the user ID in AD format (domain\userID)
3. **URL encode userid** - Encodes the user ID for API transmission
4. **Superna Zero Trust Lockout User** - Locks out the specified user from NAS storage access using the SupernaZeroTrust integration
5. **Done** - Completes the playbook

## Inputs

This playbook does not require predefined inputs. The user ID is collected interactively through a form prompt.

## Interactive Form

The playbook presents a collection task asking:

- **Title**: User NAS lock out request
- **Question**: Enter user ID in AD format domain\userID
- **Placeholder**: example corp\username

## Outputs

The playbook stores the lockout operation result in the context path:

- SupernaZeroTrust.Lockout.Result

## Use Cases

- Employee termination workflows
- Proactive data protection during elevated threat conditions
- Manual user access revocation by SecOps
- Compliance-driven access control
- Insider threat mitigation

## Dependencies

- SupernaZeroTrust integration must be configured
- User must have permissions to approve data protection actions
