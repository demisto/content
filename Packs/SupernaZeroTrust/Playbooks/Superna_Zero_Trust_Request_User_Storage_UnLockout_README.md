# Superna Zero Trust Request User Storage UnLockout

## Overview

Offers an input question to accept the userID that should be unlocked from the storage. This playbook can be run by any SecOps workflow to allow a user that was previously locked out to have the lockout removed.

## Playbook Tasks

1. **Start** - Initiates the playbook
2. **Prompt for userid** - Displays a form to collect the user ID in AD format (domain\userID)
3. **URL encode userid** - Encodes the user ID for API transmission
4. **Superna Zero Trust Unlock User** - Unlocks the specified user to restore NAS storage access using the SupernaZeroTrust integration
5. **Done** - Completes the playbook

## Inputs

This playbook does not require predefined inputs. The user ID is collected interactively through a form prompt.

## Interactive Form

The playbook presents a collection task asking:

- **Title**: User NAS unlock request
- **Question**: Enter user ID in AD format domain\userID
- **Placeholder**: example corp\username

## Outputs

The playbook stores the unlock operation result in the context path:

- SupernaZeroTrust.Unlock.Result

## Use Cases

- Restoring access after security incident resolution
- Removing false positive lockouts
- Post-investigation access restoration
- Scheduled access reinstatement workflows
- Emergency access recovery

## Dependencies

- SupernaZeroTrust integration must be configured
- User must have permissions to approve data access restoration
- Previous lockout action must have been performed
