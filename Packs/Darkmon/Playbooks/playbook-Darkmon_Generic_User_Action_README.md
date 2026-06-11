# Darkmon - Generic User Action

Provider-agnostic user-action dispatcher (disable, reset password, revoke sessions). Reads the "Darkmon - Identity Provider" List for the configured directory (`ad` | `okta` | `azuread`) and routes to the matching command.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Active Directory Query v2
* Okta v2
* Azure Active Directory Users

### Scripts

* PrintErrorEntry

### Commands

* ad-disable-account
* ad-set-new-password
* ad-clear-sessions
* okta-deactivate-user
* msgraph-user-account-disable

## Playbook Inputs

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The directory username (sAMAccountName / UPN / login) to act on. |  | Required |
| Action | One of disable \| reset-password \| revoke-sessions. | disable | Required |
| NewPassword | Required only when Action is reset-password. |  | Optional |

## Playbook Outputs

There are no outputs for this playbook.
