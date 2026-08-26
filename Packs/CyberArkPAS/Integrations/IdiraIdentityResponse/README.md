# Idira Identity Response

Trigger identity (workforce) response actions in the Idira Identity Security Platform as part of a detection-to-containment playbook: resolve a user, lock / disable / unlock the account, force logout of all sessions, expire the password, and remove a privileged role.

This integration was implemented and tested with the Idira Identity Security Platform Shared Services (ISPSS) Identity workforce APIs.

## Authentication

The integration uses the OAuth 2.0 **client-credentials** flow against `https://<tenant>.id.cyberark.cloud/oauth2/platformtoken` and sends the resulting Bearer token on every Identity API call. See the integration description for the service-user setup steps. Identity workforce actions require **system-administrator** or **user-management** rights on the service user.

## Configure Idira Identity Response in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Identity URL | The Idira Identity tenant FQDN for OAuth2 authentication and Identity workforce actions (e.g., `https://abc1234.id.cyberark.cloud`). | True |
| Client ID | Service username without domain (configured as an OAuth confidential client). | True |
| Client Secret | Service user password for OAuth2 client_credentials authentication. | True |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. Most actions target a user by **unique ID**, so run `idira-identity-response-get-user-by-name` first to resolve it.

### idira-identity-response-get-user-by-name

Resolves a username to its Idira Identity user unique ID.

**Arguments**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the cloud user (format `username@suffix` if a suffix is required). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdiraIdentityResponse.User.ID | String | The resolved user unique ID. |
| IdiraIdentityResponse.User.Username | String | The username that was resolved. |

### idira-identity-response-lock-user

Locks a user, blocking them from authenticating. Reversible with `idira-identity-response-unlock-user`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.UserState` (`ID`, `State`, `Success`).

### idira-identity-response-disable-user

Disables a user. Reversible with `idira-identity-response-unlock-user`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.UserState` (`ID`, `State`, `Success`).

### idira-identity-response-unlock-user

Reverses a lock or disable by setting the user state back to `None`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.UserState` (`ID`, `State`, `Success`).

### idira-identity-response-force-logout

Ends all of the user's active sessions and cookies, forcing them to sign in again.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.ForceLogout` (`ID`, `Success`).

### idira-identity-response-expire-password

Requires the user to set a new password at their next login.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the cloud user. | Required |

**Context Output**: `IdiraIdentityResponse.PasswordExpiry` (`Name`, `ForcePasswordChangeNext`, `Success`).

### idira-identity-response-remove-role

Strips standing privilege by removing one or more users from a role. Reversible by re-adding the user to the role.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The unique ID of the role. | Required |
| user_ids | Comma-separated list of user unique IDs (or usernames) to remove from the role. | Required |

**Context Output**: `IdiraIdentityResponse.RoleRemoval` (`RoleId`, `Users`, `Success`).

## Error handling

Responses are mapped per the development guide: `401` triggers one re-authentication retry (then an auth error), `403` reports insufficient permissions, `404` prompts you to re-resolve the target, and `409` is treated as an idempotent success (the target is already in the requested state). `429`/`5xx` are retried with exponential backoff.

## Known limitations

- The following request-body JSON keys are defaulted and should be verified against your tenant Swagger (`/identity-docs-api`) before go-live; each is a single-line constant at the top of the integration code:
  - `GetUserByName` request key - defaulted to `name`.
  - `SignOutEverywhere` user-ID key - defaulted to `ID`.
- This version covers Identity (workforce) actions only. Privilege Cloud (session terminate/suspend/resume, credential rotate/verify/vault) and Secure Infrastructure Access (list/disable access policy) actions are planned for a follow-up. Endpoint containment (EPM) is handled by the **Idira EPM SOC Response** integration.
