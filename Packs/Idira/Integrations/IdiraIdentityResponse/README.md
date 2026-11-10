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
| Privilege Cloud URL | The Idira Privilege Cloud PVWA host (e.g., `https://abc1234.privilegecloud.cyberark.cloud`). Required only for the account, session, and credential commands. | False |
| Secure Infrastructure Access (SIA) URL | The Idira SIA host (e.g., `https://abc1234.dpa.cyberark.cloud`). Required only for the disable-access-policy command. | False |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |
| Disable usage reporting | When selected, the integration does not send usage events \(command executed, integration version\) to Palo Alto Networks. | False |

All three hosts (Identity, Privilege Cloud, SIA) authenticate with the same ISPSS Bearer token, so a single service user with the appropriate rights is sufficient. The Privilege Cloud and SIA hosts are optional: commands that need them raise a clear error if the corresponding URL is not configured. Privilege Cloud actions require the relevant Safe permissions (List Accounts, Initiate CPM operations, Add account), and SIA policy actions require the `DpaAdmin` role.

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

### idira-identity-response-remove-role

Strips standing privilege by removing one or more users from a role. Reversible by re-adding the user to the role.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The unique ID of the role. | Required |
| user_ids | Comma-separated list of user unique IDs (or usernames) to remove from the role. | Required |

**Context Output**: `IdiraIdentityResponse.RoleRemoval` (`RoleId`, `Users`, `Success`).

## Privilege Cloud commands

These commands require the **Privilege Cloud URL** parameter.

### idira-identity-response-get-account

Resolves privileged accounts to their internal account IDs. Run this first — rotate and verify target the account by internal ID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Keywords to search for (e.g., account name or address). | Optional |
| search_type | Search mode: `contains` (default) or `startswith`. | Optional |
| safe_name | Filter results to a specific Safe. | Optional |
| limit | Maximum number of accounts to return (max 1000, default 50). | Optional |

**Context Output**: `IdiraIdentityResponse.Account` (`id`, `name`, `userName`, `safeName`, `platformId`, `address`, `secretType`).

### idira-identity-response-get-account-details

Fetches a single account's details by its internal ID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The internal account ID. | Required |

**Context Output**: `IdiraIdentityResponse.Account` (as above).

### idira-identity-response-list-sessions

Lists active privileged sessions to resolve a `SessionGuid`. Check the `CanTerminate` / `CanSuspend` flags before acting.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Keywords to search for (e.g., the username). | Optional |
| safe | Filter results to a specific Safe. | Optional |
| limit | Maximum number of sessions to return (default 25). | Optional |

**Context Output**: `IdiraIdentityResponse.Session` (`SessionGuid`, `User`, `AccountUsername`, `AccountAddress`, `RemoteMachine`, `Protocol`, `RiskScore`, `CanTerminate`, `CanSuspend`, `CanMonitor`).

### idira-identity-response-terminate-session

Ends a live privileged session immediately by GUID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_guid | The session GUID (from list-sessions). | Required |

**Context Output**: `IdiraIdentityResponse.SessionAction` (`SessionGuid`, `Action`, `Success`).

### idira-identity-response-suspend-session

Pauses a live session by GUID. Reversible with resume-session. Not supported for SSH/OPM sessions.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_guid | The session GUID (from list-sessions). | Required |

**Context Output**: `IdiraIdentityResponse.SessionAction` (`SessionGuid`, `Action`, `Success`).

### idira-identity-response-resume-session

Lifts the pause on a suspended session by GUID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_guid | The session GUID (from list-sessions). | Required |

**Context Output**: `IdiraIdentityResponse.SessionAction` (`SessionGuid`, `Action`, `Success`).

### idira-identity-response-rotate-credential

Triggers an immediate CPM credential change on an account.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The internal account ID (from get-account). | Required |
| change_creds_for_group | Whether the CPM changes credentials on all accounts in the same group. Default `false`. | Optional |

**Context Output**: `IdiraIdentityResponse.CredentialAction` (`AccountId`, `Action`, `Success`).

### idira-identity-response-verify-credential

Marks an account for CPM verification to confirm the credential is valid.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The internal account ID (from get-account). | Required |

**Context Output**: `IdiraIdentityResponse.CredentialAction` (`AccountId`, `Action`, `Success`).

### idira-identity-response-vault-account

Brings an unmanaged, risky privileged account under Idira management.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| platform_id | The platform definition to assign (case-sensitive). | Required |
| safe_name | The target Safe. | Required |
| name | The account object name. | Optional |
| address | The machine name or address. | Optional |
| username | The account username. | Optional |
| secret_type | The secret type: `password` or `key`. | Optional |
| secret | The password or SSH key value. | Optional |
| automatic_management_enabled | Whether to enable CPM automatic management. | Optional |

**Context Output**: `IdiraIdentityResponse.Account` (`id`, `name`, `safeName`, `platformId`, `Success`).

## Secure Infrastructure Access commands

These commands require the **Secure Infrastructure Access (SIA) URL** parameter and the `DpaAdmin` role.

### idira-identity-response-disable-access-policy

Revokes standing or just-in-time access by disabling a SIA access policy. Reversible by setting `status=Enabled`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy UUID. | Required |
| policy_name | The policy name (1–200 characters). | Required |
| status | The status to set: `Disabled` (default), `Enabled`, `Draft`, `Expired`, or `Irrelevant`. | Optional |

**Context Output**: `IdiraIdentityResponse.AccessPolicy` (`PolicyId`, `PolicyName`, `Status`, `Success`).

## Error handling

Responses are mapped per the development guide: `401` triggers one re-authentication retry (then an auth error), `403` reports insufficient permissions, `404` prompts you to re-resolve the target, and `409` is treated as an idempotent success (the target is already in the requested state). `429`/`5xx` are retried with exponential backoff.

## Known limitations

- The following request-body JSON keys are defaulted and should be verified against your tenant Swagger (`/identity-docs-api`) before go-live; each is a single-line constant at the top of the integration code:
  - `GetUserByName` request key - defaulted to `name`.
  - `SignOutEverywhere` user-ID key - defaulted to `ID`.
- This version covers Identity (workforce), Privilege Cloud (account resolution, session terminate/suspend/resume, credential rotate/verify, vault account), and Secure Infrastructure Access (disable access policy) actions. Secure Cloud Access (SCA) session revocation and machine-identity (workload/authenticator) deletion are not yet included — their API path shapes are pending live-tenant confirmation. Endpoint containment (EPM) is handled by the **Idira EPM SOC Response** integration.
