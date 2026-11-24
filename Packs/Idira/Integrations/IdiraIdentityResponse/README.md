# Idira Identity Response

Trigger identity (workforce) response actions in the Idira Identity Security Platform as part of a detection-to-containment playbook: resolve a user, lock / disable / unlock the account, force logout of all sessions, expire the password, and remove a privileged role.

This integration was implemented and tested with the Idira Identity Security Platform Shared Services (ISPSS) Identity workforce APIs.

This version implements the actions for Identity (workforce), Privilege Cloud (session/credential) and Secure Infrastructure Access (access-policy) services.

## Prerequisites

The integration uses the OAuth 2.0 **client-credentials** flow against `https://<tenant>.id.cyberark.cloud/oauth2/platformtoken` and sends the resulting Bearer token on every Identity API call. See the integration description for the service-user setup steps. Identity workforce actions require **system-administrator** or **user-management** rights on the service user.

## Configure Idira Identity Response in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Identity URL | The Idira Identity tenant FQDN for OAuth2 authentication and Identity workforce actions (e.g., `https://abc1234.id.cyberark.cloud`). | True |
| Client ID | Service username without domain (configured as an OAuth confidential client). | True |
| Client Secret | Service user password for OAuth2 client_credentials authentication. | True |
| Privilege Cloud URL | The Idira Privilege Cloud PVWA host (e.g., `https://abc1234.privilegecloud.cyberark.cloud`). Required only for the account, session, and credential commands. | False |
| Secure Infrastructure Access (SIA) URL | The Idira SIA host (e.g., `https://abc1234.dpa.cyberark.cloud`). Required only for the disable-access-policy and enable-access-policy commands. | False |
| Use system proxy settings | When selected, the integration will use the system proxy settings. | False |
| Trust any certificate (not secure) | When selected, the integration will not verify SSL certificates. | False |
| Disable usage reporting | When selected, the integration does not send usage events \(command executed, integration version\) to Palo Alto Networks. | False |

All three hosts (Identity, Privilege Cloud, SIA) authenticate with the same ISPSS Bearer token, so a single service user with the appropriate rights is sufficient. The Privilege Cloud and SIA hosts are optional: commands that need them raise a clear error if the corresponding URL is not configured. Privilege Cloud actions require the relevant Safe permissions (List Accounts, Initiate CPM operations, Add account), and SIA policy actions require the `DpaAdmin` role.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. Most actions target a user by **unique ID**, so run `idira-identity-response-get-user-by-name` first to resolve it.

Some commands need an optional instance parameter:

- The account, session, and credential commands (`get-account`, `get-account-details`, `list-sessions`, `terminate-session`, `suspend-session`, `resume-session`, `rotate-credential`, `verify-credential`, `vault-account`) require the **Privilege Cloud URL** parameter.
- The access-policy commands (`disable-access-policy`, `enable-access-policy`) require the **Secure Infrastructure Access (SIA) URL** parameter and the `DpaAdmin` role.

### idira-identity-response-get-user-by-name

Resolves a username to its Idira Identity user unique ID.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the cloud user (format `username@suffix` if a suffix is required). | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdiraIdentityResponse.User.ID | String | The resolved user unique ID. |
| IdiraIdentityResponse.User.Username | String | The username that was resolved. |

#### Command example

```!idira-identity-response-get-user-by-name username=jdoe@example.com```

#### Context Example

```json
{
    "IdiraIdentityResponse.User": {
        "ID": "00000000-0000-0000-0000-000000000000",
        "Username": "jdoe@example.com"
    }
}
```

#### Human Readable Output

>### Idira Identity User: jdoe@example.com
>
>|ID|Username|
>|---|---|
>| 00000000-0000-0000-0000-000000000000 | jdoe@example.com |

### idira-identity-response-lock-user

Locks a user, blocking them from authenticating. Reversible with `idira-identity-response-unlock-user`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.UserState` (`ID`, `State`, `Success`).

#### Command example

```!idira-identity-response-lock-user user_id=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.UserState": {
        "ID": "00000000-0000-0000-0000-000000000000",
        "State": "Locked",
        "Success": true
    }
}
```

#### Human Readable Output

>### User 00000000-0000-0000-0000-000000000000 state set to Locked
>
>|ID|State|Success|
>|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | Locked | true |

### idira-identity-response-disable-user

Disables a user. Reversible with `idira-identity-response-unlock-user`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.UserState` (`ID`, `State`, `Success`).

#### Command example

```!idira-identity-response-disable-user user_id=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.UserState": {
        "ID": "00000000-0000-0000-0000-000000000000",
        "State": "Disabled",
        "Success": true
    }
}
```

#### Human Readable Output

>### User 00000000-0000-0000-0000-000000000000 state set to Disabled
>
>|ID|State|Success|
>|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | Disabled | true |

### idira-identity-response-unlock-user

Reverses a lock or disable by setting the user state back to `None`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.UserState` (`ID`, `State`, `Success`).

#### Command example

```!idira-identity-response-unlock-user user_id=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.UserState": {
        "ID": "00000000-0000-0000-0000-000000000000",
        "State": "None",
        "Success": true
    }
}
```

#### Human Readable Output

>### User 00000000-0000-0000-0000-000000000000 state set to None
>
>|ID|State|Success|
>|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | None | true |

### idira-identity-response-force-logout

Ends all of the user's active sessions and cookies, forcing them to sign in again.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user unique ID. | Required |

**Context Output**: `IdiraIdentityResponse.ForceLogout` (`ID`, `Success`).

#### Command example

```!idira-identity-response-force-logout user_id=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.ForceLogout": {
        "ID": "00000000-0000-0000-0000-000000000000",
        "Success": true
    }
}
```

#### Human Readable Output

>### Forced logout of all sessions for user 00000000-0000-0000-0000-000000000000
>
>|ID|Success|
>|---|---|
>| 00000000-0000-0000-0000-000000000000 | true |

### idira-identity-response-expire-password

Requires the user to set a new password at their next login.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the cloud user. | Required |

**Context Output**

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdiraIdentityResponse.PasswordExpiry.Name | String | The username. |
| IdiraIdentityResponse.PasswordExpiry.ForcePasswordChangeNext | Boolean | Whether the user must change the password at next login. |
| IdiraIdentityResponse.PasswordExpiry.Success | Boolean | Whether the action succeeded. |

#### Command example

```!idira-identity-response-expire-password username=jdoe```

#### Context Example

```json
{
    "IdiraIdentityResponse.PasswordExpiry": {
        "Name": "jdoe",
        "ForcePasswordChangeNext": true,
        "Success": true
    }
}
```

#### Human Readable Output

>### User jdoe required to change password at next login
>
>|ForcePasswordChangeNext|Name|Success|
>|---|---|---|
>| true | jdoe | true |

### idira-identity-response-remove-role

Strips standing privilege by removing one or more users from a role. Reversible by re-adding the user to the role.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The unique ID of the role. | Required |
| user_ids | Comma-separated list of user unique IDs (or usernames) to remove from the role. | Required |

**Context Output**: `IdiraIdentityResponse.RoleRemoval` (`RoleId`, `Users`, `Success`).

#### Command example

```!idira-identity-response-remove-role role_id=role-123 user_ids=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.RoleRemoval": {
        "RoleId": "role-123",
        "Users": [
            "00000000-0000-0000-0000-000000000000"
        ],
        "Success": true
    }
}
```

#### Human Readable Output

>### Removed 1 user(s) from role role-123
>
>|RoleId|Success|Users|
>|---|---|---|
>| role-123 | true | 00000000-0000-0000-0000-000000000000 |

### idira-identity-response-get-account

Resolves privileged accounts to their internal account IDs. Run this first — rotate and verify target the account by internal ID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Keywords to search for (e.g., account name or address). | Optional |
| search_type | Search mode: `contains` (default) or `startswith`. | Optional |
| safe_name | Filter results to a specific Safe. | Optional |
| limit | Maximum number of accounts to return (max 1000, default 50). | Optional |

**Context Output**: `IdiraIdentityResponse.Account` (`id`, `name`, `userName`, `safeName`, `platformId`, `address`, `secretType`).

#### Command example

```!idira-identity-response-get-account search=svc-sql```

#### Context Example

```json
{
    "IdiraIdentityResponse.Account": [
        {
            "id": "12_34",
            "name": "svc-sql",
            "userName": "svc_sql",
            "safeName": "IncidentResponse",
            "platformId": "WinServerLocal",
            "address": "192.0.2.5",
            "secretType": "password"
        }
    ]
}
```

#### Human Readable Output

>### Idira Privilege Cloud Accounts (1)
>
>|id|name|userName|safeName|platformId|address|secretType|
>|---|---|---|---|---|---|---|
>| 12_34 | svc-sql | svc_sql | IncidentResponse | WinServerLocal | 192.0.2.5 | password |

### idira-identity-response-get-account-details

Fetches a single account's details by its internal ID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The internal account ID. | Required |

**Context Output**: `IdiraIdentityResponse.Account` (as above).

#### Command example

```!idira-identity-response-get-account-details account_id=12_34```

#### Context Example

```json
{
    "IdiraIdentityResponse.Account": {
        "id": "12_34",
        "name": "svc-sql",
        "userName": "svc_sql",
        "safeName": "IncidentResponse",
        "platformId": "WinServerLocal",
        "address": "192.0.2.5",
        "secretType": "password"
    }
}
```

#### Human Readable Output

>### Idira Privilege Cloud Account: 12_34
>
>|address|id|name|platformId|safeName|secretType|userName|
>|---|---|---|---|---|---|---|
>| 192.0.2.5 | 12_34 | svc-sql | WinServerLocal | IncidentResponse | password | svc_sql |

### idira-identity-response-list-sessions

Lists active privileged sessions to resolve a `SessionGuid`. Check the `CanTerminate` / `CanSuspend` flags before acting.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Keywords to search for (e.g., the username). | Optional |
| safe | Filter results to a specific Safe. | Optional |
| limit | Maximum number of sessions to return (default 25). | Optional |

**Context Output**: `IdiraIdentityResponse.Session` (`SessionGuid`, `User`, `AccountUsername`, `AccountAddress`, `RemoteMachine`, `Protocol`, `RiskScore`, `CanTerminate`, `CanSuspend`, `CanMonitor`).

#### Command example

```!idira-identity-response-list-sessions search=jdoe```

#### Context Example

```json
{
    "IdiraIdentityResponse.Session": [
        {
            "SessionGuid": "00000000-0000-0000-0000-000000000000",
            "User": "jdoe",
            "AccountUsername": "root",
            "AccountAddress": "192.0.2.10",
            "RemoteMachine": "192.0.2.10",
            "Protocol": "SSH",
            "RiskScore": 40,
            "CanTerminate": true,
            "CanSuspend": true,
            "CanMonitor": true
        }
    ]
}
```

#### Human Readable Output

>### Idira Privilege Cloud Live Sessions (1)
>
>|SessionGuid|User|AccountUsername|AccountAddress|RemoteMachine|Protocol|RiskScore|CanTerminate|CanSuspend|CanMonitor|
>|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | jdoe | root | 192.0.2.10 | 192.0.2.10 | SSH | 40 | true | true | true |

### idira-identity-response-terminate-session

Ends a live privileged session immediately by GUID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_guid | The session GUID (from list-sessions). | Required |

**Context Output**: `IdiraIdentityResponse.SessionAction` (`SessionGuid`, `Action`, `Success`).

#### Command example

```!idira-identity-response-terminate-session session_guid=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.SessionAction": {
        "SessionGuid": "00000000-0000-0000-0000-000000000000",
        "Action": "Terminate",
        "Success": true
    }
}
```

#### Human Readable Output

>### Terminated session 00000000-0000-0000-0000-000000000000
>
>|Action|SessionGuid|Success|
>|---|---|---|
>| Terminate | 00000000-0000-0000-0000-000000000000 | true |

### idira-identity-response-suspend-session

Pauses a live session by GUID. Reversible with resume-session. Not supported for SSH/OPM sessions.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_guid | The session GUID (from list-sessions). | Required |

**Context Output**: `IdiraIdentityResponse.SessionAction` (`SessionGuid`, `Action`, `Success`).

#### Command example

```!idira-identity-response-suspend-session session_guid=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.SessionAction": {
        "SessionGuid": "00000000-0000-0000-0000-000000000000",
        "Action": "Suspend",
        "Success": true
    }
}
```

#### Human Readable Output

>### Suspendd session 00000000-0000-0000-0000-000000000000
>
>|Action|SessionGuid|Success|
>|---|---|---|
>| Suspend | 00000000-0000-0000-0000-000000000000 | true |

### idira-identity-response-resume-session

Lifts the pause on a suspended session by GUID.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_guid | The session GUID (from list-sessions). | Required |

**Context Output**: `IdiraIdentityResponse.SessionAction` (`SessionGuid`, `Action`, `Success`).

#### Command example

```!idira-identity-response-resume-session session_guid=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.SessionAction": {
        "SessionGuid": "00000000-0000-0000-0000-000000000000",
        "Action": "Resume",
        "Success": true
    }
}
```

#### Human Readable Output

>### Resumed session 00000000-0000-0000-0000-000000000000
>
>|Action|SessionGuid|Success|
>|---|---|---|
>| Resume | 00000000-0000-0000-0000-000000000000 | true |

### idira-identity-response-rotate-credential

Triggers an immediate CPM credential change on an account.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The internal account ID (from get-account). | Required |
| change_creds_for_group | Whether the CPM changes credentials on all accounts in the same group. Default `false`. | Optional |

**Context Output**: `IdiraIdentityResponse.CredentialAction` (`AccountId`, `Action`, `Success`).

#### Command example

```!idira-identity-response-rotate-credential account_id=12_34```

#### Context Example

```json
{
    "IdiraIdentityResponse.CredentialAction": {
        "AccountId": "12_34",
        "Action": "Rotate",
        "Success": true
    }
}
```

#### Human Readable Output

>### Rotation triggered for account 12_34
>
>|AccountId|Action|Success|
>|---|---|---|
>| 12_34 | Rotate | true |

### idira-identity-response-verify-credential

Marks an account for CPM verification to confirm the credential is valid.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The internal account ID (from get-account). | Required |

**Context Output**: `IdiraIdentityResponse.CredentialAction` (`AccountId`, `Action`, `Success`).

#### Command example

```!idira-identity-response-verify-credential account_id=12_34```

#### Context Example

```json
{
    "IdiraIdentityResponse.CredentialAction": {
        "AccountId": "12_34",
        "Action": "Verify",
        "Success": true
    }
}
```

#### Human Readable Output

>### Verification triggered for account 12_34
>
>|AccountId|Action|Success|
>|---|---|---|
>| 12_34 | Verify | true |

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

#### Command example

```!idira-identity-response-vault-account platform_id=WinServerLocal safe_name=IncidentResponse name=risky-admin address=192.0.2.5 username=admin```

#### Context Example

```json
{
    "IdiraIdentityResponse.Account": {
        "id": "99_1",
        "name": "risky-admin",
        "safeName": "IncidentResponse",
        "platformId": "WinServerLocal",
        "Success": true
    }
}
```

#### Human Readable Output

>### Vaulted account in Safe IncidentResponse
>
>|Success|id|name|platformId|safeName|
>|---|---|---|---|---|
>| true | 99_1 | risky-admin | WinServerLocal | IncidentResponse |

### idira-identity-response-disable-access-policy

Revokes standing or just-in-time access by disabling a SIA access policy. The current policy is read first and written back with only its status changed, so all other settings are preserved. Reversible with `idira-identity-response-enable-access-policy`.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy UUID. | Required |

**Context Output**: `IdiraIdentityResponse.AccessPolicy` (`PolicyId`, `PolicyName`, `PreviousStatus`, `Status`, `Success`).

#### Command example

```!idira-identity-response-disable-access-policy policy_id=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.AccessPolicy": {
        "PolicyId": "00000000-0000-0000-0000-000000000000",
        "PolicyName": "Prod SSH Access",
        "PreviousStatus": "Enabled",
        "Status": "Disabled",
        "Success": true
    }
}
```

#### Human Readable Output

>### Access policy Prod SSH Access (00000000-0000-0000-0000-000000000000) set to Disabled
>
>|PolicyId|PolicyName|PreviousStatus|Status|Success|
>|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | Prod SSH Access | Enabled | Disabled | true |

### idira-identity-response-enable-access-policy

Restores access by enabling a previously disabled SIA access policy. All other policy settings are preserved.

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy UUID. | Required |

**Context Output**: `IdiraIdentityResponse.AccessPolicy` (`PolicyId`, `PolicyName`, `PreviousStatus`, `Status`, `Success`).

#### Command example

```!idira-identity-response-enable-access-policy policy_id=00000000-0000-0000-0000-000000000000```

#### Context Example

```json
{
    "IdiraIdentityResponse.AccessPolicy": {
        "PolicyId": "00000000-0000-0000-0000-000000000000",
        "PolicyName": "Prod SSH Access",
        "PreviousStatus": "Disabled",
        "Status": "Enabled",
        "Success": true
    }
}
```

#### Human Readable Output

>### Access policy Prod SSH Access (00000000-0000-0000-0000-000000000000) set to Enabled
>
>|PolicyId|PolicyName|PreviousStatus|Status|Success|
>|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | Prod SSH Access | Disabled | Enabled | true |

## Troubleshooting

The integration maps HTTP errors to actionable messages:

| **Status / symptom** | **Behavior** | **What to check** |
| --- | --- | --- |
| `401` | The cached token is cleared and the request is retried once. If it fails again, an `Authentication failed` error is returned. | Verify the Client ID and Client Secret, and that the service user is an OAuth confidential client. |
| `403` | An `Insufficient permissions` error is returned. | Identity actions require **system-administrator** or **user-management** rights. Privilege Cloud actions require the relevant Safe permissions, and SIA policy actions require the `DpaAdmin` role. |
| `404` | A `Target not found` error is returned. | Run `idira-identity-response-get-user-by-name` again to resolve the user unique ID. |
| `409` | Treated as success, because the target is already in the requested state. | None. |
| `429` | A `Rate limited` error is returned. | Retry later, and don't retry in a tight loop. |
| `5xx` and connection errors | Retried up to 3 times with exponential backoff. | If the error persists, check the status of the Idira service. |
| `This command requires the Privilege Cloud URL` or `...the Secure Infrastructure Access (SIA) URL` | The command stops before sending any request. | Set the missing URL in the integration instance configuration. |

## Known Limitations

- The following request-body JSON keys are defaulted and should be verified against your tenant Swagger (`/identity-docs-api`) before go-live; each is a single-line constant at the top of the integration code:
  - `GetUserByName` request key - defaulted to `name`.
  - `SignOutEverywhere` user-ID key - defaulted to `ID`.
- This version covers Identity (workforce), Privilege Cloud (account resolution, session terminate/suspend/resume, credential rotate/verify, vault account), and Secure Infrastructure Access (disable and enable access policy) actions. Secure Cloud Access (SCA) session revocation and machine-identity (workload/authenticator) deletion are not yet included — their API path shapes are pending live-tenant confirmation. Endpoint containment (EPM) is handled by the **Idira EPM SOC Response** integration.
