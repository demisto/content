## Superna Zero Trust

Integrates Cortex XSOAR with **Superna Zero Trust** to automate ransomware containment and recovery actions via the Superna SERA API.

## Configure Superna Zero Trust on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**
2. Search for **Superna Zero Trust**
3. Click **Add instance** and configure the following parameters:

| Parameter | Description | Required |
|-----------|-------------|----------|
| API URL | Base URL of your Superna Zero Trust / SERA server (e.g. `https://sera.example.local`) | True |
| API Key | API key for authenticating to the Superna SERA API | True |
| Trust any certificate (not secure) | Skip TLS certificate verification. Enable only for self-signed certificates. | False |
| Use system proxy settings | Route API calls through the system proxy | False |

4. Click **Test** to validate connectivity.

## Commands

### superna-zt-snapshot-critical-paths

Create a snapshot of Superna critical paths for ransomware rapid recovery.

#### Base Command

`superna-zt-snapshot-critical-paths`

#### Input

There are no input arguments for this command.

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| SupernaZeroTrust.Snapshot.Status | String | Result status: `Success` or `AlreadyExists` |
| SupernaZeroTrust.Snapshot.Message | String | Human-readable result message |
| SupernaZeroTrust.Snapshot.Result | Unknown | Raw API response from the snapshot operation |

#### Command Example

```
!superna-zt-snapshot-critical-paths
```

#### Human Readable Output

```
✅ Snapshot created successfully
```

---

### superna-zt-lockout-user

Lock out a user from NAS storage access.

#### Base Command

`superna-zt-lockout-user`

#### Input

| Argument Name | Description | Required |
|---------------|-------------|----------|
| username | The username to lock out from NAS storage access | Required |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| SupernaZeroTrust.Lockout.Username | String | The username that was locked out |
| SupernaZeroTrust.Lockout.Result | Unknown | Raw API response from the lockout operation |

#### Command Example

```
!superna-zt-lockout-user username="jsmith"
```

---

### superna-zt-unlock-user

Unlock a user from NAS storage access.

#### Base Command

`superna-zt-unlock-user`

#### Input

| Argument Name | Description | Required |
|---------------|-------------|----------|
| username | The username to unlock from NAS storage access | Required |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| SupernaZeroTrust.Unlock.Username | String | The username that was unlocked |
| SupernaZeroTrust.Unlock.Result | Unknown | Raw API response from the unlock operation |

#### Command Example

```
!superna-zt-unlock-user username="jsmith"
```
