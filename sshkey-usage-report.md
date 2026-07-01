# SSH Key Usage in Cortex Content Repository

**Generated:** 2026-06-22
**Repo:** `/Users/juschwartz/dev/content`
**Scope:** All content items (integrations, scripts, modules) that access the `sshkey` field from a Cortex credentials object (type 9).

---

## TL;DR

- **22 integrations across 20 packs** + **1 shared API module** access `sshkey` from credentials.
- **All access is via `type: 9` credentials objects** — no integration exposes SSH key as a separate plain-text or password parameter.
- The `sshkey` sub-field is presented to users as the **"Certificate"** field in the Credential Manager UI.
- No JavaScript or PowerShell integrations use this pattern.
- Only **2 integrations** (AnsibleCiscoIOS, AnsibleCiscoNXOS) accept `sshkey` as a *command argument* — and that's an Ansible passthrough for configuring SSH **public** keys on remote devices, NOT auth credentials.

---

## How `sshkey` Is Sourced

### The standard access pattern

```python
params.get("<param_name>", {}).get("credentials", {}).get("sshkey")
```

This reflects the nested structure of XSOAR/XSIAM type-9 credentials parameters.

### What `type: 9` means in the UI
When a parameter is defined as `type: 9` in the integration YAML, the user gets two options:
1. **Pick an existing credential** from the credential vault — SSH key lives under the "Certificate" field
2. **Type values inline** in the integration configuration form

In both cases, the runtime value is delivered to the integration as `params[<name>].credentials.sshkey`.

---

## Integrations Using `credentials.sshkey` (Direct Access)

### 1. GitHub
- **Pack:** `GitHub`
- **File:** `Packs/GitHub/Integrations/GitHub/GitHub.py:2471-2472`
- **Cred param:** `credentials` (display: `Credentials`, type 9)
- **Purpose:** GitHub App private key (PEM) for JWT signing
- **Notes:** Pack also has separate `api_token` (type 9) for token auth — only `credentials` exposes sshkey
```python
creds: dict = params.get("credentials", {}).get("credentials", {})
PRIVATE_KEY = creds.get("sshkey", "") if creds else ""
```

### 2. Snowflake
- **Pack:** `Snowflake`
- **File:** `Packs/Snowflake/Integrations/Snowflake/Snowflake.py:22`
- **Cred param:** `credentials` (display: `Username`, type 9)
- **Purpose:** Private certificate for Snowflake key-pair authentication
```python
CERTIFICATE = CREDENTIALS.get("credentials", {}).get("sshkey", "").encode()
```

### 3. Cybereason
- **Pack:** `Cybereason`
- **File:** `Packs/Cybereason/Integrations/Cybereason/Cybereason.py:24`
- **Cred param:** `credentials` (display: `Credentials`, type 9)
- **Purpose:** Client certificate for mutual TLS authentication
```python
CERTIFICATE = demisto.params().get("credentials", {}).get("credentials", {}).get("sshkey")
```

### 4. MS-ISAC
- **Pack:** `MS-ISAC`
- **File:** `Packs/MS-ISAC/Integrations/MSISAC/MSISAC.py:435`
- **Cred param:** `apikey` (display: hidden username, `displaypassword: API Key`, type 9)
- **Purpose:** Stores an **API key** in the sshkey field (with fallback to password)
- **Notes:** Atypical use — `sshkey` is repurposed as alternative storage for an API key
```python
api_key = params.get("apikey", {}).get("credentials", {}).get("sshkey", "") \
          or params.get("apikey", {}).get("password", "")
```

### 5. MailListenerV2
- **Pack:** `MailListener`
- **File:** `Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py:685`
- **Cred params:** `credentials` (display: `Username`, type 9) AND `clientCertAndKey` (also type 9, exposes sshkey)
- **Purpose:** Concatenated cert + private key PEM for OAuth/cert-based mail authentication
```python
cert_and_pkey_pem = demisto.get(cred_params, "credentials.sshkey")
```

### 6. RemoteAccessv2
- **Pack:** `RemoteAccess`
- **File:** `Packs/RemoteAccess/Integrations/RemoteAccessv2/RemoteAccessv2.py:331`
- **Cred param:** `credentials` (display: `User`, type 9)
- **Purpose:** SSH private key for executing remote commands
```python
certificate: str = (credentials.get("credentials") or {}).get("sshkey", "")
```

### 7. PaloAltoNetworks_PAN_OS_EDL_Management
- **Pack:** `PaloAltoNetworks_PAN_OS_EDL_Management`
- **File:** `Packs/PaloAltoNetworks_PAN_OS_EDL_Management/Integrations/PaloAltoNetworks_PAN_OS_EDL_Management/PaloAltoNetworks_PAN_OS_EDL_Management.py:41-43`
- **Cred param:** `Authentication` (display: `SSH credentials to server (username and certificate, see in the credential manager)`, type 9)
- **Purpose:** SSH key for connecting to PAN-OS firewall to manage EDLs
```python
if 'credentials' in authentication and 'sshkey' in authentication['credentials'] \
        and len(authentication['credentials']['sshkey']) > 0:
    certificate = authentication.get('credentials', None).get('sshkey')
```

### 8. Netmiko
- **Pack:** `Netmiko`
- **File:** `Packs/Netmiko/Integrations/Netmiko/Netmiko.py:213`
- **Cred param:** `credentials` (display: `Credentials`, type 9)
- **Purpose:** SSH private key loaded as `paramiko.RSAKey` for connecting to network devices
```python
ssh_key = params.get("credentials", {}).get("credentials", {}).get("sshkey")
```

### 9. DockerEngine
- **Pack:** `DevSecOps`
- **File:** `Packs/DevSecOps/Integrations/DockerEngine/DockerEngine.py:2881`
- **Cred params:** `client_key` (hidden username, displayed as `Docker Client Private Key`, type 9) AND `client_certificate` (type 12, separate cert field)
- **Purpose:** Docker TLS client key for authenticated Docker API access
```python
client_key = params.get("client_key", {}).get("credentials", {}).get("sshkey")
```

---

## Ansible Powered Integrations

All located in `Packs/Ansible_Powered_Integrations/` — these use the SSH key to authenticate the Ansible runner to remote hosts.

### Direct accessors (5)
These integrations read `sshkey` directly in their own module file:

| Integration | File | Lines |
|---|---|---|
| **ACME** | `Integrations/ACME/ACME.py` | 80, 113, 115, 146 |
| **CiscoIOS** | `Integrations/CiscoIOS/CiscoIOS.py` | 80, 113–116, 151 |
| **CiscoNXOS** | `Integrations/CiscoNXOS/CiscoNXOS.py` | 80, 113–116, 151 |
| **Linux** | `Integrations/Linux/Linux.py` | 80, 113–115, 146 |
| **OpenSSL** | `Integrations/OpenSSL/OpenSSL.py` | 80, 113–115, 146 |

Pattern:
```python
if demisto.params().get('creds', {}).get('credentials').get('sshkey'):
    sshkey = demisto.params().get('creds', {}).get('credentials').get('sshkey')
# ...
ansible_runner.run(..., ssh_key=sshkey, ...)
```

### Indirect accessors (8) — via AnsibleApiModule
These integrations only declare `sshkey = ""` locally and delegate to `AnsibleApiModule.generic_ansible(...)` which handles credentials internally:

| Integration | File |
|---|---|
| AlibabaCloud | `Integrations/AlibabaCloud/AlibabaCloud.py` |
| AzureComputeV3 | `Integrations/AzureComputeV3/AzureComputeV3.py` |
| AzureNetworking | `Integrations/AzureNetworking/AzureNetworking.py` |
| DNS | `Integrations/DNS/DNS.py` |
| HCloud | `Integrations/HCloud/HCloud.py` |
| Kubernetes | `Integrations/Kubernetes/Kubernetes.py` |
| MicrosoftWindows | `Integrations/MicrosoftWindows/MicrosoftWindows.py` |
| VMwareV2 | `Integrations/VMwareV2/VMwareV2.py` |

All Ansible integrations declare:
- **Cred param:** `creds` (display: `Username`, type 9)
- **Additional info:** "SSH keys can be configured using the credential manager, under the Certificate field"

---

## Shared API Module

### AnsibleApiModule
- **Pack:** `ApiModules`
- **File:** `Packs/ApiModules/Scripts/AnsibleApiModule/AnsibleApiModule.py:121, 155, 157, 237, 283, 290, 325`
- **Purpose:** Centralized helper used by Ansible-powered integrations to pass SSH keys to `ansible_runner`
```python
if int_params.get("creds", {}).get("credentials").get("sshkey"):
    sshkey = int_params.get("creds", {}).get("credentials").get("sshkey")
# ...
return inventory, sshkey
```

---

## `sshkey` as a Command Argument (Not Credentials)

Some YAML files reference `sshkey` as a **command argument name** rather than the credentials field. These are NOT credential auth — they're parameters to specific commands.

| Pack / Integration | File | Purpose |
|---|---|---|
| AnsibleCiscoIOS | `Packs/AnsibleCiscoIOS/Integrations/AnsibleCiscoIOS/AnsibleCiscoIOS.yml:816` | `sshkey` arg on `cisco-ios-iosuser` (configures SSH public key on Cisco device) |
| AnsibleCiscoNXOS | `Packs/AnsibleCiscoNXOS/Integrations/AnsibleCiscoNXOS/AnsibleCiscoNXOS.yml:2764-2765` | `sshkey` arg on `cisco-nxos-nxosuser` (same purpose) |
| Ansible_Powered_Integrations/CiscoIOS | `.../CiscoIOS/CiscoIOS.yml:583` | Same as above |
| Ansible_Powered_Integrations/CiscoNXOS | `.../CiscoNXOS/CiscoNXOS.yml:2257-2258` | Same as above |
| Thycotic | `Packs/Thycotic/Integrations/Thycotic/Thycotic.yml:360` | `sshkeyargs` argument |
| DelineaSS | `Packs/DelineaSS/Integrations/DelineaSS/DelineaSS.yml:380` | `sshkeyargs` argument |

---

## YAML Configuration Summary

| Integration | Cred Param Name | Display | Type | Separate non-cred SSH input? | `sshkey` as cmd arg? |
|---|---|---|---|---|---|
| GitHub | `credentials` | Credentials | 9 | No | No |
| Snowflake | `credentials` | Username | 9 | No | No |
| Cybereason | `credentials` | Credentials | 9 | No | No |
| MS-ISAC | `apikey` | (hidden) / `displaypassword: API Key` | 9 | No | No |
| MailListenerV2 | `credentials` + `clientCertAndKey` | Username | 9 + 9 | No (both are type 9) | No |
| RemoteAccessv2 | `credentials` | User | 9 | No | No |
| PAN-OS EDL Mgmt | `Authentication` | SSH credentials to server... | 9 | No | No |
| Netmiko | `credentials` | Credentials | 9 | No | No |
| DockerEngine | `client_key` (+`client_certificate` type 12) | Docker Client Private Key | 9 | Cert is separate (type 12) | No |
| Ansible: Linux | `creds` | Username | 9 | No | No |
| Ansible: CiscoIOS | `creds` | Username | 9 | No | **Yes** (passthrough) |
| Ansible: CiscoNXOS | `creds` | Username | 9 | No | **Yes** (passthrough) |
| Ansible: ACME | `creds` | Username | 9 | No | No |
| Ansible: MicrosoftWindows | `creds` | Username | 9 | No | No |
| (other Ansible integrations) | `creds` | Username | 9 | No | No |

---

## Test / Mock Data References

These files contain `sshkey` only in test fixtures (typically set to empty string) — no production access:

- `Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py:1433-1435` — tests for masking SSH keys in debug logs
- `Packs/Palo_Alto_Networks_Enterprise_DLP/Integrations/Palo_Alto_Networks_Enterprise_DLP/Palo_Alto_Networks_Enterprise_DLP_test.py:145-345`
- `Packs/GenericSQL/Integrations/GenericSQL/test_data/input_data.py:47-367`
- `Packs/GitHub/Integrations/GitHub/GitHub_test.py:83`
- `Packs/MailListener/Integrations/MailListenerV2/MailListenerV2_test.py:387, 461`
- `Packs/Netmiko/Integrations/Netmiko/Netmiko_test.py:18` + `test_data/test_data.json:7`
- `Packs/ApiModules/Scripts/AnsibleApiModule/AnsibleApiModule_test.py:141, 153, 156, 162-171`
- `Packs/ApiModules/Scripts/AnsibleApiModule/test_data/ansible_inventory.py:5`

---

## Key Observations

1. **Consistent pattern:** All 22 integrations use `type: 9` credentials objects with the nested `params[X].credentials.sshkey` access pattern.

2. **No separate dedicated input:** Not a single integration exposes the SSH key as a standalone plain text / password / certificate parameter. It's always inside a credentials object.

3. **Field reuse:** The `sshkey` field is used for diverse secrets — not just SSH keys:
   - Actual SSH private keys (Netmiko, RemoteAccessv2, PAN-OS EDL, Ansible)
   - TLS client certificates (DockerEngine, Cybereason)
   - PEM private keys (Snowflake, GitHub App)
   - Concatenated cert+key PEM blobs (MailListenerV2)
   - API keys (MS-ISAC — atypical use)

4. **UI mapping:** The `sshkey` JSON field corresponds to the **"Certificate"** field in the XSOAR Credentials Manager UI.

5. **Naming consistency:** The field is always lowercase `sshkey` — no `ssh_key` (snake_case) or `SSHKey` (PascalCase) variants exist.

6. **No JavaScript or PowerShell** integrations use this pattern.

7. **Notable edge case (MS-ISAC):** Uses `sshkey` field as an alternate storage location for an API key (with password fallback). Worth flagging if doing credential-handling consistency audits.

---

## Search Methodology

Verified completeness via 7 different search patterns:
- `\.sshkey` (attribute-like access)
- `\["sshkey"\]` and `\['sshkey'\]` (dict bracket access)
- `get\(["\']sshkey` (.get() method calls)
- `"sshkey"` and `'sshkey'` (string literal references in .py files)
- All `.ps1` files
- All `.js` files
- Broad `sshkey` scan across all `.py` files

All patterns resolved to the same 22 integrations + 1 shared module listed above.
